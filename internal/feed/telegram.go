package feed

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
)

// TelegramConfig holds credentials for MTProto access.
type TelegramConfig struct {
	APIID   int
	APIHash string
}

// TelegramChannel defines a channel to monitor.
type TelegramChannel struct {
	Name     string // display name
	Username string // @username without @
}

// CheckTelegramSession verifies that the Telegram session is valid and authorized.
func CheckTelegramSession(cfg TelegramConfig) (bool, error) {
	if cfg.APIID == 0 || cfg.APIHash == "" {
		return false, fmt.Errorf("telegram credentials not configured")
	}

	home, _ := os.UserHomeDir()
	sessionPath := filepath.Join(home, ".newsdigest", "telegram.session")
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		return false, fmt.Errorf("no session file — run -telegram-auth first")
	}

	storage := &session.FileStorage{Path: sessionPath}
	client := telegram.NewClient(cfg.APIID, cfg.APIHash, telegram.Options{
		SessionStorage: storage,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var authorized bool
	err := client.Run(ctx, func(ctx context.Context) error {
		status, err := client.Auth().Status(ctx)
		if err != nil {
			return err
		}
		authorized = status.Authorized
		return nil
	})
	if err != nil {
		return false, err
	}
	return authorized, nil
}

// FetchTelegramChannels uses MTProto to read full message history
// from public Telegram channels (last N days).
// Each channel has a 30-second timeout to prevent one slow channel from blocking.
func FetchTelegramChannels(ctx context.Context, cfg TelegramConfig, channels []TelegramChannel, days int) []Article {
	if cfg.APIID == 0 || cfg.APIHash == "" {
		return nil
	}

	home, _ := os.UserHomeDir()
	sessionDir := filepath.Join(home, ".newsdigest")
	os.MkdirAll(sessionDir, 0o755)
	sessionPath := filepath.Join(sessionDir, "telegram.session")

	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		log.Printf("warning: telegram: no session file — run -telegram-auth first")
		return nil
	}

	storage := &session.FileStorage{Path: sessionPath}
	client := telegram.NewClient(cfg.APIID, cfg.APIHash, telegram.Options{
		SessionStorage: storage,
	})

	// Global timeout: 30s per channel + overhead
	globalTimeout := time.Duration(len(channels)+1) * 30 * time.Second
	if globalTimeout > 5*time.Minute {
		globalTimeout = 5 * time.Minute
	}
	tgCtx, cancel := context.WithTimeout(ctx, globalTimeout)
	defer cancel()

	var allArticles []Article

	err := client.Run(tgCtx, func(ctx context.Context) error {
		status, err := client.Auth().Status(ctx)
		if err != nil {
			return fmt.Errorf("auth status: %w", err)
		}
		if !status.Authorized {
			return fmt.Errorf("not authorized — run telegram-auth first")
		}

		api := client.API()
		cutoff := time.Now().AddDate(0, 0, -days)

		for i, ch := range channels {
			// Per-channel timeout
			chCtx, chCancel := context.WithTimeout(ctx, 30*time.Second)
			articles, err := fetchTelegramChannel(chCtx, api, ch, cutoff)
			chCancel()
			if err != nil {
				log.Printf("warning: telegram %s: %v", ch.Name, err)
				continue
			}
			log.Printf("telegram %s: %d articles", ch.Name, len(articles))
			allArticles = append(allArticles, articles...)
			if i < len(channels)-1 {
				time.Sleep(time.Second)
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("warning: telegram MTProto: %v", err)
	}

	return allArticles
}

func fetchTelegramChannel(ctx context.Context, api *tg.Client, ch TelegramChannel, cutoff time.Time) ([]Article, error) {
	// Resolve username to peer
	resolved, err := api.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{Username: ch.Username})
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ch.Username, err)
	}

	var inputPeer tg.InputPeerClass
	for _, c := range resolved.Chats {
		switch v := c.(type) {
		case *tg.Channel:
			inputPeer = &tg.InputPeerChannel{
				ChannelID:  v.ID,
				AccessHash: v.AccessHash,
			}
		}
	}
	if inputPeer == nil {
		return nil, fmt.Errorf("no channel found for @%s", ch.Username)
	}

	// Fetch messages (newest first, paginate backwards)
	var messages []tg.MessageClass
	offsetID := 0
	for {
		history, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
			Peer:     inputPeer,
			Limit:    100,
			OffsetID: offsetID,
		})
		if err != nil {
			return nil, fmt.Errorf("get history: %w", err)
		}

		var msgs []tg.MessageClass
		switch h := history.(type) {
		case *tg.MessagesMessages:
			msgs = h.Messages
		case *tg.MessagesMessagesSlice:
			msgs = h.Messages
		case *tg.MessagesChannelMessages:
			msgs = h.Messages
		default:
			break
		}

		if len(msgs) == 0 {
			break
		}

		reachedCutoff := false
		for _, m := range msgs {
			msg, ok := m.(*tg.Message)
			if !ok || msg.Message == "" {
				continue
			}
			t := time.Unix(int64(msg.Date), 0)
			if t.Before(cutoff) {
				reachedCutoff = true
				break
			}
			messages = append(messages, m)
			offsetID = msg.ID
		}

		if reachedCutoff || len(msgs) < 100 {
			break
		}

		// Small delay to avoid flood wait
		time.Sleep(500 * time.Millisecond)
	}

	if len(messages) == 0 {
		return nil, nil
	}

	// Extract targets and actor mentions from messages
	targets := make(map[string]bool)
	mentionedActors := make(map[string]bool)
	var latest time.Time
	msgCount := 0

	for _, m := range messages {
		msg, ok := m.(*tg.Message)
		if !ok || len(msg.Message) < 10 {
			continue
		}
		msgCount++
		t := time.Unix(int64(msg.Date), 0)
		if t.After(latest) {
			latest = t
		}

		// Extract domains
		text := msg.Message
		for _, d := range tgDomainRe.FindAllStringSubmatch(text, -1) {
			host := strings.ToLower(d[1])
			parts := strings.Split(host, ".")
			root := host
			if len(parts) >= 2 {
				root = parts[len(parts)-2] + "." + parts[len(parts)-1]
			}
			if tgExcludeDomains[root] || tgExcludeDomains[host] {
				continue
			}
			targets[host] = true
		}

		// Check for actor mentions
		textLower := strings.ToLower(text)
		for pattern, name := range ddosActorPatterns {
			if strings.Contains(textLower, pattern) {
				mentionedActors[name] = true
			}
		}
	}

	// Build description
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("%s: %d meddelanden (senaste %d dagar).", ch.Name, msgCount, int(time.Since(latest).Hours()/24)+1))

	if len(mentionedActors) > 0 {
		names := make([]string, 0, len(mentionedActors))
		for n := range mentionedActors {
			names = append(names, n)
		}
		sort.Strings(names)
		desc.WriteString(fmt.Sprintf(" Nämnda aktörer: %s.", strings.Join(names, ", ")))
	}

	if len(targets) > 0 {
		tlist := make([]string, 0, len(targets))
		for t := range targets {
			tlist = append(tlist, t)
		}
		sort.Strings(tlist)
		if len(tlist) > 10 {
			tlist = append(tlist[:10], fmt.Sprintf("(+%d till)", len(tlist)-10))
		}
		desc.WriteString(fmt.Sprintf(" Mål: %s.", strings.Join(tlist, ", ")))
	}

	dayLink := fmt.Sprintf("https://t.me/%s#%s", ch.Username, time.Now().Format("2006-01-02"))
	return []Article{{
		Title:       fmt.Sprintf("%s: %d inlägg med cyberaktivitet (MTProto)", ch.Name, msgCount),
		Link:        dayLink,
		Description: desc.String(),
		Published:   time.Now(),
		Source:      ch.Name + " (Telegram)",
	}}, nil
}

// AuthTelegram performs interactive authentication (phone number + code).
// This should be called once from a CLI command.
func AuthTelegram(ctx context.Context, cfg TelegramConfig, phone string) error {
	home, _ := os.UserHomeDir()
	sessionDir := filepath.Join(home, ".newsdigest")
	os.MkdirAll(sessionDir, 0o755)
	sessionPath := filepath.Join(sessionDir, "telegram.session")

	storage := &session.FileStorage{Path: sessionPath}

	client := telegram.NewClient(cfg.APIID, cfg.APIHash, telegram.Options{
		SessionStorage: storage,
	})

	return client.Run(ctx, func(ctx context.Context) error {
		// Use terminal auth flow
		flow := auth.NewFlow(
			auth.Constant(phone, "", auth.CodeAuthenticatorFunc(
				func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
					fmt.Print("Enter Telegram code: ")
					var code string
					fmt.Scanln(&code)
					return code, nil
				},
			)),
			auth.SendCodeOptions{},
		)
		return client.Auth().IfNecessary(ctx, flow)
	})
}
