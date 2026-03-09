package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	gosync "sync"
	"time"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"

	"news/internal/config"
	"news/internal/feed"
	"news/internal/scorer"
	"news/internal/store"
)

type SyncResult struct {
	Fetched  int
	New      int
	Scored   int
	PerFeed  []FeedStatus
	Duration time.Duration
}

type FeedStatus struct {
	Name     string
	URL      string
	Articles int
	Error    string
	LastSync time.Time
	LastData time.Time
}

// SyncProgress tracks the current state of a running sync operation.
type SyncProgress struct {
	Phase   string `json:"phase"`   // "idle", "fetching", "triage", "enrich", "rescoring", "done"
	Message string `json:"message"` // Human-readable status
	Done    int    `json:"done"`    // Completed items in current phase
	Total   int    `json:"total"`   // Total items in current phase
}

type SyncEngine struct {
	Cfg         *config.Config
	DB          *store.DB
	ConfigPath  string
	SkipRescore bool
	OnBatch     func() // called after each incremental save so the server can reload
	mu          gosync.Mutex
	progMu      gosync.RWMutex
	progress    SyncProgress
}

// Progress returns a copy of the current sync progress.
func (se *SyncEngine) Progress() SyncProgress {
	se.progMu.RLock()
	defer se.progMu.RUnlock()
	return se.progress
}

func scoredToCached(a scorer.ScoredArticle) store.CachedArticle {
	attackChain := "[]"
	if len(a.AttackChain) > 0 {
		if b, err := json.Marshal(a.AttackChain); err == nil {
			attackChain = string(b)
		}
	}
	cves := "[]"
	if len(a.CVEs) > 0 {
		if b, err := json.Marshal(a.CVEs); err == nil {
			cves = string(b)
		}
	}
	return store.CachedArticle{
		Title:              a.Title,
		Link:               a.Link,
		Description:        a.Description,
		Content:            a.Content,
		Source:             a.Source,
		Sources:            []string{a.Source},
		Published:          a.Published.UTC().Format("2006-01-02T15:04"),
		Score:              a.Score,
		Severity:           a.Severity,
		Verified:           a.Verified,
		Scope:              a.Scope,
		Novelty:            a.Novelty,
		Summary:            a.Summary,
		Detail:             a.Detail,
		ThreatActor:        a.ThreatActor,
		ThreatActorAliases: a.ThreatActorAliases,
		ActivityType:       a.ActivityType,
		ActorType:          a.ActorType,
		Origin:             a.Origin,
		Country:            a.Country,
		Region:             a.Region,
		Impact:             a.Impact,
		Sector:             a.Sector,
		TTPs:               a.TTPs,
		ScoreVersion:       scorer.CurrentScoreVersion,
		AttackChain:        attackChain,
		CVEs:               cves,
	}
}

func (se *SyncEngine) setProgress(phase, message string, done, total int) {
	se.progMu.Lock()
	se.progress = SyncProgress{Phase: phase, Message: message, Done: done, Total: total}
	se.progMu.Unlock()
}

func (se *SyncEngine) Run(ctx context.Context) (*SyncResult, error) {
	se.mu.Lock()
	defer se.mu.Unlock()

	start := time.Now()

	// Load MITRE ATT&CK data for actor normalization
	cacheDir := filepath.Dir(se.DB.Path())
	if _, err := scorer.LoadMITREData(cacheDir); err != nil {
		log.Printf("warning: load MITRE data: %v (actor normalization will use manual aliases only)", err)
	}

	// Load deepdarkCTI channel list for Telegram auto-approve
	if se.Cfg.TelegramAutoApprove {
		if _, err := LoadDeepDarkCTIChannels(); err != nil {
			log.Printf("warning: load deepdarkCTI: %v", err)
		}
	}

	// Load feedback for scorer calibration
	feedback, err := se.DB.LoadFeedback()
	if err != nil {
		log.Printf("warning: load feedback: %v", err)
	}
	recentFeedback := store.RecentFeedback(feedback, 50)

	// Build feed sources
	sources := make([]feed.FeedSource, len(se.Cfg.Feeds))
	for i, f := range se.Cfg.Feeds {
		src := feed.FeedSource{Name: f.Name, URL: f.URL}
		if se.Cfg.OTXApiKey != "" && strings.Contains(f.URL, "otx.alienvault.com") {
			src.Headers = map[string]string{"X-OTX-API-KEY": se.Cfg.OTXApiKey}
		}
		sources[i] = src
	}

	maxAge := time.Duration(se.Cfg.FetchWindow) * 24 * time.Hour

	// Fetch RSS synchronously (need both articles and feedResults)
	se.setProgress("fetching", fmt.Sprintf("Hämtar %d feeds...", len(sources)), 0, len(sources))
	log.Printf("fetching %d feeds (window: %d days)...", len(sources), se.Cfg.FetchWindow)
	articles, feedResults := feed.FetchAllDetailed(sources, maxAge)
	se.setProgress("fetching", fmt.Sprintf("Hämtade %d artiklar", len(articles)), len(sources), len(sources))

	// Fetch Cloudflare, DDoSia, Telegram in parallel (non-blocking)
	var ddosiaArticles []feed.Article
	var extraMu gosync.Mutex
	var extraWg gosync.WaitGroup

	if se.Cfg.CloudflareKey != "" {
		extraWg.Add(1)
		go func() {
			defer extraWg.Done()
			cfArticles := feed.FetchCloudflareRadar(se.Cfg.CloudflareKey)
			extraMu.Lock()
			articles = append(articles, cfArticles...)
			extraMu.Unlock()
		}()
	}

	extraWg.Add(1)
	go func() {
		defer extraWg.Done()
		da, err := feed.FetchDDoSiaHistory(se.Cfg.FetchWindow)
		if err != nil {
			log.Printf("warning: ddosia history: %v", err)
		}
		extraMu.Lock()
		ddosiaArticles = da
		articles = append(articles, da...)
		extraMu.Unlock()
	}()

	if se.Cfg.TelegramAPIID != 0 && se.Cfg.TelegramAPIHash != "" {
		extraWg.Add(1)
		go func() {
			defer extraWg.Done()
			tgCfg := feed.TelegramConfig{
				APIID:   se.Cfg.TelegramAPIID,
				APIHash: se.Cfg.TelegramAPIHash,
			}
			var tgChannels []feed.TelegramChannel
			for _, ch := range se.Cfg.TelegramChannels {
				tgChannels = append(tgChannels, feed.TelegramChannel{Name: ch.Name, Username: ch.Username})
			}
			tgArticles := feed.FetchTelegramChannels(ctx, tgCfg, tgChannels, se.Cfg.FetchWindow)
			extraMu.Lock()
			articles = append(articles, tgArticles...)
			extraMu.Unlock()
		}()
	}

	extraWg.Wait()

	log.Printf("got %d articles from last %d days", len(articles), se.Cfg.FetchWindow)

	// Build per-feed status
	now := time.Now()
	perFeed := make([]FeedStatus, len(feedResults))
	for i, fr := range feedResults {
		perFeed[i] = FeedStatus{
			Name:     fr.Name,
			URL:      fr.URL,
			Articles: fr.Articles,
			Error:    fr.Error,
			LastSync: now,
		}
	}

	// Add Telegram per-channel status
	if se.Cfg.TelegramAPIID != 0 {
		tgCount := make(map[string]int)
		for _, a := range articles {
			for _, ch := range se.Cfg.TelegramChannels {
				if a.Source == ch.Name+" (Telegram)" {
					tgCount[ch.Username]++
				}
			}
		}
		for _, ch := range se.Cfg.TelegramChannels {
			perFeed = append(perFeed, FeedStatus{
				Name:     ch.Name + " (Telegram)",
				URL:      "https://t.me/" + ch.Username,
				Articles: tgCount[ch.Username],
				LastSync: now,
			})
		}
	}

	// Add DDoSia and Cloudflare status
	ddosiaCount := len(ddosiaArticles)
	perFeed = append(perFeed, FeedStatus{
		Name:     "DDoSia Targets",
		URL:      "https://ddosia.seculetter.com",
		Articles: ddosiaCount,
		LastSync: now,
	})
	if se.Cfg.CloudflareKey != "" {
		cfCount := 0
		for _, a := range articles {
			if a.Source == "Cloudflare Radar" {
				cfCount++
			}
		}
		perFeed = append(perFeed, FeedStatus{
			Name:     "Cloudflare Radar",
			URL:      "https://radar.cloudflare.com",
			Articles: cfCount,
			LastSync: now,
		})
	}

	// Preserve LastData from previous sync status
	prevStatus, _ := se.DB.LoadSyncStatus()
	prevByName := make(map[string]store.FeedSyncStatus)
	if prevStatus != nil {
		for _, fs := range prevStatus.Feeds {
			prevByName[fs.Name] = fs
		}
	}
	for i := range perFeed {
		if perFeed[i].Articles > 0 {
			perFeed[i].LastData = now
		} else if prev, ok := prevByName[perFeed[i].Name]; ok && prev.LastData != "" {
			if t, err := time.Parse(time.RFC3339, prev.LastData); err == nil {
				perFeed[i].LastData = t
			}
		}
	}

	result := &SyncResult{
		Fetched: len(articles),
		PerFeed: perFeed,
	}

	// Dedup
	var newArticles []feed.Article
	for _, a := range articles {
		if se.DB.IsNew(a.Link) {
			newArticles = append(newArticles, a)
		}
	}
	result.New = len(newArticles)
	log.Printf("%d new articles after dedup", len(newArticles))

	// Fetch full article content for articles that only have short RSS descriptions
	if len(newArticles) > 0 {
		needFetch := 0
		for _, a := range newArticles {
			if a.Content == "" {
				needFetch++
			}
		}
		if needFetch > 0 {
			se.setProgress("fetching_content", fmt.Sprintf("Hämtar artikeltext för %d artiklar...", needFetch), 0, needFetch)
			log.Printf("fetching full content for %d articles (of %d new)...", needFetch, len(newArticles))
			fetched := feed.FetchContentBatch(newArticles, 10)
			log.Printf("fetched content for %d articles", fetched)
		}
	}

	feedNames := se.feedNames()

	if len(newArticles) == 0 {
		log.Println("no new articles to score")
		se.setProgress("pruning", "Rensar inaktiva feeds...", 0, 0)
		if kept, removed, err := se.DB.PruneArticles(feedNames...); err != nil {
			log.Printf("warning: prune articles: %v", err)
		} else if removed > 0 {
			log.Printf("pruned %d articles from inactive feeds, %d remaining", removed, kept)
		}
		if !se.SkipRescore {
			se.setProgress("rescoring", "Ompoängsätter ofullständiga artiklar...", 0, 0)
			se.rescoreIncomplete(ctx, recentFeedback)
		}
		if se.Cfg.TelegramAPIID != 0 {
			se.discoverTelegramChannels(ctx, articles)
		}
		result.Duration = time.Since(start)
		se.saveSyncStatus(result)
		se.setProgress("done", fmt.Sprintf("Klart — inga nya artiklar (%s)", result.Duration.Round(time.Second)), 0, 0)
		return result, nil
	}

	// Score with progress tracking — save incrementally after each batch
	se.setProgress("triage", fmt.Sprintf("Triagerar %d artiklar...", len(newArticles)), 0, len(newArticles))
	log.Printf("scoring %d articles with %s...", len(newArticles), se.Cfg.Model)
	var savedCount int
	progressFn := func(phase string, done, total int) {
		msg := ""
		switch phase {
		case "triage":
			msg = fmt.Sprintf("Triagerar artiklar (%d/%d)", done, total)
		case "enrich":
			msg = fmt.Sprintf("Anrikar artiklar (%d/%d)", done, total)
		}
		se.setProgress(phase, msg, done, total)
	}
	scored, err := scorer.ScoreWithProgress(ctx, se.Cfg, newArticles, recentFeedback, progressFn)
	if err != nil {
		return nil, fmt.Errorf("scorer: %w", err)
	}
	result.Scored = len(scored)

	// Save scored articles incrementally and notify server
	batchSize := 15
	for i := 0; i < len(scored); i += batchSize {
		end := i + batchSize
		if end > len(scored) {
			end = len(scored)
		}
		batch := scored[i:end]
		cached := make([]store.CachedArticle, 0, len(batch))
		for _, a := range batch {
			cached = append(cached, scoredToCached(a))
		}
		if err := se.DB.SaveArticles(cached); err != nil {
			log.Printf("warning: cache articles batch: %v", err)
		} else {
			for _, a := range batch {
				se.DB.Mark(a.Link)
			}
		}
		// Save extracted IOCs for enriched articles
		for _, a := range batch {
			if len(a.IOCs) > 0 {
				iocs := make([]store.IOCEntry, len(a.IOCs))
				for j, ioc := range a.IOCs {
					iocs[j] = store.IOCEntry{
						Value:       ioc.Value,
						Type:        ioc.Type,
						ThreatActor: a.ThreatActor,
						Confidence:  50,
					}
				}
				if err := se.DB.SaveIOCs(a.Link, iocs); err != nil {
					log.Printf("warning: save IOCs for %q: %v", a.Link, err)
				}
			}
		}
		savedCount += len(batch)
		se.setProgress("saving", fmt.Sprintf("Sparar artiklar (%d/%d)", savedCount, len(scored)), savedCount, len(scored))
		if se.OnBatch != nil {
			se.OnBatch()
		}
	}

	// Prune seen entries older than fetch window
	se.DB.PruneSeen(maxAge)

	// Prune articles from removed feeds
	kept, removed, err := se.DB.PruneArticles(feedNames...)
	if err != nil {
		log.Printf("warning: prune articles: %v", err)
	} else if removed > 0 {
		log.Printf("pruned %d articles from inactive feeds, %d remaining", removed, kept)
	}

	// Rescore articles with missing fields
	if !se.SkipRescore {
		se.setProgress("rescoring", "Ompoängsätter ofullständiga artiklar...", 0, 0)
		se.rescoreIncomplete(ctx, recentFeedback)
	}

	// Auto-discover new Telegram channels from article content
	if se.Cfg.TelegramAPIID != 0 {
		se.discoverTelegramChannels(ctx, articles)
	}

	result.Duration = time.Since(start)
	se.saveSyncStatus(result)
	se.setProgress("done", fmt.Sprintf("Klart — %d nya, %d poängsatta (%s)", result.New, result.Scored, result.Duration.Round(time.Second)), 0, 0)

	log.Printf("sync complete: %d fetched, %d new, %d scored in %s",
		result.Fetched, result.New, result.Scored, result.Duration.Round(time.Second))

	return result, nil
}

// FilteredArticles returns cached articles filtered and sorted by config.
func (se *SyncEngine) FilteredArticles() []scorer.ScoredArticle {
	allCached, _ := se.DB.LoadArticles()
	var filtered []scorer.ScoredArticle
	for _, a := range allCached {
		t, _ := time.Parse("2006-01-02T15:04", a.Published)
		sa := scorer.ScoredArticle{
			Article: feed.Article{
				Title:       a.Title,
				Link:        a.Link,
				Description: a.Description,
				Content:     a.Content,
				Source:      a.Source,
				Published:   t,
			},
			Score:              a.Score,
			Severity:           a.Severity,
			Verified:           a.Verified,
			Scope:              a.Scope,
			Novelty:            a.Novelty,
			Summary:            a.Summary,
			Detail:             a.Detail,
			ThreatActor:        a.ThreatActor,
			ThreatActorAliases: a.ThreatActorAliases,
			ActivityType:       a.ActivityType,
			ActorType:          a.ActorType,
			Origin:             a.Origin,
			Country:            a.Country,
			Region:             a.Region,
			Impact:             a.Impact,
			Sector:             a.Sector,
			TTPs:               a.TTPs,
		}
		if sa.Score >= se.Cfg.MinScore {
			filtered = append(filtered, sa)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Score > filtered[j].Score
	})
	if len(filtered) > se.Cfg.TopN {
		filtered = filtered[:se.Cfg.TopN]
	}
	return filtered
}

func (se *SyncEngine) feedNames() []string {
	names := make([]string, 0, len(se.Cfg.Feeds)+len(se.Cfg.TelegramChannels)+2)
	for _, f := range se.Cfg.Feeds {
		names = append(names, f.Name)
	}
	names = append(names, "DDoSia Targets")
	if se.Cfg.CloudflareKey != "" {
		names = append(names, "Cloudflare Radar")
	}
	if se.Cfg.TelegramAPIID != 0 {
		for _, ch := range se.Cfg.TelegramChannels {
			names = append(names, ch.Name+" (Telegram)")
		}
	}
	return names
}

var tgUsernameRe = regexp.MustCompile(`(?:t\.me/|@)([A-Za-z0-9_]{5,32})`)

var tgBlockedUsernames = map[string]bool{
	"s": true, "share": true, "joinchat": true, "addstickers": true,
	"proxy": true, "socks": true, "setlanguage": true, "addtheme": true,
	"iv": true, "login": true, "confirmphone": true, "addlist": true,
}

// discoverTelegramChannels scans article text for t.me/ and @ mentions,
// validates them via MTProto, and saves as pending channels for approval.
func (se *SyncEngine) discoverTelegramChannels(ctx context.Context, articles []feed.Article) {
	known := make(map[string]bool)
	for _, ch := range se.Cfg.TelegramChannels {
		known[strings.ToLower(ch.Username)] = true
	}

	counts := make(map[string]int)
	for _, a := range articles {
		text := a.Title + " " + a.Description
		for _, m := range tgUsernameRe.FindAllStringSubmatch(text, -1) {
			username := m[1]
			lower := strings.ToLower(username)
			if tgBlockedUsernames[lower] || known[lower] {
				continue
			}
			counts[username]++
		}
	}

	var candidates []string
	for username, count := range counts {
		if count >= 2 {
			candidates = append(candidates, username)
		}
	}
	if len(candidates) == 0 {
		return
	}
	sort.Strings(candidates)

	home, _ := os.UserHomeDir()
	sessionPath := filepath.Join(home, ".newsdigest", "telegram.session")
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		return
	}

	storage := &session.FileStorage{Path: sessionPath}
	client := telegram.NewClient(se.Cfg.TelegramAPIID, se.Cfg.TelegramAPIHash, telegram.Options{
		SessionStorage: storage,
	})

	tgCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err := client.Run(tgCtx, func(ctx context.Context) error {
		status, err := client.Auth().Status(ctx)
		if err != nil || !status.Authorized {
			return fmt.Errorf("not authorized")
		}
		api := client.API()
		for _, username := range candidates {
			resolved, err := api.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{Username: username})
			if err != nil {
				continue
			}
			for _, c := range resolved.Chats {
				if ch, ok := c.(*tg.Channel); ok && ch.Broadcast {
					if err := se.DB.AddPendingChannel(username, counts[username]); err != nil {
						log.Printf("warning: save pending channel %s: %v", username, err)
					} else {
						log.Printf("discovered pending telegram channel: @%s (%d mentions)", username, counts[username])
					}
					// Auto-approve if enabled and criteria met
					if se.Cfg.TelegramAutoApprove && se.shouldAutoApprove(username, counts[username], ch.Title) {
						se.autoApproveChannel(username, ch.Title)
					}
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		return nil
	})
	if err != nil {
		log.Printf("warning: telegram discovery: %v", err)
	}
}

// shouldAutoApprove checks if a discovered channel qualifies for auto-approval.
// Criteria: mention_count >= threshold AND (matches known threat actor alias OR in deepdarkCTI list).
func (se *SyncEngine) shouldAutoApprove(username string, mentionCount int, channelTitle string) bool {
	if mentionCount < se.Cfg.TelegramAutoThreshold {
		return false
	}
	// Check if channel title matches a known threat actor alias
	if scorer.IsKnownActor(channelTitle) {
		log.Printf("auto-approve: @%s matches known actor via title %q", username, channelTitle)
		return true
	}
	// Check username against known actor aliases
	if scorer.IsKnownActor(username) {
		log.Printf("auto-approve: @%s matches known actor via username", username)
		return true
	}
	// Check against deepdarkCTI channels if loaded
	deepDarkMu.RLock()
	channels := deepDarkChannels
	deepDarkMu.RUnlock()
	if channels != nil && channels[strings.ToLower(username)] {
		log.Printf("auto-approve: @%s found in deepdarkCTI list", username)
		return true
	}
	return false
}

// autoApproveChannel adds a channel to the active config and removes from pending.
func (se *SyncEngine) autoApproveChannel(username, title string) {
	name := title
	if name == "" {
		name = username
	}
	se.Cfg.TelegramChannels = append(se.Cfg.TelegramChannels, config.TelegramChannel{
		Name:     name,
		Username: username,
	})
	se.DB.RemovePendingChannel(username)
	log.Printf("auto-approved telegram channel: @%s (%s)", username, name)
}

func (se *SyncEngine) saveSyncStatus(result *SyncResult) {
	feeds := make([]store.FeedSyncStatus, len(result.PerFeed))
	for i, fs := range result.PerFeed {
		feeds[i] = store.FeedSyncStatus{
			Name:     fs.Name,
			URL:      fs.URL,
			Articles: fs.Articles,
			Error:    fs.Error,
			LastSync: fs.LastSync.Format(time.RFC3339),
		}
		if !fs.LastData.IsZero() {
			feeds[i].LastData = fs.LastData.Format(time.RFC3339)
		}
	}
	status := &store.SyncStatusData{
		LastRun:  time.Now().Format(time.RFC3339),
		Feeds:    feeds,
		Fetched:  result.Fetched,
		New:      result.New,
		Scored:   result.Scored,
		Duration: result.Duration.Round(time.Second).String(),
	}
	if err := se.DB.SaveSyncStatus(status); err != nil {
		log.Printf("warning: save sync status: %v", err)
	}
}

// rescoreIncomplete finds cached articles with missing fields and rescores them.
func (se *SyncEngine) rescoreIncomplete(ctx context.Context, feedback []store.FeedbackEntry) {
	incomplete, err := se.DB.NeedsRescoreList(scorer.CurrentScoreVersion)
	if err != nil {
		log.Printf("warning: load articles for rescore: %v", err)
		return
	}

	if len(incomplete) == 0 {
		return
	}

	log.Printf("rescoring %d articles with missing fields...", len(incomplete))

	articles := make([]feed.Article, len(incomplete))
	for i, a := range incomplete {
		t, _ := time.Parse("2006-01-02T15:04", a.Published)
		articles[i] = feed.Article{
			Title:       a.Title,
			Link:        a.Link,
			Description: a.Description,
			Content:     a.Content,
			Source:      a.Source,
			Published:   t,
		}
	}

	scored, err := scorer.Score(ctx, se.Cfg, articles, feedback)
	if err != nil {
		log.Printf("warning: rescore incomplete: %v", err)
		return
	}

	var updated int
	for _, a := range scored {
		if a.Score == 0 && a.Severity == 0 {
			continue // scoring failed for this article
		}
		ca := scoredToCached(a)
		for _, inc := range incomplete {
			if inc.Link == a.Link {
				if ca.Content == "" {
					ca.Content = inc.Content
				}
				ca.Sources = inc.Sources
				break
			}
		}
		if err := se.DB.UpdateArticle(ca); err != nil {
			log.Printf("warning: update rescored article: %v", err)
		}
		// Save IOCs from rescored articles
		if len(a.IOCs) > 0 {
			iocs := make([]store.IOCEntry, len(a.IOCs))
			for j, ioc := range a.IOCs {
				iocs[j] = store.IOCEntry{
					Value:       ioc.Value,
					Type:        ioc.Type,
					ThreatActor: a.ThreatActor,
					Confidence:  50,
				}
			}
			if err := se.DB.SaveIOCs(a.Link, iocs); err != nil {
				log.Printf("warning: save IOCs for rescored %q: %v", a.Link, err)
			}
		}
		updated++
	}

	if updated > 0 {
		log.Printf("rescored %d/%d articles successfully", updated, len(incomplete))
	} else {
		log.Printf("warning: rescore failed — 0/%d articles scored (API issue?)", len(incomplete))
	}
}
