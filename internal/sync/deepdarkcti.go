package sync

import (
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	gosync "sync"
	"time"
)

const (
	deepDarkCTIURL = "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/telegram.md"
	deepDarkCTICacheTTL = 24 * time.Hour
)

var (
	deepDarkChannels map[string]bool
	deepDarkMu       gosync.RWMutex
	deepDarkLoadedAt time.Time
)

// deepDarkCTI markdown format: lines like `| [ChannelName](https://t.me/username) | description |`
var deepDarkTgRe = regexp.MustCompile(`t\.me/([A-Za-z0-9_]{5,32})`)

// LoadDeepDarkCTIChannels fetches the deepdarkCTI Telegram channel list from GitHub.
// Returns a map of lowercased usernames. Results are cached for 24h.
func LoadDeepDarkCTIChannels() (map[string]bool, error) {
	deepDarkMu.RLock()
	if deepDarkChannels != nil && time.Since(deepDarkLoadedAt) < deepDarkCTICacheTTL {
		defer deepDarkMu.RUnlock()
		return deepDarkChannels, nil
	}
	deepDarkMu.RUnlock()

	resp, err := http.Get(deepDarkCTIURL)
	if err != nil {
		return deepDarkChannels, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return deepDarkChannels, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return deepDarkChannels, err
	}

	channels := parseDeepDarkCTI(string(body))

	deepDarkMu.Lock()
	deepDarkChannels = channels
	deepDarkLoadedAt = time.Now()
	deepDarkMu.Unlock()

	log.Printf("loaded %d channels from deepdarkCTI", len(channels))
	return channels, nil
}

// parseDeepDarkCTI extracts Telegram usernames from the markdown content.
func parseDeepDarkCTI(content string) map[string]bool {
	channels := make(map[string]bool)
	for _, match := range deepDarkTgRe.FindAllStringSubmatch(content, -1) {
		username := strings.ToLower(match[1])
		channels[username] = true
	}
	return channels
}
