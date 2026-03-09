package store

import (
	"strings"
	"unicode"
)

// NormalizeTitle returns a lowercased, whitespace-collapsed version of a title
// for fuzzy deduplication across feeds.
func NormalizeTitle(t string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(t) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			space = false
		} else if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}

// FeedbackEntry represents a user vote on an article.
type FeedbackEntry struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	Vote  string `json:"vote"` // "up" or "down"
	Time  string `json:"time"`
}

// RecentFeedback returns the last n entries for use in prompts.
func RecentFeedback(entries []FeedbackEntry, n int) []FeedbackEntry {
	if len(entries) <= n {
		return entries
	}
	return entries[len(entries)-n:]
}

// CachedArticle is the persistent format for article storage.
type CachedArticle struct {
	Title              string   `json:"title"`
	Link               string   `json:"link"`
	Description        string   `json:"description"`
	Content            string   `json:"content,omitempty"`
	Source             string   `json:"source"`
	Sources            []string `json:"sources,omitempty"`
	Published          string   `json:"published"`
	Score              float64  `json:"score"`
	Severity           float64  `json:"severity"`
	Verified           bool     `json:"verified"`
	Scope              int      `json:"scope"`
	Novelty            int      `json:"novelty"`
	Summary            string   `json:"summary"`
	Detail             string   `json:"detail"`
	ThreatActor        string   `json:"threat_actor"`
	ThreatActorAliases string   `json:"threat_actor_aliases"`
	ActivityType       string   `json:"activity_type"`
	ActorType          string   `json:"actor_type"`
	Origin             string   `json:"origin"`
	Country            string   `json:"country"`
	Region             string   `json:"region"`
	Impact             string   `json:"impact"`
	Sector             string   `json:"sector"`
	TTPs               string   `json:"ttps"`
	ScoreVersion       int      `json:"score_version"`
	AttackChain        string   `json:"attack_chain,omitempty"` // JSON array of AttackChainStep
	CVEs               string   `json:"cves,omitempty"`         // JSON array of CVE strings
}

// NeedsRescore returns true if the article is missing required fields or
// was scored with an outdated prompt version.
// Sector is intentionally excluded — many articles have no NIS2 sector.
func NeedsRescore(a CachedArticle, currentVersion int) bool {
	return a.ScoreVersion != currentVersion ||
		a.Severity <= 0 ||
		a.Summary == "" ||
		a.ActivityType == "" ||
		a.Region == "" ||
		a.Country == ""
}

// IOCEntry represents an indicator of compromise stored in the database.
type IOCEntry struct {
	ID            int64  `json:"id"`
	Value         string `json:"value"`
	Type          string `json:"type"` // "ipv4", "domain", "md5", "sha1", "sha256"
	Source        string `json:"source,omitempty"`
	ThreatActor   string `json:"threat_actor,omitempty"`
	MalwareFamily string `json:"malware_family,omitempty"`
	Confidence    int    `json:"confidence"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

// SyncStatus tracks per-feed sync state.
type FeedSyncStatus struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Articles int    `json:"articles"`
	Error    string `json:"error,omitempty"`
	LastSync string `json:"last_sync"`
	LastData string `json:"last_data,omitempty"`
}

// SyncStatusData holds the overall sync status.
type SyncStatusData struct {
	LastRun  string           `json:"last_run"`
	Feeds    []FeedSyncStatus `json:"feeds"`
	Fetched  int              `json:"fetched"`
	New      int              `json:"new_articles"`
	Scored   int              `json:"scored"`
	Duration string           `json:"duration"`
}
