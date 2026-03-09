package sync

import (
	"testing"
	"time"

	"news/internal/config"
	"news/internal/feed"
	"news/internal/scorer"
)

func TestScoredToCached(t *testing.T) {
	now := time.Date(2026, 3, 8, 14, 30, 0, 0, time.UTC)
	sa := scorer.ScoredArticle{
		Article: feed.Article{
			Title:       "Test Article",
			Link:        "https://example.com/1",
			Description: "Description",
			Content:     "Full content",
			Source:      "TestFeed",
			Published:   now,
		},
		Score:        7.5,
		Severity:     8.0,
		Verified:     true,
		Scope:        3,
		Novelty:      2,
		Summary:      "Test summary",
		Detail:       "Detailed analysis",
		ThreatActor:  "APT28",
		ActivityType: "Ransomware",
		Country:      "Sverige",
		Region:       "Norden",
		Sector:       "Energi",
		TTPs:         "T1566",
		AttackChain: []scorer.AttackChainStep{
			{Phase: "Initial Access", Actor: "APT28", TTP: "T1566", Detail: "Phishing"},
		},
		CVEs: []string{"CVE-2024-1234"},
	}

	ca := scoredToCached(sa)

	if ca.Title != "Test Article" {
		t.Errorf("title = %q", ca.Title)
	}
	if ca.Link != "https://example.com/1" {
		t.Errorf("link = %q", ca.Link)
	}
	if ca.Published != "2026-03-08T14:30" {
		t.Errorf("published = %q, want %q", ca.Published, "2026-03-08T14:30")
	}
	if ca.Score != 7.5 {
		t.Errorf("score = %v", ca.Score)
	}
	if !ca.Verified {
		t.Error("should be verified")
	}
	if ca.ThreatActor != "APT28" {
		t.Errorf("threat_actor = %q", ca.ThreatActor)
	}
	if ca.ScoreVersion != scorer.CurrentScoreVersion {
		t.Errorf("score_version = %d, want %d", ca.ScoreVersion, scorer.CurrentScoreVersion)
	}
	if ca.AttackChain == "[]" {
		t.Error("attack_chain should not be empty")
	}
	if ca.CVEs == "[]" {
		t.Error("cves should not be empty")
	}
	if len(ca.Sources) != 1 || ca.Sources[0] != "TestFeed" {
		t.Errorf("sources = %v", ca.Sources)
	}
}

func TestScoredToCachedEmptyOptionals(t *testing.T) {
	sa := scorer.ScoredArticle{
		Article: feed.Article{
			Title:     "Minimal",
			Link:      "https://example.com/2",
			Published: time.Time{},
		},
	}

	ca := scoredToCached(sa)

	if ca.AttackChain != "[]" {
		t.Errorf("empty attack_chain should be %q, got %q", "[]", ca.AttackChain)
	}
	if ca.CVEs != "[]" {
		t.Errorf("empty cves should be %q, got %q", "[]", ca.CVEs)
	}
}

func TestTelegramUsernameRegex(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"Check t.me/testchannel for updates", []string{"testchannel"}},
		{"Follow @cybernews for alerts", []string{"cybernews"}},
		{"Both t.me/channel1 and @channel2", []string{"channel1", "channel2"}},
		{"Short @ab is too short", nil},                     // less than 5 chars
		{"t.me/s/channel is a share link", nil}, // "s" blocked, "channel" not matched (no t.me/ prefix)
		{"No mentions here", nil},
	}

	for _, tt := range tests {
		matches := tgUsernameRe.FindAllStringSubmatch(tt.input, -1)
		var got []string
		for _, m := range matches {
			if !tgBlockedUsernames[m[1]] {
				got = append(got, m[1])
			}
		}
		if len(got) != len(tt.want) {
			t.Errorf("input=%q: got %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestTgBlockedUsernames(t *testing.T) {
	blocked := []string{"s", "share", "joinchat", "addstickers", "proxy", "login"}
	for _, u := range blocked {
		if !tgBlockedUsernames[u] {
			t.Errorf("%q should be blocked", u)
		}
	}

	if tgBlockedUsernames["legitimate_channel"] {
		t.Error("legitimate_channel should not be blocked")
	}
}

func TestSyncProgress(t *testing.T) {
	se := &SyncEngine{}

	// Initial state
	p := se.Progress()
	if p.Phase != "" {
		t.Errorf("initial phase = %q, want empty", p.Phase)
	}

	// Set progress
	se.setProgress("triage", "Triagerar...", 5, 10)
	p = se.Progress()
	if p.Phase != "triage" {
		t.Errorf("phase = %q, want triage", p.Phase)
	}
	if p.Done != 5 || p.Total != 10 {
		t.Errorf("progress = %d/%d, want 5/10", p.Done, p.Total)
	}
}

func TestParseDeepDarkCTI(t *testing.T) {
	markdown := `# Telegram channels
| Name | Link | Description |
|------|------|-------------|
| LockBit | [LockBit](https://t.me/lockbit_channel) | Ransomware |
| NoName | [NoName](https://t.me/noname05716) | DDoS |
| Short | [Short](https://t.me/ab) | Too short |
`
	channels := parseDeepDarkCTI(markdown)

	if !channels["lockbit_channel"] {
		t.Error("expected lockbit_channel to be parsed")
	}
	if !channels["noname05716"] {
		t.Error("expected noname05716 to be parsed")
	}
	if channels["ab"] {
		t.Error("short username (< 5 chars) should not be parsed")
	}
}

func TestParseDeepDarkCTIEmpty(t *testing.T) {
	channels := parseDeepDarkCTI("# No channels here")
	if len(channels) != 0 {
		t.Errorf("expected 0 channels, got %d", len(channels))
	}
}

func TestShouldAutoApprove(t *testing.T) {
	se := &SyncEngine{
		Cfg: &config.Config{
			TelegramAutoApprove:   true,
			TelegramAutoThreshold: 3,
		},
	}

	// Below threshold
	if se.shouldAutoApprove("testchannel", 2, "Test Channel") {
		t.Error("should not approve below threshold")
	}

	// Known actor name as channel title
	if !se.shouldAutoApprove("apt28_channel", 5, "APT28") {
		t.Error("should approve known actor name")
	}

	// Known actor alias as username
	if !se.shouldAutoApprove("lockbit", 3, "Some Channel") {
		t.Error("should approve known actor username")
	}

	// Unknown channel
	if se.shouldAutoApprove("random_channel", 5, "Random News") {
		t.Error("should not approve unknown channel")
	}
}

func TestShouldAutoApproveDeepDarkCTI(t *testing.T) {
	// Set up deepdarkCTI channels
	deepDarkMu.Lock()
	deepDarkChannels = map[string]bool{"known_threat_channel": true}
	deepDarkMu.Unlock()
	defer func() {
		deepDarkMu.Lock()
		deepDarkChannels = nil
		deepDarkMu.Unlock()
	}()

	se := &SyncEngine{
		Cfg: &config.Config{
			TelegramAutoApprove:   true,
			TelegramAutoThreshold: 3,
		},
	}

	if !se.shouldAutoApprove("known_threat_channel", 3, "Unknown Title") {
		t.Error("should approve channel found in deepdarkCTI")
	}
}
