package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSaveAndLoadArticles(t *testing.T) {
	db := openTestDB(t)

	articles := []CachedArticle{
		{
			Title:        "Test Article 1",
			Link:         "https://example.com/1",
			Source:       "TestFeed",
			Published:    "2026-03-08T12:00",
			Score:        7.5,
			Severity:     8.0,
			Verified:     true,
			Scope:        3,
			Novelty:      2,
			Summary:      "Test summary",
			ActivityType: "Ransomware",
			Country:      "Sverige",
			Region:       "Norden",
			ScoreVersion: 6,
		},
		{
			Title:        "Test Article 2",
			Link:         "https://example.com/2",
			Source:       "TestFeed",
			Published:    "2026-03-08T13:00",
			Score:        5.0,
			Severity:     5.0,
			ScoreVersion: 6,
		},
	}

	if err := db.SaveArticles(articles); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := db.LoadArticles()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("got %d articles, want 2", len(loaded))
	}

	// Ordered by score DESC
	if loaded[0].Score != 7.5 {
		t.Errorf("first article score = %v, want 7.5", loaded[0].Score)
	}
	if loaded[0].Title != "Test Article 1" {
		t.Errorf("first article title = %q, want %q", loaded[0].Title, "Test Article 1")
	}
	if !loaded[0].Verified {
		t.Error("first article should be verified")
	}
	if loaded[0].ActivityType != "Ransomware" {
		t.Errorf("activity_type = %q, want Ransomware", loaded[0].ActivityType)
	}
}

func TestUpsertHigherScoreWins(t *testing.T) {
	db := openTestDB(t)

	// Insert with low score
	low := []CachedArticle{{
		Title:        "Original Title",
		Link:         "https://example.com/1",
		Source:       "Feed1",
		Score:        3.0,
		Severity:     3.0,
		Summary:      "Low score summary",
		ScoreVersion: 5,
	}}
	if err := db.SaveArticles(low); err != nil {
		t.Fatal(err)
	}

	// Upsert with higher score — should update
	high := []CachedArticle{{
		Title:        "Updated Title",
		Link:         "https://example.com/1",
		Source:       "Feed2",
		Score:        8.0,
		Severity:     8.0,
		Summary:      "High score summary",
		ScoreVersion: 6,
	}}
	if err := db.SaveArticles(high); err != nil {
		t.Fatal(err)
	}

	loaded, _ := db.LoadArticles()
	if len(loaded) != 1 {
		t.Fatalf("got %d articles, want 1", len(loaded))
	}
	if loaded[0].Score != 8.0 {
		t.Errorf("score = %v, want 8.0 (higher score should win)", loaded[0].Score)
	}
	if loaded[0].Title != "Updated Title" {
		t.Errorf("title = %q, want %q (higher score should update title)", loaded[0].Title, "Updated Title")
	}
}

func TestUpsertLowerScoreLoses(t *testing.T) {
	db := openTestDB(t)

	// Insert with high score
	high := []CachedArticle{{
		Title:        "Original",
		Link:         "https://example.com/1",
		Score:        8.0,
		Summary:      "Keep this",
		ScoreVersion: 6,
	}}
	db.SaveArticles(high)

	// Upsert with lower score — should NOT update
	low := []CachedArticle{{
		Title:        "Should Not Win",
		Link:         "https://example.com/1",
		Score:        3.0,
		Summary:      "Discard this",
		ScoreVersion: 6,
	}}
	db.SaveArticles(low)

	loaded, _ := db.LoadArticles()
	if loaded[0].Title != "Original" {
		t.Errorf("title = %q, want %q (lower score should not overwrite)", loaded[0].Title, "Original")
	}
	if loaded[0].Summary != "Keep this" {
		t.Errorf("summary changed when it shouldn't have")
	}
}

func TestSourceMerging(t *testing.T) {
	db := openTestDB(t)

	// Save from Feed1
	db.SaveArticles([]CachedArticle{{
		Title:  "Multi-source article",
		Link:   "https://example.com/1",
		Source: "Feed1",
		Score:  5.0,
	}})

	// Save same link from Feed2 with higher score
	db.SaveArticles([]CachedArticle{{
		Title:  "Multi-source article",
		Link:   "https://example.com/1",
		Source: "Feed2",
		Score:  6.0,
	}})

	loaded, _ := db.LoadArticles()
	if len(loaded) != 1 {
		t.Fatalf("got %d articles, want 1", len(loaded))
	}
	if len(loaded[0].Sources) < 2 {
		t.Errorf("sources = %v, want at least 2 sources merged", loaded[0].Sources)
	}
}

func TestIsNewAndMark(t *testing.T) {
	db := openTestDB(t)

	url := "https://example.com/article"
	if !db.IsNew(url) {
		t.Error("URL should be new before marking")
	}

	db.Mark(url)
	if db.IsNew(url) {
		t.Error("URL should NOT be new after marking")
	}

	// Mark again — should be idempotent
	db.Mark(url)
	if db.IsNew(url) {
		t.Error("URL should still not be new")
	}
}

func TestPruneSeen(t *testing.T) {
	db := openTestDB(t)

	db.Mark("https://example.com/old")
	// Manually set old timestamp
	db.db.Exec("UPDATE seen SET first_seen = ? WHERE url = ?",
		time.Now().Add(-30*24*time.Hour).UTC().Format(time.RFC3339),
		"https://example.com/old")

	db.Mark("https://example.com/new")

	db.PruneSeen(7 * 24 * time.Hour) // prune older than 7 days

	if !db.IsNew("https://example.com/old") {
		t.Error("old URL should have been pruned")
	}
	if db.IsNew("https://example.com/new") {
		t.Error("new URL should NOT have been pruned")
	}
}

func TestFeedback(t *testing.T) {
	db := openTestDB(t)

	entry := FeedbackEntry{
		URL:   "https://example.com/1",
		Title: "Test Article",
		Vote:  "up",
		Time:  "2026-03-08T12:00:00Z",
	}
	if err := db.SaveFeedback(entry); err != nil {
		t.Fatalf("save feedback: %v", err)
	}

	loaded, err := db.LoadFeedback()
	if err != nil {
		t.Fatalf("load feedback: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("got %d entries, want 1", len(loaded))
	}
	if loaded[0].Vote != "up" {
		t.Errorf("vote = %q, want %q", loaded[0].Vote, "up")
	}
}

func TestFeedbackLimit200(t *testing.T) {
	db := openTestDB(t)

	// Insert 210 entries
	for i := 0; i < 210; i++ {
		db.SaveFeedback(FeedbackEntry{
			URL:   "https://example.com/" + string(rune('a'+i%26)),
			Title: "Article",
			Vote:  "up",
			Time:  "2026-03-08T12:00:00Z",
		})
	}

	loaded, _ := db.LoadFeedback()
	if len(loaded) > 200 {
		t.Errorf("feedback count = %d, want <= 200", len(loaded))
	}
}

func TestRecalcScores(t *testing.T) {
	db := openTestDB(t)

	// Insert article with old version and known fields
	db.SaveArticles([]CachedArticle{{
		Title:        "Test",
		Link:         "https://example.com/1",
		Score:        1.0, // wrong score
		Severity:     8.0,
		Verified:     true,
		Scope:        3,
		Novelty:      2,
		ScoreVersion: 5, // old version
	}})

	// Recalc to version 6
	affected, err := db.RecalcScores(6)
	if err != nil {
		t.Fatalf("recalc: %v", err)
	}
	if affected != 1 {
		t.Errorf("affected = %d, want 1", affected)
	}

	loaded, _ := db.LoadArticles()
	// Expected: 8*0.65 + 0.5 + 3*0.25 + 2*0.35 = 5.2 + 0.5 + 0.75 + 0.7 = 7.15
	want := 7.15
	got := loaded[0].Score
	if got < want-0.01 || got > want+0.01 {
		t.Errorf("recalculated score = %v, want ~%v", got, want)
	}
	if loaded[0].ScoreVersion != 6 {
		t.Errorf("score_version = %d, want 6", loaded[0].ScoreVersion)
	}
}

func TestRecalcScoresSkipsCurrent(t *testing.T) {
	db := openTestDB(t)

	db.SaveArticles([]CachedArticle{{
		Title:        "Test",
		Link:         "https://example.com/1",
		Score:        7.15,
		Severity:     8.0,
		Verified:     true,
		Scope:        3,
		Novelty:      2,
		ScoreVersion: 6,
	}})

	affected, err := db.RecalcScores(6)
	if err != nil {
		t.Fatal(err)
	}
	if affected != 0 {
		t.Errorf("affected = %d, want 0 (already at current version with correct score)", affected)
	}
}

func TestUpdateArticle(t *testing.T) {
	db := openTestDB(t)

	db.SaveArticles([]CachedArticle{{
		Title: "Test",
		Link:  "https://example.com/1",
		Score: 5.0,
	}})

	err := db.UpdateArticle(CachedArticle{
		Link:         "https://example.com/1",
		Score:        8.0,
		Severity:     8.0,
		Summary:      "Updated summary",
		ThreatActor:  "APT28",
		ScoreVersion: 6,
	})
	if err != nil {
		t.Fatal(err)
	}

	loaded, _ := db.LoadArticles()
	if loaded[0].Score != 8.0 {
		t.Errorf("score = %v, want 8.0", loaded[0].Score)
	}
	if loaded[0].Summary != "Updated summary" {
		t.Errorf("summary = %q, want %q", loaded[0].Summary, "Updated summary")
	}
	if loaded[0].ThreatActor != "APT28" {
		t.Errorf("threat_actor = %q, want APT28", loaded[0].ThreatActor)
	}
}

func TestNeedsRescoreList(t *testing.T) {
	db := openTestDB(t)

	// Article with current version and all fields — should NOT need rescore
	db.SaveArticles([]CachedArticle{{
		Title:        "Complete",
		Link:         "https://example.com/1",
		Score:        7.0,
		Severity:     7.0,
		Summary:      "Has summary",
		ActivityType: "Ransomware",
		Country:      "Sverige",
		Region:       "Norden",
		ScoreVersion: 6,
	}})

	// Article with old version — should need rescore
	db.SaveArticles([]CachedArticle{{
		Title:        "Old Version",
		Link:         "https://example.com/2",
		Score:        5.0,
		Severity:     5.0,
		Summary:      "Has summary",
		ActivityType: "DDoS",
		Country:      "USA",
		Region:       "Nordamerika",
		ScoreVersion: 4, // old
	}})

	// Article with missing summary — should need rescore
	db.SaveArticles([]CachedArticle{{
		Title:        "Missing Fields",
		Link:         "https://example.com/3",
		Score:        3.0,
		Severity:     3.0,
		ScoreVersion: 6,
	}})

	list, err := db.NeedsRescoreList(6)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Errorf("got %d articles needing rescore, want 2", len(list))
	}
}

func TestPruneArticles(t *testing.T) {
	db := openTestDB(t)

	db.SaveArticles([]CachedArticle{
		{Title: "Keep", Link: "https://example.com/1", Source: "ActiveFeed", Score: 5.0},
		{Title: "Remove", Link: "https://example.com/2", Source: "RemovedFeed", Score: 3.0},
		{Title: "Also Keep", Link: "https://example.com/3", Source: "ActiveFeed", Score: 4.0},
	})

	kept, removed, err := db.PruneArticles("ActiveFeed")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if kept != 2 {
		t.Errorf("kept = %d, want 2", kept)
	}

	loaded, _ := db.LoadArticles()
	for _, a := range loaded {
		if a.Source == "RemovedFeed" {
			t.Error("article from RemovedFeed should have been pruned")
		}
	}
}

func TestArticleCount(t *testing.T) {
	db := openTestDB(t)

	if db.ArticleCount() != 0 {
		t.Error("empty db should have 0 articles")
	}

	db.SaveArticles([]CachedArticle{
		{Title: "A", Link: "https://a.com/1", Score: 1},
		{Title: "B", Link: "https://b.com/2", Score: 2},
	})

	if db.ArticleCount() != 2 {
		t.Errorf("count = %d, want 2", db.ArticleCount())
	}
}

func TestActorDescriptions(t *testing.T) {
	db := openTestDB(t)

	if err := db.SaveActorDescription("APT28", "Russian state-sponsored group"); err != nil {
		t.Fatal(err)
	}

	descs, err := db.LoadActorDescriptions()
	if err != nil {
		t.Fatal(err)
	}
	if descs["APT28"] != "Russian state-sponsored group" {
		t.Errorf("description = %q", descs["APT28"])
	}

	// Upsert
	db.SaveActorDescription("APT28", "Updated description")
	descs, _ = db.LoadActorDescriptions()
	if descs["APT28"] != "Updated description" {
		t.Error("upsert should update description")
	}
}

func TestPendingChannels(t *testing.T) {
	db := openTestDB(t)

	if err := db.AddPendingChannel("testchannel", 3); err != nil {
		t.Fatal(err)
	}

	channels, err := db.PendingChannels()
	if err != nil {
		t.Fatal(err)
	}
	if len(channels) != 1 {
		t.Fatalf("got %d channels, want 1", len(channels))
	}
	if channels[0].Username != "testchannel" {
		t.Errorf("username = %q", channels[0].Username)
	}
	if channels[0].MentionCount != 3 {
		t.Errorf("mention_count = %d, want 3", channels[0].MentionCount)
	}

	// Add more mentions — should accumulate
	db.AddPendingChannel("testchannel", 2)
	channels, _ = db.PendingChannels()
	if channels[0].MentionCount != 5 {
		t.Errorf("mention_count = %d, want 5 (accumulated)", channels[0].MentionCount)
	}

	// Remove
	db.RemovePendingChannel("testchannel")
	channels, _ = db.PendingChannels()
	if len(channels) != 0 {
		t.Error("channel should have been removed")
	}
}

func TestSyncStatus(t *testing.T) {
	db := openTestDB(t)

	status := &SyncStatusData{
		LastRun:  "2026-03-08T12:00:00Z",
		Fetched:  100,
		New:      10,
		Scored:   10,
		Duration: "2m30s",
		Feeds: []FeedSyncStatus{
			{Name: "Feed1", URL: "https://feed1.com", Articles: 50},
			{Name: "Feed2", URL: "https://feed2.com", Articles: 30, Error: "timeout"},
		},
	}

	if err := db.SaveSyncStatus(status); err != nil {
		t.Fatal(err)
	}

	loaded, err := db.LoadSyncStatus()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fetched != 100 {
		t.Errorf("fetched = %d, want 100", loaded.Fetched)
	}
	if loaded.New != 10 {
		t.Errorf("new = %d, want 10", loaded.New)
	}
	if len(loaded.Feeds) != 2 {
		t.Fatalf("feeds = %d, want 2", len(loaded.Feeds))
	}
	if loaded.Feeds[1].Error != "timeout" {
		t.Errorf("feed2 error = %q, want %q", loaded.Feeds[1].Error, "timeout")
	}
}

func TestContentHash(t *testing.T) {
	// Same title+domain = same hash
	h1 := ContentHash("Breaking: Major Breach!", "https://example.com/article/123")
	h2 := ContentHash("Breaking: Major Breach!", "https://example.com/different/path")
	if h1 != h2 {
		t.Error("same title+domain should produce same hash")
	}

	// Different domain = different hash
	h3 := ContentHash("Breaking: Major Breach!", "https://other.com/article/123")
	if h1 == h3 {
		t.Error("different domain should produce different hash")
	}

	// Different title = different hash
	h4 := ContentHash("Different Title", "https://example.com/article/123")
	if h1 == h4 {
		t.Error("different title should produce different hash")
	}
}

func TestNormalizeTitle(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Breaking: Major Breach!", "breaking major breach"},
		{"  SPACES   everywhere  ", "spaces everywhere"},
		{"APT28 — New Campaign", "apt28 new campaign"},
		{"", ""},
	}
	for _, tt := range tests {
		got := NormalizeTitle(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeTitle(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNeedsRescore(t *testing.T) {
	complete := CachedArticle{
		Severity:     7.0,
		Summary:      "Has summary",
		ActivityType: "Ransomware",
		Region:       "Norden",
		Country:      "Sverige",
		ScoreVersion: 6,
	}
	if NeedsRescore(complete, 6) {
		t.Error("complete article should not need rescore")
	}

	// Old version
	old := complete
	old.ScoreVersion = 4
	if !NeedsRescore(old, 6) {
		t.Error("old version should need rescore")
	}

	// Missing summary
	noSummary := complete
	noSummary.Summary = ""
	if !NeedsRescore(noSummary, 6) {
		t.Error("missing summary should need rescore")
	}

	// Zero severity
	zeroSev := complete
	zeroSev.Severity = 0
	if !NeedsRescore(zeroSev, 6) {
		t.Error("zero severity should need rescore")
	}
}

func TestRecentFeedback(t *testing.T) {
	entries := make([]FeedbackEntry, 100)
	for i := range entries {
		entries[i] = FeedbackEntry{Title: "Article"}
	}

	recent := RecentFeedback(entries, 50)
	if len(recent) != 50 {
		t.Errorf("got %d, want 50", len(recent))
	}

	// Less than n
	small := RecentFeedback(entries[:10], 50)
	if len(small) != 10 {
		t.Errorf("got %d, want 10", len(small))
	}
}

func TestOverwriteArticles(t *testing.T) {
	db := openTestDB(t)

	// Insert initial articles
	db.SaveArticles([]CachedArticle{
		{Title: "Old 1", Link: "https://old.com/1", Score: 3.0},
		{Title: "Old 2", Link: "https://old.com/2", Score: 4.0},
	})

	// Overwrite with completely new set
	err := db.OverwriteArticles([]CachedArticle{
		{Title: "New 1", Link: "https://new.com/1", Source: "NewFeed", Score: 7.0},
	})
	if err != nil {
		t.Fatal(err)
	}

	loaded, _ := db.LoadArticles()
	if len(loaded) != 1 {
		t.Fatalf("got %d articles, want 1 (overwrite should replace all)", len(loaded))
	}
	if loaded[0].Title != "New 1" {
		t.Errorf("title = %q, want %q", loaded[0].Title, "New 1")
	}
}

func TestParseCVEs(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{`["CVE-2024-1234","CVE-2024-5678"]`, 2},
		{`[]`, 0},
		{``, 0},
		{`invalid`, 0},
	}
	for _, tt := range tests {
		got := ParseCVEs(tt.input)
		if len(got) != tt.want {
			t.Errorf("ParseCVEs(%q) = %d items, want %d", tt.input, len(got), tt.want)
		}
	}
}

func TestSaveAndLoadIOCs(t *testing.T) {
	db := openTestDB(t)

	// First save an article to link IOCs to
	db.SaveArticles([]CachedArticle{{
		Title: "IOC Test", Link: "https://example.com/ioc1", Source: "TestFeed",
		Score: 7.0, ScoreVersion: 6,
	}})

	iocs := []IOCEntry{
		{Value: "185.220.101.42", Type: "ipv4", ThreatActor: "APT28", Confidence: 80},
		{Value: "evil.xyz", Type: "domain", MalwareFamily: "Emotet", Confidence: 60},
		{Value: "d41d8cd98f00b204e9800998ecf8427e", Type: "md5", Confidence: 50},
	}

	err := db.SaveIOCs("https://example.com/ioc1", iocs)
	if err != nil {
		t.Fatalf("SaveIOCs: %v", err)
	}

	if db.IOCCount() != 3 {
		t.Errorf("IOCCount = %d, want 3", db.IOCCount())
	}

	// Load by article
	loaded, err := db.LoadIOCsForArticle("https://example.com/ioc1")
	if err != nil {
		t.Fatalf("LoadIOCsForArticle: %v", err)
	}
	if len(loaded) != 3 {
		t.Errorf("LoadIOCsForArticle got %d, want 3", len(loaded))
	}
}

func TestIOCsForActor(t *testing.T) {
	db := openTestDB(t)

	db.SaveArticles([]CachedArticle{{
		Title: "APT28 Attack", Link: "https://example.com/apt28", Source: "Feed",
		ThreatActor: "APT28", Score: 8.0, ScoreVersion: 6,
	}})

	db.SaveIOCs("https://example.com/apt28", []IOCEntry{
		{Value: "1.2.3.4", Type: "ipv4", ThreatActor: "APT28", Confidence: 90},
	})

	iocs, err := db.LoadIOCsForActor("APT28")
	if err != nil {
		t.Fatalf("LoadIOCsForActor: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("got %d IOCs, want 1", len(iocs))
	}
	if iocs[0].Value != "1.2.3.4" {
		t.Errorf("value = %q", iocs[0].Value)
	}
}

func TestSearchIOCs(t *testing.T) {
	db := openTestDB(t)

	db.SaveArticles([]CachedArticle{{
		Title: "Test", Link: "https://example.com/search", Source: "Feed",
		Score: 5.0, ScoreVersion: 6,
	}})

	db.SaveIOCs("https://example.com/search", []IOCEntry{
		{Value: "185.220.101.42", Type: "ipv4", Confidence: 80},
		{Value: "185.220.101.43", Type: "ipv4", Confidence: 70},
		{Value: "10.0.0.1", Type: "ipv4", Confidence: 50},
	})

	// Search by prefix
	results, err := db.SearchIOCs("185.220")
	if err != nil {
		t.Fatalf("SearchIOCs: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}
}

func TestIOCUpsertUpdatesFields(t *testing.T) {
	db := openTestDB(t)

	db.SaveArticles([]CachedArticle{{
		Title: "Test", Link: "https://example.com/upsert", Source: "Feed",
		Score: 5.0, ScoreVersion: 6,
	}})

	// First insert with low confidence
	db.SaveIOCs("https://example.com/upsert", []IOCEntry{
		{Value: "1.2.3.4", Type: "ipv4", Confidence: 30},
	})

	// Upsert with higher confidence and actor attribution
	db.SaveIOCs("https://example.com/upsert", []IOCEntry{
		{Value: "1.2.3.4", Type: "ipv4", ThreatActor: "APT28", Confidence: 90},
	})

	// Should keep higher confidence and have actor
	results, _ := db.SearchIOCs("1.2.3.4")
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Confidence != 90 {
		t.Errorf("confidence = %d, want 90", results[0].Confidence)
	}
	if results[0].ThreatActor != "APT28" {
		t.Errorf("threat_actor = %q, want APT28", results[0].ThreatActor)
	}
}

func TestSaveIOCsNoArticle(t *testing.T) {
	db := openTestDB(t)

	err := db.SaveIOCs("https://nonexistent.com", []IOCEntry{
		{Value: "1.2.3.4", Type: "ipv4"},
	})
	if err == nil {
		t.Error("expected error for nonexistent article")
	}
}

func TestSaveIOCsEmpty(t *testing.T) {
	db := openTestDB(t)
	err := db.SaveIOCs("https://example.com", nil)
	if err != nil {
		t.Errorf("SaveIOCs(nil) should be no-op, got %v", err)
	}
}

func TestLoadFilteredArticles(t *testing.T) {
	db := openTestDB(t)

	articles := []CachedArticle{
		{
			Title: "Nordic Ransomware", Link: "https://example.com/1",
			Source: "Feed1", Published: "2026-03-08",
			Score: 8.0, Severity: 8.0, ScoreVersion: 6,
			ThreatActor: "APT28", Region: "Norden", Sector: "Energi",
			ActivityType: "Ransomware",
		},
		{
			Title: "Asia DDoS", Link: "https://example.com/2",
			Source: "Feed2", Published: "2026-03-07",
			Score: 5.0, Severity: 5.0, ScoreVersion: 6,
			ThreatActor: "Lazarus", Region: "Asien", Sector: "Bankverksamhet",
			ActivityType: "DDoS",
		},
		{
			Title: "Old European Breach", Link: "https://example.com/3",
			Source: "Feed3", Published: "2026-01-01",
			Score: 6.0, Severity: 6.0, ScoreVersion: 6,
			ThreatActor: "APT28", Region: "Europa", Sector: "Energi",
			ActivityType: "Dataläcka",
		},
		{
			Title: "Global DDoS Campaign", Link: "https://example.com/5",
			Source: "Feed5", Published: "2026-03-06",
			Score: 4.0, Severity: 4.0, ScoreVersion: 6,
			ThreatActor: "NoName", Region: "Globalt",
			ActivityType: "DDoS",
		},
	}
	if err := db.SaveArticles(articles); err != nil {
		t.Fatal(err)
	}

	t.Run("no filter", func(t *testing.T) {
		result, err := db.LoadFilteredArticles(ReportFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 4 {
			t.Errorf("got %d, want 4", len(result))
		}
	})

	t.Run("filter by actor", func(t *testing.T) {
		result, err := db.LoadFilteredArticles(ReportFilter{Actor: "APT28"})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 2 {
			t.Errorf("got %d, want 2", len(result))
		}
	})

	t.Run("region filter done in Go not SQL", func(t *testing.T) {
		// Region filtering is done in Go via scorer.MatchRegion,
		// so LoadFilteredArticles returns all articles regardless of Region.
		result, err := db.LoadFilteredArticles(ReportFilter{Region: "Norden"})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 4 {
			t.Errorf("got %d, want 4 (region filtering in Go, not SQL)", len(result))
		}
	})

	t.Run("filter by sector", func(t *testing.T) {
		result, err := db.LoadFilteredArticles(ReportFilter{Sectors: []string{"Energi"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 2 {
			t.Errorf("got %d, want 2", len(result))
		}
	})

	t.Run("filter by min score", func(t *testing.T) {
		result, err := db.LoadFilteredArticles(ReportFilter{MinScore: 6.0})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 2 {
			t.Errorf("got %d, want 2 (score >= 6)", len(result))
		}
	})

	t.Run("filter by date range", func(t *testing.T) {
		after, _ := time.Parse("2006-01-02", "2026-03-01")
		result, err := db.LoadFilteredArticles(ReportFilter{After: after})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 3 {
			t.Errorf("got %d, want 3 (after 2026-03-01)", len(result))
		}
	})

	t.Run("combined filters", func(t *testing.T) {
		after, _ := time.Parse("2006-01-02", "2026-03-01")
		result, err := db.LoadFilteredArticles(ReportFilter{
			Actor:    "APT28",
			Region:   "Norden",
			MinScore: 7.0,
			After:    after,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 1 {
			t.Errorf("got %d, want 1", len(result))
		}
		if len(result) > 0 && result[0].Title != "Nordic Ransomware" {
			t.Errorf("title = %q", result[0].Title)
		}
	})

	t.Run("no results", func(t *testing.T) {
		result, err := db.LoadFilteredArticles(ReportFilter{Actor: "NonExistent"})
		if err != nil {
			t.Fatal(err)
		}
		if len(result) != 0 {
			t.Errorf("got %d, want 0", len(result))
		}
	})

	t.Run("before includes articles with time component", func(t *testing.T) {
		// Add article with time in published field
		extra := []CachedArticle{{
			Title: "Same Day With Time", Link: "https://example.com/4",
			Source: "Feed4", Published: "2026-03-08T14:30:00Z",
			Score: 4.0, Severity: 4.0, ScoreVersion: 6,
			ThreatActor: "APT28", Region: "Norden",
		}}
		if err := db.SaveArticles(extra); err != nil {
			t.Fatal(err)
		}
		before, _ := time.Parse("2006-01-02", "2026-03-08")
		result, err := db.LoadFilteredArticles(ReportFilter{Before: before})
		if err != nil {
			t.Fatal(err)
		}
		// Should include the "2026-03-08T14:30:00Z" article
		found := false
		for _, a := range result {
			if a.Title == "Same Day With Time" {
				found = true
			}
		}
		if !found {
			t.Error("article published on Before date with time component should be included")
		}
	})
}
