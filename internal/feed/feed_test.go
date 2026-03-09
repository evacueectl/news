package feed

import (
	"strings"
	"testing"
	"time"
)

func TestParseDate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // expected in "2006-01-02T15:04:05Z07:00" format, or "zero"
	}{
		{"RFC3339", "2026-03-08T14:30:00Z", "2026-03-08T14:30:00Z"},
		{"RFC3339 offset", "2026-03-08T14:30:00+01:00", "2026-03-08T14:30:00+01:00"},
		{"RFC1123Z", "Sat, 08 Mar 2026 14:30:00 +0000", "2026-03-08T14:30:00Z"},
		{"RFC1123 no timezone", "Sat, 08 Mar 2026 14:30:00", "2026-03-08T14:30:00Z"},
		{"RFC1123Z GMT", "Sat, 08 Mar 2026 14:30:00 GMT", "2026-03-08T14:30:00Z"},
		{"datetime space", "2026-03-08 14:30:00", "2026-03-08T14:30:00Z"},
		{"empty", "", "zero"},
		{"whitespace", "   ", "zero"},
		{"unparseable", "not a date", "zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDate(tt.input)
			if tt.want == "zero" {
				if !got.IsZero() {
					t.Errorf("parseDate(%q) = %v, want zero time", tt.input, got)
				}
				return
			}
			expected, err := time.Parse(time.RFC3339, tt.want)
			if err != nil {
				t.Fatalf("bad test want value %q: %v", tt.want, err)
			}
			if !got.Equal(expected) {
				t.Errorf("parseDate(%q) = %v, want %v", tt.input, got, expected)
			}
		})
	}
}

func TestTryURLhaus(t *testing.T) {
	data := []byte(`{
		"query_status": "ok",
		"urls": [
			{"url": "http://evil.xyz/mal.exe", "host": "evil.xyz", "date_added": "2026-03-08 10:00:00", "threat": "malware_download", "tags": ["emotet"]},
			{"url": "http://bad.top/dl.bin", "host": "bad.top", "date_added": "2026-03-08 11:00:00", "threat": "malware_download", "tags": ["emotet"]},
			{"url": "http://other.ru/x", "host": "other.ru", "date_added": "2026-03-08 09:00:00", "threat": "malware_download", "tags": ["qakbot"]}
		]
	}`)

	articles := tryURLhaus("URLhaus", data)
	if len(articles) != 2 {
		t.Fatalf("got %d articles, want 2 (grouped by tag)", len(articles))
	}

	var emotetFound bool
	for _, a := range articles {
		if strings.Contains(a.Title, "emotet") {
			emotetFound = true
			if !strings.Contains(a.Title, "2") {
				t.Errorf("emotet article should mention 2 URLs: %q", a.Title)
			}
		}
	}
	if !emotetFound {
		t.Error("expected emotet article")
	}
}

func TestTryURLhausEmpty(t *testing.T) {
	articles := tryURLhaus("URLhaus", []byte(`{"query_status": "no_results", "urls": []}`))
	if len(articles) != 0 {
		t.Errorf("expected 0 articles for empty response, got %d", len(articles))
	}
}

func TestTryFeodoTracker(t *testing.T) {
	data := []byte(`# Feodo Tracker CSV
# first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
2026-03-08 10:00:00,185.220.101.42,443,online,2026-03-08,TrickBot
2026-03-08 09:00:00,45.33.32.156,8080,offline,2026-03-07,TrickBot
2026-03-08 11:00:00,1.2.3.4,443,online,2026-03-08,Dridex
`)

	articles := tryFeodoTracker("Feodo", data)
	if len(articles) != 2 {
		t.Fatalf("got %d articles, want 2 (grouped by malware)", len(articles))
	}

	var trickbotFound bool
	for _, a := range articles {
		if strings.Contains(a.Title, "TrickBot") {
			trickbotFound = true
			if !strings.Contains(a.Description, "185.220.101.42") {
				t.Errorf("should contain IP in description: %q", a.Description)
			}
		}
	}
	if !trickbotFound {
		t.Error("expected TrickBot article")
	}
}

func TestTryFeodoTrackerEmpty(t *testing.T) {
	data := []byte("# Only comments\n# nothing here\n")
	articles := tryFeodoTracker("Feodo", data)
	if len(articles) != 0 {
		t.Errorf("expected 0 articles, got %d", len(articles))
	}
}

func TestTryRansomwatch(t *testing.T) {
	data := []byte(`[
		{"victim": "Acme Corp", "group_name": "lockbit", "discovered": "2026-03-08 10:00:00.000000", "country": "SE", "website": "acme.se"},
		{"victim": "FooCorp", "group_name": "alphv", "discovered": "2026-03-07", "country": "US", "website": "foo.com"}
	]`)

	articles := tryRansomwatch("Ransomwatch", data)
	if len(articles) != 2 {
		t.Fatalf("got %d articles, want 2", len(articles))
	}

	if !strings.Contains(articles[0].Title, "lockbit") {
		t.Errorf("first article title = %q, want lockbit mention", articles[0].Title)
	}
	if !strings.Contains(articles[0].Title, "Acme Corp") {
		t.Errorf("first article title = %q, want Acme Corp mention", articles[0].Title)
	}
}

func TestTryRansomwatchEmpty(t *testing.T) {
	articles := tryRansomwatch("Ransomwatch", []byte(`[]`))
	if len(articles) != 0 {
		t.Errorf("expected 0 articles, got %d", len(articles))
	}
}

func TestAppendUnique(t *testing.T) {
	s := appendUnique(nil, "a")
	s = appendUnique(s, "b")
	s = appendUnique(s, "a")
	if len(s) != 2 {
		t.Errorf("got %v, want [a b]", s)
	}
}

func TestTryHIBPBreaches(t *testing.T) {
	now := time.Now()
	added := now.AddDate(0, 0, -7).Format("2006-01-02T15:04:05Z")
	old := now.AddDate(0, -6, 0).Format("2006-01-02T15:04:05Z")

	data := []byte(`[
		{"Name":"TestBreach","Title":"Test Corp","Domain":"test.com","BreachDate":"2026-03-01","PwnCount":1500000,"Description":"Test breach","DataClasses":["Email addresses","Passwords"],"IsVerified":true,"AddedDate":"` + added + `"},
		{"Name":"OldBreach","Title":"Old Corp","Domain":"old.com","BreachDate":"2025-01-01","PwnCount":100,"Description":"Old","DataClasses":["Emails"],"IsVerified":true,"AddedDate":"` + old + `"}
	]`)

	articles := tryHIBPBreaches("HIBP", data)
	if len(articles) != 1 {
		t.Fatalf("got %d articles, want 1 (old breach should be filtered)", len(articles))
	}
	if !strings.Contains(articles[0].Title, "Test Corp") {
		t.Errorf("title = %q", articles[0].Title)
	}
	if !strings.Contains(articles[0].Title, "1.5M") {
		t.Errorf("should format count as 1.5M: %q", articles[0].Title)
	}
}

func TestTryHIBPBreachesEmpty(t *testing.T) {
	articles := tryHIBPBreaches("HIBP", []byte(`[]`))
	if len(articles) != 0 {
		t.Errorf("expected 0, got %d", len(articles))
	}
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{500, "500"},
		{1500, "2k"},
		{1500000, "1.5M"},
		{2000000000, "2.0Md"},
	}
	for _, tt := range tests {
		got := formatCount(tt.n)
		if got != tt.want {
			t.Errorf("formatCount(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestTryMISPManifest(t *testing.T) {
	recent := time.Now().AddDate(0, 0, -3).Format("2006-01-02")
	old := time.Now().AddDate(0, -2, 0).Format("2006-01-02")

	data := []byte(`{
		"uuid-recent-1": {"info": "APT28 targets Nordic energy sector", "date": "` + recent + `", "threat_level_id": "1", "timestamp": "1709900000"},
		"uuid-recent-2": {"info": "Emotet resurgence campaign", "date": "` + recent + `", "threat_level_id": "2", "timestamp": "1709800000"},
		"uuid-old": {"info": "Old event", "date": "` + old + `", "threat_level_id": "3", "timestamp": "1700000000"}
	}`)

	articles := tryMISPManifest("MISP", data, "https://www.circl.lu/doc/misp/feed-osint/manifest.json")
	if len(articles) != 2 {
		t.Fatalf("got %d articles, want 2 (old event should be filtered)", len(articles))
	}

	// Check link format
	for _, a := range articles {
		if !strings.HasPrefix(a.Link, "https://www.circl.lu/doc/misp/feed-osint/uuid-recent") {
			t.Errorf("unexpected link: %q", a.Link)
		}
	}
}

func TestTryMISPManifestEmpty(t *testing.T) {
	articles := tryMISPManifest("MISP", []byte(`{}`), "https://example.com/manifest.json")
	if len(articles) != 0 {
		t.Errorf("expected 0, got %d", len(articles))
	}
}
