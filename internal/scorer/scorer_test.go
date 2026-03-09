package scorer

import (
	"math"
	"testing"

	"news/internal/feed"
)

func TestComputeScore(t *testing.T) {
	tests := []struct {
		name     string
		severity float64
		verified bool
		scope    int
		novelty  int
		want     float64
	}{
		{"zero severity", 0, false, 1, 1, 1.0}, // clamped to 1
		{"max severity unverified", 10, false, 5, 3, 8.8},
		{"max everything", 10, true, 5, 3, 9.3},
		{"mid range verified", 5, true, 3, 2, 5.2},
		{"mid range unverified", 5, false, 3, 2, 4.7},
		{"low severity high scope", 2, false, 5, 3, 3.6},
		{"high severity low scope", 8, true, 1, 1, 6.3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeScore(tt.severity, tt.verified, tt.scope, tt.novelty)
			if math.Abs(got-tt.want) > 0.01 {
				t.Errorf("computeScore(%v, %v, %v, %v) = %v, want %v",
					tt.severity, tt.verified, tt.scope, tt.novelty, got, tt.want)
			}
		})
	}
}

func TestComputeScoreClamping(t *testing.T) {
	// Verify score never exceeds bounds
	lo := computeScore(0, false, 0, 0)
	if lo < 1.0 {
		t.Errorf("score below 1: %v", lo)
	}
	hi := computeScore(10, true, 5, 3)
	if hi > 10.0 {
		t.Errorf("score above 10: %v", hi)
	}
}

func TestNormalizeThreatActor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Empty/junk
		{"", ""},
		{"  ", ""},
		{"unknown", ""},
		{"okänd", ""},
		{"n/a", ""},
		{"Iran", ""},      // country, not actor
		{"Ryssland", ""},  // country
		{"AsyncRAT", ""},  // malware, not actor

		// Alias resolution
		{"apt28", "APT28"},
		{"APT28", "APT28"},
		{"fancy bear", "APT28"},
		{"Fancy Bear", "APT28"},
		{"lockbit", "LockBit"},
		{"LOCKBIT", "LockBit"},
		{"lockbit3", "LockBit"},
		{"cl0p", "cl0p"}, // no alias entry, passes through as-is

		// Pass-through for unknown actors
		{"SomeNewGroup", "SomeNewGroup"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeThreatActor(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeThreatActor(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeActivity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Ransomware", "Ransomware"},
		{"ransomware", "Ransomware"},
		{"DDoS", "DDoS"},
		{"ddos", "DDoS"},
		{"phishing", "Phishing"},
		{"sårbarhet", "Sårbarhet"},
		{"dataläcka", "Dataläcka"},
		{"invalid_type", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeActivity(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeActivity(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeCountry(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Sweden", "Sverige"},
		{"sweden", "Sverige"},
		{"Sverige", "Sverige"},
		{"United States", "USA"},
		{"Germany", "Tyskland"},
		{"", "Globalt"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeCountry(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeCountry(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeRegion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Norden", "Norden"},
		{"norden", "Norden"},
		{"Europa", "Europa"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeRegion(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeRegion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestApplyTriageResult(t *testing.T) {
	a := ScoredArticle{}
	r := triageResult{
		Severity:     7.5,
		Verified:     true,
		Scope:        3,
		Novelty:      2,
		ActivityType: "ransomware",
		Summary:      "Test summary",
	}

	applyTriageResult(&a, r)

	if a.Severity != 7.5 {
		t.Errorf("severity = %v, want 7.5", a.Severity)
	}
	if !a.Verified {
		t.Error("verified should be true")
	}
	if a.ActivityType != "Ransomware" {
		t.Errorf("activity_type = %q, want Ransomware", a.ActivityType)
	}
	if a.Summary != "Test summary" {
		t.Errorf("summary = %q, want 'Test summary'", a.Summary)
	}
	if a.Score == 0 {
		t.Error("score should be computed, got 0")
	}
}

func TestExtractIOCsIPv4(t *testing.T) {
	a := feed.Article{Description: "C2 server at 185.220.101.42 and 8.8.8.8 observed"}
	iocs := extractIOCs(a)

	ips := filterIOCType(iocs, "ipv4")
	if len(ips) != 2 {
		t.Fatalf("got %d ipv4 IOCs, want 2: %v", len(ips), ips)
	}
	if ips[0].Value != "185.220.101.42" {
		t.Errorf("first ip = %q", ips[0].Value)
	}
}

func TestExtractIOCsFilterRFC1918(t *testing.T) {
	a := feed.Article{Description: "Internal 192.168.1.1 and 10.0.0.1 and 127.0.0.1 should be ignored, but 45.33.32.156 is external"}
	iocs := extractIOCs(a)

	ips := filterIOCType(iocs, "ipv4")
	if len(ips) != 1 {
		t.Fatalf("got %d ipv4 IOCs, want 1: %v", len(ips), ips)
	}
	if ips[0].Value != "45.33.32.156" {
		t.Errorf("ip = %q, want 45.33.32.156", ips[0].Value)
	}
}

func TestExtractIOCsInvalidIPv4(t *testing.T) {
	a := feed.Article{Description: "Not an IP: 999.999.999.999"}
	iocs := extractIOCs(a)
	ips := filterIOCType(iocs, "ipv4")
	if len(ips) != 0 {
		t.Errorf("got %d ipv4 IOCs for invalid IP, want 0: %v", len(ips), ips)
	}
}

func TestExtractIOCsHashes(t *testing.T) {
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	a := feed.Article{Description: md5 + " and " + sha1 + " and " + sha256}
	iocs := extractIOCs(a)

	md5s := filterIOCType(iocs, "md5")
	sha1s := filterIOCType(iocs, "sha1")
	sha256s := filterIOCType(iocs, "sha256")

	if len(sha256s) != 1 || sha256s[0].Value != sha256 {
		t.Errorf("sha256: got %v", sha256s)
	}
	if len(sha1s) != 1 || sha1s[0].Value != sha1 {
		t.Errorf("sha1: got %v", sha1s)
	}
	if len(md5s) != 1 || md5s[0].Value != md5 {
		t.Errorf("md5: got %v", md5s)
	}
}

func TestExtractIOCsHashNoSubstring(t *testing.T) {
	// A SHA256 should not also produce SHA1 and MD5 false positives
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	a := feed.Article{Description: "Hash: " + sha256}
	iocs := extractIOCs(a)

	if len(filterIOCType(iocs, "md5")) != 0 {
		t.Error("SHA256 should not produce MD5 false positive")
	}
	if len(filterIOCType(iocs, "sha1")) != 0 {
		t.Error("SHA256 should not produce SHA1 false positive")
	}
}

func TestExtractIOCsDomains(t *testing.T) {
	a := feed.Article{Description: "Malware phones home to evil-c2.xyz and dropper.top"}
	iocs := extractIOCs(a)

	domains := filterIOCType(iocs, "domain")
	if len(domains) != 2 {
		t.Fatalf("got %d domain IOCs, want 2: %v", len(domains), domains)
	}
}

func TestExtractIOCsBenignDomains(t *testing.T) {
	a := feed.Article{Description: "Legitimate traffic to google.ru should be filtered"}
	iocs := extractIOCs(a)
	domains := filterIOCType(iocs, "domain")
	if len(domains) != 0 {
		t.Errorf("benign domain should be filtered, got %v", domains)
	}
}

func TestExtractIOCsDedup(t *testing.T) {
	a := feed.Article{
		Title:       "IOC: 185.220.101.42",
		Description: "Server 185.220.101.42 used in attack",
		Content:     "The IP 185.220.101.42 was observed again",
	}
	iocs := extractIOCs(a)
	ips := filterIOCType(iocs, "ipv4")
	if len(ips) != 1 {
		t.Errorf("duplicate IP should be deduped, got %d: %v", len(ips), ips)
	}
}

func TestExtractIOCsEmpty(t *testing.T) {
	a := feed.Article{Description: "No indicators in this article about policy changes"}
	iocs := extractIOCs(a)
	if len(iocs) != 0 {
		t.Errorf("expected no IOCs, got %v", iocs)
	}
}

func TestValidIPv4(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"1.2.3.4", true},
		{"255.255.255.255", true},
		{"0.0.0.0", true},
		{"256.1.1.1", false},
		{"1.2.3", false},
		{"1.2.3.4.5", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := validIPv4(tt.ip); got != tt.want {
			t.Errorf("validIPv4(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestRFC1918(t *testing.T) {
	private := []string{"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.0.1", "127.0.0.1"}
	for _, ip := range private {
		if !rfc1918(ip) {
			t.Errorf("rfc1918(%q) = false, want true", ip)
		}
	}
	public := []string{"8.8.8.8", "185.220.101.42", "1.1.1.1"}
	for _, ip := range public {
		if rfc1918(ip) {
			t.Errorf("rfc1918(%q) = true, want false", ip)
		}
	}
}

// filterIOCType is a test helper to filter IOCs by type.
func filterIOCType(iocs []ExtractedIOC, typ string) []ExtractedIOC {
	var filtered []ExtractedIOC
	for _, ioc := range iocs {
		if ioc.Type == typ {
			filtered = append(filtered, ioc)
		}
	}
	return filtered
}
