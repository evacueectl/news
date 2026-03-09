package feed

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Shared HTTP client with connection pooling.
var sharedClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

// maxResponseSize limits feed response bodies to 10 MB.
const maxResponseSize = 10 << 20

type Article struct {
	Title       string
	Link        string
	Description string
	Content     string // Full article text (from content:encoded, atom content, or fetched)
	Published   time.Time
	Source      string
	ThreatActor string // Pre-set by structured feeds (e.g. DDoSia → NoName057(16))
}

// RSS 2.0
type rssDoc struct {
	Channel struct {
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
}

type rssItem struct {
	Title          string `xml:"title"`
	Link           string `xml:"link"`
	Description    string `xml:"description"`
	ContentEncoded string `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
	PubDate        string `xml:"pubDate"`
	GUID           string `xml:"guid"`
}

// Atom
type atomFeed struct {
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	Title   string     `xml:"title"`
	Links   []atomLink `xml:"link"`
	Summary string     `xml:"summary"`
	Content string     `xml:"content"`
	Updated string     `xml:"updated"`
	ID      string     `xml:"id"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

var htmlRe = regexp.MustCompile(`<[^>]*>`)

func stripHTML(s string) string {
	s = htmlRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

var dateFormats = []string{
	time.RFC1123Z,
	time.RFC1123,
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05-07:00",
	"Mon, 2 Jan 2006 15:04:05 -0700",
	"Mon, 2 Jan 2006 15:04:05 MST",
	"Mon, 2 Jan 2006 15:04:05 MST-0700", // e.g. "GMT+0100"
	"Mon, 2 Jan 06 15:04:05 -0700",       // 2-digit year (RFC822Z)
	"Mon, 2 Jan 06 15:04:05 MST",         // 2-digit year (RFC822)
	"Jan 2, 2006 15:04:05-0700",           // US date with numeric tz
	"Jan 02, 2006 15:04:05-0700",          // US date zero-padded day
	"2006-01-02 15:04:05",
	"02 Jan 2006 15:04:05",
	"2 Jan 2006 15:04:05",
	"Mon, 2 Jan 2006 15:04:05", // RFC 1123 without timezone
	"January 2, 2006",
}

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range dateFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	log.Printf("warning: unparseable date %q, using zero time", s)
	return time.Time{}
}

func fetchOne(name, url string, headers map[string]string) ([]Article, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NewsDigest/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}

	// Try Telegram channel scraping
	if strings.Contains(url, "t.me/s/") {
		articles := tryTelegramChannel(name, body, url)
		if len(articles) > 0 {
			return articles, nil
		}
	}

	// Try JSON feeds (OTX, ThreatFox, ransomware.live, DDoSia), then RSS, then Atom
	if strings.Contains(url, "threatfox.abuse.ch") && strings.Contains(url, "json") {
		articles := tryThreatFoxJSON(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "otx.alienvault.com") {
		articles := fetchOTXPaginated(name, url, body, headers)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "ransomware.live") {
		articles := tryRansomwareLive(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "ransomlook.io") {
		articles := tryRansomLook(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "known_exploited_vulnerabilities") {
		articles := tryCISAKEV(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "urlhaus-api.abuse.ch") {
		articles := tryURLhaus(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "feodotracker.abuse.ch") {
		articles := tryFeodoTracker(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "api.ransomware.live") || strings.Contains(url, "ransomwhat.telemetry.ltd") {
		articles := tryRansomwatch(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "haveibeenpwned.com") {
		articles := tryHIBPBreaches(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.Contains(url, "circl.lu") && strings.Contains(url, "manifest.json") {
		articles := tryMISPManifest(name, body, url)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	if strings.HasSuffix(url, ".json") {
		articles := tryDDoSiaJSON(name, body)
		if len(articles) > 0 {
			return articles, nil
		}
	}
	articles := tryRSS(name, body)
	if len(articles) == 0 {
		articles = tryAtom(name, body)
	}
	return articles, nil
}

func tryRSS(source string, data []byte) []Article {
	var doc rssDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil
	}

	var articles []Article
	for _, item := range doc.Channel.Items {
		link := strings.TrimSpace(item.Link)
		if link == "" {
			link = strings.TrimSpace(item.GUID)
		}
		if link == "" {
			continue
		}
		content := stripHTML(item.ContentEncoded)
		articles = append(articles, Article{
			Title:       strings.TrimSpace(item.Title),
			Link:        link,
			Description: stripHTML(item.Description),
			Content:     content,
			Published:   parseDate(item.PubDate),
			Source:      source,
		})
	}
	return articles
}

func tryAtom(source string, data []byte) []Article {
	var doc atomFeed
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil
	}

	var articles []Article
	for _, entry := range doc.Entries {
		link := ""
		for _, l := range entry.Links {
			if l.Rel == "" || l.Rel == "alternate" {
				link = l.Href
				break
			}
		}
		if link == "" && len(entry.Links) > 0 {
			link = entry.Links[0].Href
		}
		if link == "" {
			link = entry.ID
		}
		if link == "" {
			continue
		}

		desc := entry.Summary
		content := ""
		if desc == "" {
			// No summary — use content for both (avoids redundant URL fetch)
			desc = entry.Content
			if entry.Content != "" {
				content = stripHTML(entry.Content)
			}
		} else if entry.Content != "" {
			// Both exist — store full content separately
			content = stripHTML(entry.Content)
		}

		articles = append(articles, Article{
			Title:       strings.TrimSpace(entry.Title),
			Link:        strings.TrimSpace(link),
			Description: stripHTML(desc),
			Content:     content,
			Published:   parseDate(entry.Updated),
			Source:      source,
		})
	}
	return articles
}

// ransomware.live recent victims JSON format (supports both v1 and v2 fields)
type ransomVictim struct {
	PostTitle   string `json:"post_title"` // v1
	GroupName   string `json:"group_name"` // v1
	Victim      string `json:"victim"`     // v2
	Group       string `json:"group"`      // v2
	Discovered  string `json:"discovered"`
	Published   string `json:"published"`
	Country     string `json:"country"`
	Activity    string `json:"activity"`
	Website     string `json:"website"`
	Domain      string `json:"domain"`      // v2
	Description string `json:"description"`
}

// countryName maps ISO 2-letter codes to Swedish country names.
var countryName = map[string]string{
	"US": "USA", "GB": "Storbritannien", "DE": "Tyskland", "FR": "Frankrike",
	"SE": "Sverige", "NO": "Norge", "DK": "Danmark", "FI": "Finland",
	"NL": "Nederländerna", "BE": "Belgien", "IT": "Italien", "ES": "Spanien",
	"CA": "Kanada", "AU": "Australien", "JP": "Japan", "KR": "Sydkorea",
	"CN": "Kina", "IN": "Indien", "BR": "Brasilien", "MX": "Mexiko",
	"TH": "Thailand", "TW": "Taiwan", "IL": "Israel", "AE": "Förenade Arabemiraten",
	"SA": "Saudiarabien", "TR": "Turkiet", "PL": "Polen", "AT": "Österrike",
	"CH": "Schweiz", "PT": "Portugal", "CZ": "Tjeckien", "RO": "Rumänien",
	"CO": "Colombia", "AR": "Argentina", "CL": "Chile", "ZA": "Sydafrika",
	"NG": "Nigeria", "KE": "Kenya", "PH": "Filippinerna", "MY": "Malaysia",
	"SG": "Singapore", "ID": "Indonesien", "VN": "Vietnam", "UA": "Ukraina",
	"PK": "Pakistan", "BD": "Bangladesh", "EG": "Egypten", "KW": "Kuwait",
	"IE": "Irland", "GR": "Grekland", "HU": "Ungern", "BG": "Bulgarien",
	"HR": "Kroatien", "SK": "Slovakien", "LT": "Litauen", "LV": "Lettland",
	"EE": "Estland", "IS": "Island", "LU": "Luxemburg",
}

func tryRansomwareLive(source string, data []byte) []Article {
	var victims []ransomVictim
	if err := json.Unmarshal(data, &victims); err != nil {
		return nil
	}
	if len(victims) == 0 {
		return nil
	}
	// Check at least one has valid group (v1 or v2 field)
	hasGroup := false
	for _, v := range victims {
		if v.GroupName != "" || v.Group != "" {
			hasGroup = true
			break
		}
	}
	if !hasGroup {
		return nil
	}

	// Aggregate per group
	type groupData struct {
		Victims   []string
		Countries map[string]int
		Sectors   map[string]int
		Latest    time.Time
	}
	groups := make(map[string]*groupData)
	var groupOrder []string

	for _, v := range victims {
		// Support both v1 and v2 field names
		title := v.PostTitle
		if title == "" {
			title = v.Victim
		}
		groupName := v.GroupName
		if groupName == "" {
			groupName = v.Group
		}
		if title == "" || groupName == "" {
			continue
		}
		v.PostTitle = title
		v.GroupName = groupName
		t := parseRansomDate(v.Discovered)
		if t.IsZero() {
			t = parseRansomDate(v.Published)
		}
		if t.IsZero() {
			continue
		}

		g, ok := groups[v.GroupName]
		if !ok {
			g = &groupData{Countries: map[string]int{}, Sectors: map[string]int{}}
			groups[v.GroupName] = g
			groupOrder = append(groupOrder, v.GroupName)
		}
		g.Victims = append(g.Victims, v.PostTitle)
		if t.After(g.Latest) {
			g.Latest = t
		}
		if v.Country != "" {
			name := v.Country
			if full, ok := countryName[v.Country]; ok {
				name = full
			}
			g.Countries[name]++
		}
		if v.Activity != "" && v.Activity != "Not Found" {
			g.Sectors[v.Activity]++
		}
	}

	var articles []Article
	for _, gn := range groupOrder {
		g := groups[gn]
		group := strings.ReplaceAll(gn, "_", " ")
		// Capitalize first letter
		if len(group) > 0 {
			group = strings.ToUpper(group[:1]) + group[1:]
		}

		// Build country summary (top 3)
		type kv struct{ k string; v int }
		var cs []kv
		for k, v := range g.Countries {
			cs = append(cs, kv{k, v})
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].v > cs[j].v })
		var countryParts []string
		for i, c := range cs {
			if i >= 3 {
				countryParts = append(countryParts, fmt.Sprintf("+%d andra", len(cs)-3))
				break
			}
			countryParts = append(countryParts, fmt.Sprintf("%s (%d)", c.k, c.v))
		}

		// Build sector summary (top 3)
		var ss []kv
		for k, v := range g.Sectors {
			ss = append(ss, kv{k, v})
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i].v > ss[j].v })
		var sectorParts []string
		for i, s := range ss {
			if i >= 3 {
				break
			}
			sectorParts = append(sectorParts, s.k)
		}

		desc := fmt.Sprintf("Ransomware-gruppen %s har publicerat %d nya offer.", group, len(g.Victims))
		if len(countryParts) > 0 {
			desc += fmt.Sprintf(" Drabbade länder: %s.", strings.Join(countryParts, ", "))
		}
		if len(sectorParts) > 0 {
			desc += fmt.Sprintf(" Sektorer: %s.", strings.Join(sectorParts, ", "))
		}
		// List first few victims
		names := g.Victims
		if len(names) > 5 {
			names = append(names[:5], fmt.Sprintf("(+%d till)", len(g.Victims)-5))
		}
		desc += fmt.Sprintf(" Offer: %s.", strings.Join(names, ", "))

		articles = append(articles, Article{
			Title:       fmt.Sprintf("%s: %d nya ransomware-offer", group, len(g.Victims)),
			Link:        fmt.Sprintf("https://www.ransomware.live/group/%s", gn),
			Description: desc,
			Published:   g.Latest,
			Source:      source,
		})
	}
	return articles
}

func parseRansomDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	// "2026-02-24 14:00:49.630908"
	for _, layout := range []string{
		"2006-01-02 15:04:05.000000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// DDoSia target list JSON format
type ddosiaTarget struct {
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Type   string `json:"type"`
	Method string `json:"method"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
}

func tryDDoSiaJSON(source string, data []byte) []Article {
	return parseDDoSiaTargets(source, data, time.Now(),
		fmt.Sprintf("https://witha.name/data/last.json#%s", time.Now().Format("2006-01-02")))
}

// parseDDoSiaTargets parses DDoSia target list JSON and creates a single aggregated article.
func parseDDoSiaTargets(source string, data []byte, published time.Time, link string) []Article {
	// Try parsing as {"targets": [...]} or bare [...]
	var targets []ddosiaTarget
	var wrapper struct {
		Targets []ddosiaTarget `json:"targets"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Targets) > 0 {
		targets = wrapper.Targets
	} else if err := json.Unmarshal(data, &targets); err != nil {
		return nil
	}
	if len(targets) == 0 || targets[0].Host == "" {
		return nil
	}

	// Group by host
	type hostInfo struct {
		IPs       map[string]bool
		Methods   map[string]bool
		Endpoints int
	}
	hosts := make(map[string]*hostInfo)
	var hostOrder []string
	for _, t := range targets {
		h := t.Host
		if h == "" {
			continue
		}
		info, ok := hosts[h]
		if !ok {
			info = &hostInfo{IPs: map[string]bool{}, Methods: map[string]bool{}}
			hosts[h] = info
			hostOrder = append(hostOrder, h)
		}
		if t.IP != "" {
			info.IPs[t.IP] = true
		}
		info.Methods[strings.ToUpper(t.Method)] = true
		info.Endpoints++
	}

	// Aggregate all targets into one article
	totalEndpoints := 0
	allMethods := map[string]bool{}
	for _, info := range hosts {
		totalEndpoints += info.Endpoints
		for m := range info.Methods {
			allMethods[m] = true
		}
	}
	methods := make([]string, 0, len(allMethods))
	for m := range allMethods {
		methods = append(methods, m)
	}
	sort.Strings(methods)

	// List targets (first 5, then count)
	targetList := make([]string, len(hostOrder))
	copy(targetList, hostOrder)
	if len(targetList) > 5 {
		targetList = append(hostOrder[:5:5], fmt.Sprintf("(+%d till)", len(hostOrder)-5))
	}

	desc := fmt.Sprintf("NoName057(16) riktar DDoS-attacker mot %d mål med totalt %d endpoints via %s. Mål: %s.",
		len(hostOrder), totalEndpoints, strings.Join(methods, ", "), strings.Join(targetList, ", "))

	return []Article{{
		Title:       fmt.Sprintf("NoName057(16) DDoS-kampanj: %d aktiva mål", len(hostOrder)),
		Link:        link,
		Description: desc,
		Published:   published,
		Source:      source,
		ThreatActor: "NoName057(16)",
	}}
}

// ddosiaFileRe matches DDoSia target list filenames in the witha.name/data/ directory listing.
var ddosiaFileRe = regexp.MustCompile(`(\d{4}-\d{2}-\d{2})_\d{2}-\d{2}-\d{2}_DDoSia-target-list-full\.json`)

// FetchDDoSiaHistory fetches historical DDoSia target list snapshots from witha.name/data/.
// It picks one snapshot per day within the given window and creates one article per day.
func FetchDDoSiaHistory(windowDays int) ([]Article, error) {
	const baseURL = "https://witha.name/data/"

	// Fetch directory listing
	req, err := http.NewRequest("GET", baseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NewsDigest/1.0")
	resp, err := sharedClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ddosia history: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ddosia history: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("ddosia history: %w", err)
	}

	// Parse directory listing for DDoSia files within window
	cutoff := time.Now().AddDate(0, 0, -windowDays)
	perDay := make(map[string]string) // date -> filename (keep latest per day)
	for _, m := range ddosiaFileRe.FindAllStringSubmatch(string(body), -1) {
		filename := m[0]
		dateStr := m[1]
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil || t.Before(cutoff) {
			continue
		}
		// Keep latest snapshot per day (filenames sort chronologically)
		if existing, ok := perDay[dateStr]; !ok || filename > existing {
			perDay[dateStr] = filename
		}
	}

	if len(perDay) == 0 {
		return nil, nil
	}

	// Fetch snapshots concurrently
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []Article
	)
	sem := make(chan struct{}, 5) // limit concurrent fetches

	for dateStr, filename := range perDay {
		wg.Add(1)
		go func(dateStr, filename string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			url := baseURL + filename
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Printf("warning: ddosia %s: %v", dateStr, err)
				return
			}
			req.Header.Set("User-Agent", "NewsDigest/1.0")
			resp, err := sharedClient.Do(req)
			if err != nil {
				log.Printf("warning: ddosia %s: %v", dateStr, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				log.Printf("warning: ddosia %s: HTTP %d", dateStr, resp.StatusCode)
				return
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
			if err != nil {
				log.Printf("warning: ddosia %s: %v", dateStr, err)
				return
			}

			t, _ := time.Parse("2006-01-02", dateStr)
			// Use same link format as last.json for dedup compatibility
			link := fmt.Sprintf("https://witha.name/data/last.json#%s", dateStr)
			arts := parseDDoSiaTargets("DDoSia Targets", data, t, link)
			if len(arts) > 0 {
				mu.Lock()
				results = append(results, arts...)
				mu.Unlock()
			}
		}(dateStr, filename)
	}
	wg.Wait()

	log.Printf("ddosia history: %d snapshots fetched from %d available", len(results), len(perDay))
	return results, nil
}

// Telegram channel preview page parser.
// Scrapes t.me/s/<channel> for recent messages and creates articles.
var (
	tgMsgTextRe = regexp.MustCompile(`(?s)tgme_widget_message_text[^>]*>(.*?)</div>`)
	tgDateRe    = regexp.MustCompile(`<time[^>]*datetime="([^"]+)"`)
	tgPostRe    = regexp.MustCompile(`data-post="([^"]+)"`)
	tgTitleRe   = regexp.MustCompile(`(?s)tgme_channel_info_header_title[^>]*>(.*?)</div>`)
)

// Domains to exclude from target extraction (tools, social media, news, etc.)
var tgExcludeDomains = map[string]bool{
	"t.me": true, "telegram.org": true, "telegram.me": true,
	"twitter.com": true, "x.com": true, "youtube.com": true, "youtu.be": true,
	"instagram.com": true, "facebook.com": true, "tiktok.com": true,
	"github.com": true, "google.com": true, "wikipedia.org": true,
	"check-host.net": true, "check-host.info": true, "host-tracker.com": true,
	"medium.com": true, "reddit.com": true, "linkedin.com": true,
}

// Known DDoS actor names — used for attribution when a channel mentions another group.
var ddosActorPatterns = map[string]string{
	"server killers":     "Server Killers",
	"server_killers":     "Server Killers",
	"inteid":             "Inteid",
	"noname057":          "NoName057(16)",
	"noname05716":        "NoName057(16)",
	"killnet":            "KillNet",
	"dark storm":         "Dark Storm Team",
	"darkstorm":          "Dark Storm Team",
	"dienet":             "DieNet",
	"die net":            "DieNet",
	"usersec":            "UserSec",
	"keymous":            "Keymous+",
	"cyber army of russia": "Cyber Army of Russia Reborn",
	"it army":            "IT Army",
	"z-pentest":          "Z-Pentest Alliance",
	"рубеж":              "РУБЕЖ",
	"coup team":          "Coup Team",
	"holy league":        "Holy League",
	"anonymous sudan":    "Anonymous Sudan",
	"rippersec":          "RipperSec",
	"mr hamza":           "Mr Hamza",
	"cybervolk":          "CyberVolk",
	"wolf cyber":         "Wolf Cyber Army",
	"overflame":          "OverFlame",
	"thunder cyber":      "THUNDER CYBER",
	"crew russia":        "CREW RUSSIA",
	"revolusi hime666":   "REVOLUSI HIME666",
	"we are killnet":     "WE ARE KILLNET",
	"dcg":                "DCG",
	"furqan alliance":    "Furqan Alliance",
	"al furqan":          "Furqan Alliance",
	"tunisian maskers":   "Tunisian Maskers",
	"avangardsec":        "AvangardSec",
	"rubiconh4ck":        "RubiconH4CK",
	"floodhacking":       "FloodHacking",
}

var tgDomainRe = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9][-a-z0-9]*\.[a-z0-9][-a-z0-9.]*\.[a-z]{2,})`)

func tryTelegramChannel(source string, data []byte, url string) []Article {
	html := string(data)

	// Extract channel title
	channelTitle := source
	if m := tgTitleRe.FindStringSubmatch(html); len(m) > 1 {
		t := stripHTML(m[1])
		if t != "" {
			channelTitle = t
		}
	}

	texts := tgMsgTextRe.FindAllStringSubmatch(html, -1)
	dates := tgDateRe.FindAllStringSubmatch(html, -1)
	posts := tgPostRe.FindAllStringSubmatch(html, -1)
	if len(texts) == 0 {
		return nil
	}

	type tgMsg struct {
		Text string
		Time time.Time
		Link string
	}
	var msgs []tgMsg
	for i, m := range texts {
		text := stripHTML(m[1])
		if len(text) < 10 {
			continue
		}
		var t time.Time
		if i < len(dates) {
			t, _ = time.Parse(time.RFC3339, dates[i][1])
			if t.IsZero() {
				t, _ = time.Parse("2006-01-02T15:04:05+00:00", dates[i][1])
			}
		}
		if t.IsZero() {
			continue
		}
		link := url
		if i < len(posts) {
			link = fmt.Sprintf("https://t.me/%s", posts[i][1])
		}
		msgs = append(msgs, tgMsg{Text: text, Time: t, Link: link})
	}
	if len(msgs) == 0 {
		return nil
	}

	// Find latest and extract targets
	var latest time.Time
	targets := make(map[string]bool)
	mentionedActors := make(map[string]bool)

	for _, m := range msgs {
		if m.Time.After(latest) {
			latest = m.Time
		}
		// Extract domains
		for _, d := range tgDomainRe.FindAllStringSubmatch(m.Text, -1) {
			host := strings.ToLower(d[1])
			root := host
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				root = parts[len(parts)-2] + "." + parts[len(parts)-1]
			}
			if tgExcludeDomains[root] || tgExcludeDomains[host] {
				continue
			}
			targets[host] = true
		}
		// Check for mentioned actor names
		textLower := strings.ToLower(m.Text)
		for pattern, name := range ddosActorPatterns {
			if strings.Contains(textLower, pattern) {
				mentionedActors[name] = true
			}
		}
	}

	// Build description
	var desc strings.Builder
	desc.WriteString(fmt.Sprintf("%s: %d meddelanden.", channelTitle, len(msgs)))

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
		if len(tlist) > 8 {
			tlist = append(tlist[:8], fmt.Sprintf("(+%d till)", len(tlist)-8))
		}
		desc.WriteString(fmt.Sprintf(" Mål: %s.", strings.Join(tlist, ", ")))
	}

	// Add latest message snippets
	for i := len(msgs) - 1; i >= 0 && i >= len(msgs)-2; i-- {
		snippet := msgs[i].Text
		if len(snippet) > 150 {
			snippet = snippet[:150] + "..."
		}
		desc.WriteString(fmt.Sprintf(" [%s] %s", msgs[i].Time.Format("2 Jan"), snippet))
	}

	// Use time.Now() as published time — the article is a live summary
	// of channel activity, not a single post with a fixed date.
	// Append today's date to the link so each day gets a fresh summary
	// instead of being dedup'd against yesterday's.
	dayLink := fmt.Sprintf("%s#%s", url, time.Now().Format("2006-01-02"))
	return []Article{{
		Title:       fmt.Sprintf("%s: %d inlägg med cyberaktivitet", channelTitle, len(msgs)),
		Link:        dayLink,
		Description: desc.String(),
		Published:   time.Now(),
		Source:      source,
	}}
}

// AlienVault OTX pulse format
type otxSearchResult struct {
	Results []otxPulse `json:"results"`
	Next    string     `json:"next"`
}

type otxPulse struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	Description       string      `json:"description"`
	Created           string      `json:"created"`
	Modified          string      `json:"modified"`
	Tags              []string    `json:"tags"`
	Adversary         string      `json:"adversary"`
	TargetedCountries []string    `json:"targeted_countries"`
	MalwareFamilies   []string    `json:"malware_families"`
	AttackIDs         []otxAttack `json:"attack_ids"`
	Industries        []string    `json:"industries"`
	References        []string    `json:"references"`
	IndicatorCount    int         `json:"indicator_count"`
}

type otxAttack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

// fetchOTXPaginated fetches OTX pulses, following pagination up to 5 pages.
func fetchOTXPaginated(source, baseURL string, firstPage []byte, headers map[string]string) []Article {
	articles := tryOTXPulses(source, firstPage)

	// Check for next page
	var result otxSearchResult
	if err := json.Unmarshal(firstPage, &result); err != nil {
		return articles
	}

	nextURL := result.Next
	for page := 2; page <= 5 && nextURL != ""; page++ {
		req, err := http.NewRequest("GET", nextURL, nil)
		if err != nil {
			break
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := sharedClient.Do(req)
		if err != nil {
			break
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			break
		}

		pageArticles := tryOTXPulses(source, body)
		articles = append(articles, pageArticles...)

		var pageResult otxSearchResult
		if err := json.Unmarshal(body, &pageResult); err != nil {
			break
		}
		nextURL = pageResult.Next
	}
	return articles
}

func tryOTXPulses(source string, data []byte) []Article {
	var result otxSearchResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	if len(result.Results) == 0 {
		return nil
	}

	var articles []Article
	for _, p := range result.Results {
		if p.Name == "" {
			continue
		}

		// Build enriched description
		desc := stripHTML(p.Description)
		if len(desc) > 500 {
			desc = desc[:500] + "..."
		}

		var meta []string
		if p.Adversary != "" {
			meta = append(meta, fmt.Sprintf("Hotaktör: %s", p.Adversary))
		}
		if len(p.TargetedCountries) > 0 {
			countries := make([]string, 0, len(p.TargetedCountries))
			for _, c := range p.TargetedCountries {
				if name, ok := countryName[c]; ok {
					countries = append(countries, name)
				} else {
					countries = append(countries, c)
				}
			}
			if len(countries) > 5 {
				countries = append(countries[:5], fmt.Sprintf("+%d", len(p.TargetedCountries)-5))
			}
			meta = append(meta, fmt.Sprintf("Drabbade länder: %s", strings.Join(countries, ", ")))
		}
		if len(p.MalwareFamilies) > 0 {
			families := p.MalwareFamilies
			if len(families) > 5 {
				families = append(families[:5], fmt.Sprintf("+%d", len(p.MalwareFamilies)-5))
			}
			meta = append(meta, fmt.Sprintf("Malware: %s", strings.Join(families, ", ")))
		}
		if len(p.Industries) > 0 {
			meta = append(meta, fmt.Sprintf("Sektorer: %s", strings.Join(p.Industries, ", ")))
		}
		if len(p.AttackIDs) > 0 {
			techniques := make([]string, 0, len(p.AttackIDs))
			for _, a := range p.AttackIDs {
				if len(techniques) >= 3 {
					break
				}
				if a.Name != "" {
					techniques = append(techniques, a.Name)
				}
			}
			if len(techniques) > 0 {
				meta = append(meta, fmt.Sprintf("Tekniker: %s", strings.Join(techniques, ", ")))
			}
		}

		fullDesc := desc
		if len(meta) > 0 {
			fullDesc += " | " + strings.Join(meta, ". ") + "."
		}

		// Parse date (OTX format: "2026-02-10T14:30:00.000000" or "2026-02-10T14:30:00")
		t := parseOTXDate(p.Modified)
		if t.IsZero() {
			t = parseOTXDate(p.Created)
		}
		if t.IsZero() {
			continue
		}

		link := fmt.Sprintf("https://otx.alienvault.com/pulse/%s", p.ID)

		articles = append(articles, Article{
			Title:       p.Name,
			Link:        link,
			Description: fullDesc,
			Published:   t,
			Source:      source,
		})
	}
	return articles
}

func parseOTXDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.000000",
		"2006-01-02T15:04:05",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// ThreatFox IOC export (JSON format: {"id": [{ioc_data}], ...})
type threatFoxIOC struct {
	IOCValue         string `json:"ioc_value"`
	IOCType          string `json:"ioc_type"`
	ThreatType       string `json:"threat_type"`
	MalwarePrintable string `json:"malware_printable"`
	MalwareAlias     *string `json:"malware_alias"`
	FirstSeen        string `json:"first_seen_utc"`
	Tags             string `json:"tags"`
}

func tryThreatFoxJSON(source string, data []byte) []Article {
	var raw map[string][]threatFoxIOC
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if len(raw) == 0 {
		return nil
	}

	// Aggregate per malware family
	type malwareInfo struct {
		IOCs       int
		ThreatType string
		Types      map[string]int
		Latest     time.Time
		Examples   []string
	}
	families := make(map[string]*malwareInfo)
	var familyOrder []string

	for _, items := range raw {
		for _, ioc := range items {
			name := ioc.MalwarePrintable
			if name == "" || name == "Unknown" || name == "Unknown Stealer" {
				continue
			}

			t, _ := time.Parse("2006-01-02 15:04:05", ioc.FirstSeen)
			if t.IsZero() {
				continue
			}

			info, ok := families[name]
			if !ok {
				info = &malwareInfo{Types: map[string]int{}}
				families[name] = info
				familyOrder = append(familyOrder, name)
			}
			info.IOCs++
			info.ThreatType = ioc.ThreatType
			info.Types[ioc.IOCType]++
			if t.After(info.Latest) {
				info.Latest = t
			}
			if len(info.Examples) < 3 {
				info.Examples = append(info.Examples, ioc.IOCValue)
			}
		}
	}

	// Sort by IOC count descending
	sort.Slice(familyOrder, func(i, j int) bool {
		return families[familyOrder[i]].IOCs > families[familyOrder[j]].IOCs
	})

	var articles []Article
	for _, name := range familyOrder {
		info := families[name]
		if info.IOCs < 2 {
			continue // skip single-IOC entries
		}

		// Build threat type description
		threatDesc := "Malware"
		switch info.ThreatType {
		case "botnet_cc":
			threatDesc = "Botnet C2-infrastruktur"
		case "payload_delivery":
			threatDesc = "Malware-distribution"
		case "payload":
			threatDesc = "Skadlig payload"
		}

		// Build IOC type summary
		var typeParts []string
		for t, c := range info.Types {
			typeParts = append(typeParts, fmt.Sprintf("%d %s", c, t))
		}

		desc := fmt.Sprintf("%s: %d nya IOCer rapporterade (%s). Typ: %s.",
			name, info.IOCs, strings.Join(typeParts, ", "), threatDesc)
		if len(info.Examples) > 0 {
			desc += fmt.Sprintf(" Exempel: %s.", strings.Join(info.Examples, ", "))
		}

		articles = append(articles, Article{
			Title:       fmt.Sprintf("%s: %d nya indikatorer upptäckta", name, info.IOCs),
			Link:        fmt.Sprintf("https://threatfox.abuse.ch/browse.php?search=malware%%3A%s", strings.ReplaceAll(name, " ", "+")),
			Description: desc,
			Published:   info.Latest,
			Source:      source,
		})
	}
	return articles
}

// CISA Known Exploited Vulnerabilities catalog
type cisaKEVCatalog struct {
	CatalogVersion string    `json:"catalogVersion"`
	Vulnerabilities []cisaKEV `json:"vulnerabilities"`
}

type cisaKEV struct {
	CVEID         string `json:"cveID"`
	Vendor        string `json:"vendorProject"`
	Product       string `json:"product"`
	Name          string `json:"vulnerabilityName"`
	DateAdded     string `json:"dateAdded"`
	Description   string `json:"shortDescription"`
	Action        string `json:"requiredAction"`
	DueDate       string `json:"dueDate"`
	Ransomware    string `json:"knownRansomwareCampaignUse"`
}

func tryCISAKEV(source string, data []byte) []Article {
	var catalog cisaKEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil
	}
	if len(catalog.Vulnerabilities) == 0 {
		return nil
	}

	// Only recent additions (last 14 days)
	cutoff := time.Now().AddDate(0, 0, -14).Format("2006-01-02")
	var recent []cisaKEV
	for _, v := range catalog.Vulnerabilities {
		if v.DateAdded >= cutoff {
			recent = append(recent, v)
		}
	}
	if len(recent) == 0 {
		return nil
	}

	// Group by date added
	type dayGroup struct {
		Date  string
		Vulns []cisaKEV
	}
	groups := make(map[string]*dayGroup)
	var dates []string
	for _, v := range recent {
		g, ok := groups[v.DateAdded]
		if !ok {
			g = &dayGroup{Date: v.DateAdded}
			groups[v.DateAdded] = g
			dates = append(dates, v.DateAdded)
		}
		g.Vulns = append(g.Vulns, v)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dates)))

	var articles []Article
	for _, date := range dates {
		g := groups[date]
		t, _ := time.Parse("2006-01-02", date)
		if t.IsZero() {
			continue
		}

		var names []string
		ransomCount := 0
		for _, v := range g.Vulns {
			names = append(names, fmt.Sprintf("%s (%s %s)", v.CVEID, v.Vendor, v.Product))
			if v.Ransomware == "Known" {
				ransomCount++
			}
		}

		desc := fmt.Sprintf("CISA har lagt till %d nya aktivt exploaterade sårbarheter: %s.",
			len(g.Vulns), strings.Join(names, "; "))
		if ransomCount > 0 {
			desc += fmt.Sprintf(" %d av dessa används i ransomware-kampanjer.", ransomCount)
		}

		articles = append(articles, Article{
			Title:       fmt.Sprintf("CISA KEV: %d nya aktivt exploaterade sårbarheter (%s)", len(g.Vulns), date),
			Link:        fmt.Sprintf("https://www.cisa.gov/known-exploited-vulnerabilities-catalog#%s", date),
			Description: desc,
			Published:   t,
			Source:      source,
		})
	}
	return articles
}

// RansomLook recent victims API
type ransomLookVictim struct {
	PostTitle   string `json:"post_title"`
	GroupName   string `json:"group_name"`
	Discovered  string `json:"discovered"`
	Description string `json:"description"`
}

func tryRansomLook(source string, data []byte) []Article {
	var victims []ransomLookVictim
	if err := json.Unmarshal(data, &victims); err != nil {
		return nil
	}
	if len(victims) == 0 || victims[0].GroupName == "" {
		return nil
	}

	// Aggregate per group (same pattern as ransomware.live)
	type groupData struct {
		Victims []string
		Latest  time.Time
	}
	groups := make(map[string]*groupData)
	var groupOrder []string

	for _, v := range victims {
		if v.PostTitle == "" || v.GroupName == "" {
			continue
		}
		t := parseRansomDate(v.Discovered)
		if t.IsZero() {
			continue
		}

		g, ok := groups[v.GroupName]
		if !ok {
			g = &groupData{}
			groups[v.GroupName] = g
			groupOrder = append(groupOrder, v.GroupName)
		}
		g.Victims = append(g.Victims, v.PostTitle)
		if t.After(g.Latest) {
			g.Latest = t
		}
	}

	var articles []Article
	for _, gn := range groupOrder {
		g := groups[gn]
		group := strings.ReplaceAll(gn, "_", " ")
		if len(group) > 0 {
			group = strings.ToUpper(group[:1]) + group[1:]
		}

		names := g.Victims
		if len(names) > 5 {
			names = append(names[:5], fmt.Sprintf("(+%d till)", len(g.Victims)-5))
		}
		desc := fmt.Sprintf("Ransomware-gruppen %s har publicerat %d nya offer. Offer: %s.",
			group, len(g.Victims), strings.Join(names, ", "))

		articles = append(articles, Article{
			Title:       fmt.Sprintf("%s: %d nya ransomware-offer (RansomLook)", group, len(g.Victims)),
			Link:        fmt.Sprintf("https://www.ransomlook.io/group/%s", gn),
			Description: desc,
			Published:   g.Latest,
			Source:      source,
		})
	}
	return articles
}

// Cloudflare Radar DDoS overview — fetches top target/source countries
func FetchCloudflareRadar(apiKey string) []Article {
	if apiKey == "" {
		return nil
	}

	type cfTopEntry struct {
		TargetName   string `json:"targetCountryName"`
		TargetAlpha2 string `json:"targetCountryAlpha2"`
		OriginName   string `json:"originCountryName"`
		OriginAlpha2 string `json:"originCountryAlpha2"`
		Value        string `json:"value"`
	}
	type cfResponse struct {
		Success bool `json:"success"`
		Result  struct {
			Top0 []cfTopEntry `json:"top_0"`
		} `json:"result"`
	}

	fetchTop := func(endpoint string) []cfTopEntry {
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := sharedClient.Do(req)
		if err != nil {
			log.Printf("warning: cloudflare radar: %v", err)
			return nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Printf("warning: cloudflare radar: HTTP %d", resp.StatusCode)
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if err != nil {
			log.Printf("warning: cloudflare radar read: %v", err)
			return nil
		}
		var r cfResponse
		if err := json.Unmarshal(body, &r); err != nil || !r.Success {
			return nil
		}
		return r.Result.Top0
	}

	targets := fetchTop("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target?dateRange=1d&limit=15")
	sources := fetchTop("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin?dateRange=1d&limit=10")

	if len(targets) == 0 {
		return nil
	}

	// Build target summary
	var targetParts []string
	nordicHit := false
	nordicCountries := map[string]bool{"SE": true, "NO": true, "DK": true, "FI": true, "IS": true}
	for _, t := range targets {
		alpha2 := t.TargetAlpha2
		name := t.TargetName
		if full, ok := countryName[alpha2]; ok {
			name = full
		}
		if name == "" {
			name = alpha2
		}
		targetParts = append(targetParts, fmt.Sprintf("%s (%.1f%%)", name, parseFloat(t.Value)))
		if nordicCountries[alpha2] {
			nordicHit = true
		}
	}

	var sourceParts []string
	for _, s := range sources {
		alpha2 := s.OriginAlpha2
		name := s.OriginName
		if full, ok := countryName[alpha2]; ok {
			name = full
		}
		if name == "" {
			name = alpha2
		}
		sourceParts = append(sourceParts, fmt.Sprintf("%s (%.1f%%)", name, parseFloat(s.Value)))
	}

	desc := fmt.Sprintf("Cloudflare Radar DDoS-överblick (senaste 24h). Mest attackerade länder: %s.",
		strings.Join(targetParts, ", "))
	if len(sourceParts) > 0 {
		desc += fmt.Sprintf(" Största attackkällor: %s.", strings.Join(sourceParts, ", "))
	}

	topTarget := targets[0].TargetName
	if full, ok := countryName[targets[0].TargetAlpha2]; ok {
		topTarget = full
	}
	title := fmt.Sprintf("DDoS-trender: %s mest attackerat (senaste 24h)", topTarget)
	if nordicHit {
		title = "DDoS-trender: Nordiskt land bland mest attackerade (senaste 24h)"
	}

	return []Article{{
		Title:       title,
		Link:        fmt.Sprintf("https://radar.cloudflare.com/security-and-attacks#%s", time.Now().Format("2006-01-02")),
		Description: desc,
		Published:   time.Now(),
		Source:      "Cloudflare Radar",
	}}
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// --- URLhaus parser ---

type urlhausResponse struct {
	QueryStatus string       `json:"query_status"`
	URLs        []urlhausURL `json:"urls"`
}
type urlhausURL struct {
	URL              string   `json:"url"`
	URLStatus        string   `json:"url_status"`
	Host             string   `json:"host"`
	DateAdded        string   `json:"date_added"`
	Threat           string   `json:"threat"`
	Tags             []string `json:"tags"`
	URLhausReference string   `json:"urlhaus_reference"`
}

func tryURLhaus(source string, data []byte) []Article {
	var resp urlhausResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil
	}
	if resp.QueryStatus != "ok" || len(resp.URLs) == 0 {
		return nil
	}

	// Group by malware tag to avoid one article per URL
	type group struct {
		tag   string
		hosts []string
		urls  []string
		first time.Time
	}
	groups := make(map[string]*group)
	for _, u := range resp.URLs {
		tag := "unknown"
		if len(u.Tags) > 0 {
			tag = u.Tags[0]
		}
		g, ok := groups[tag]
		if !ok {
			g = &group{tag: tag}
			groups[tag] = g
		}
		g.hosts = appendUnique(g.hosts, u.Host)
		g.urls = appendUnique(g.urls, u.URL)
		if t, err := time.Parse("2006-01-02 15:04:05", u.DateAdded); err == nil {
			if g.first.IsZero() || t.Before(g.first) {
				g.first = t
			}
		}
	}

	var articles []Article
	for _, g := range groups {
		if len(g.hosts) == 0 {
			continue
		}
		hostList := g.hosts
		if len(hostList) > 10 {
			hostList = hostList[:10]
		}
		title := fmt.Sprintf("URLhaus: %s — %d skadliga URL:er", g.tag, len(g.urls))
		desc := fmt.Sprintf("Malware-familj: %s. Infrastruktur: %s.", g.tag, strings.Join(hostList, ", "))

		published := g.first
		if published.IsZero() {
			published = time.Now()
		}

		articles = append(articles, Article{
			Title:       title,
			Link:        fmt.Sprintf("https://urlhaus.abuse.ch/browse/tag/%s/#%s", g.tag, published.Format("2006-01-02")),
			Description: desc,
			Published:   published,
			Source:      source,
		})
	}
	return articles
}

// --- Feodo Tracker parser (CSV format) ---

func tryFeodoTracker(source string, data []byte) []Article {
	lines := strings.Split(string(data), "\n")

	type c2Entry struct {
		ip      string
		port    string
		malware string
		seen    time.Time
	}

	// Group by malware family
	groups := make(map[string][]c2Entry)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 6 {
			continue
		}
		firstSeen := strings.TrimSpace(parts[0])
		ip := strings.TrimSpace(parts[1])
		port := strings.TrimSpace(parts[2])
		malware := strings.TrimSpace(parts[5])
		if malware == "" {
			malware = "Unknown"
		}

		t, _ := time.Parse("2006-01-02 15:04:05", firstSeen)
		groups[malware] = append(groups[malware], c2Entry{ip: ip, port: port, malware: malware, seen: t})
	}

	var articles []Article
	for malware, entries := range groups {
		if len(entries) == 0 {
			continue
		}
		var ips []string
		var latest time.Time
		for _, e := range entries {
			ips = appendUnique(ips, e.ip)
			if e.seen.After(latest) {
				latest = e.seen
			}
		}
		ipList := ips
		if len(ipList) > 10 {
			ipList = ipList[:10]
		}
		title := fmt.Sprintf("Feodo Tracker: %s C2 — %d servrar", malware, len(ips))
		desc := fmt.Sprintf("Botnet C2-infrastruktur för %s. IP:er: %s.", malware, strings.Join(ipList, ", "))

		if latest.IsZero() {
			latest = time.Now()
		}

		articles = append(articles, Article{
			Title:       title,
			Link:        fmt.Sprintf("https://feodotracker.abuse.ch/browse/%s/#%s", strings.ToLower(malware), latest.Format("2006-01-02")),
			Description: desc,
			Published:   latest,
			Source:      source,
		})
	}
	return articles
}

// --- Ransomwatch parser ---

type ransomwatchVictim struct {
	Name       string `json:"victim"`
	Group      string `json:"group_name"`
	AttackDate string `json:"discovered"`
	Country    string `json:"country"`
	Website    string `json:"website"`
}

func tryRansomwatch(source string, data []byte) []Article {
	var victims []ransomwatchVictim
	if err := json.Unmarshal(data, &victims); err != nil {
		return nil
	}
	if len(victims) == 0 {
		return nil
	}

	var articles []Article
	for _, v := range victims {
		if v.Name == "" || v.Group == "" {
			continue
		}

		published := time.Now()
		if v.AttackDate != "" {
			if t, err := time.Parse("2006-01-02 15:04:05.000000", v.AttackDate); err == nil {
				published = t
			} else if t, err := time.Parse("2006-01-02", v.AttackDate); err == nil {
				published = t
			}
		}

		country := v.Country
		if country == "" {
			country = "okänt land"
		}

		title := fmt.Sprintf("Ransomware: %s listar %s som offer", v.Group, v.Name)
		desc := fmt.Sprintf("Ransomwaregruppen %s har publicerat %s (%s) på sin läcksida.", v.Group, v.Name, country)
		link := fmt.Sprintf("https://www.ransomware.live/#/group/%s", strings.ToLower(v.Group))

		articles = append(articles, Article{
			Title:       title,
			Link:        link,
			Description: desc,
			Published:   published,
			Source:      source,
		})
	}
	return articles
}

// --- HIBP Breaches parser ---

type hibpBreach struct {
	Name         string `json:"Name"`
	Title        string `json:"Title"`
	Domain       string `json:"Domain"`
	BreachDate   string `json:"BreachDate"`
	PwnCount     int    `json:"PwnCount"`
	Description  string `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool   `json:"IsVerified"`
	IsSensitive  bool   `json:"IsSensitive"`
	AddedDate    string `json:"AddedDate"`
}

func tryHIBPBreaches(source string, data []byte) []Article {
	var breaches []hibpBreach
	if err := json.Unmarshal(data, &breaches); err != nil {
		return nil
	}
	if len(breaches) == 0 {
		return nil
	}

	// Only include recent breaches (last 90 days by AddedDate)
	cutoff := time.Now().AddDate(0, -3, 0)
	var articles []Article
	for _, b := range breaches {
		added, err := time.Parse("2006-01-02T15:04:05Z", b.AddedDate)
		if err != nil {
			continue
		}
		if added.Before(cutoff) {
			continue
		}

		published := added
		if t, err := time.Parse("2006-01-02", b.BreachDate); err == nil {
			published = t
		}

		dataTypes := strings.Join(b.DataClasses, ", ")
		title := fmt.Sprintf("Dataläcka: %s — %s konton exponerade", b.Title, formatCount(b.PwnCount))
		desc := fmt.Sprintf("Dataintrång mot %s (domän: %s). %s konton med: %s.",
			b.Title, b.Domain, formatCount(b.PwnCount), dataTypes)

		articles = append(articles, Article{
			Title:       title,
			Link:        fmt.Sprintf("https://haveibeenpwned.com/PwnedWebsites#%s", b.Name),
			Description: desc,
			Published:   published,
			Source:      source,
		})
	}
	return articles
}

// --- MISP Manifest parser ---

type mispManifestEntry struct {
	Info           string `json:"info"`
	Date           string `json:"date"`
	ThreatLevelID  string `json:"threat_level_id"`
	Timestamp      string `json:"timestamp"`
}

func tryMISPManifest(source string, data []byte, manifestURL string) []Article {
	var manifest map[string]mispManifestEntry
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil
	}
	if len(manifest) == 0 {
		return nil
	}

	baseURL := strings.TrimSuffix(manifestURL, "manifest.json")
	cutoff := time.Now().AddDate(0, -1, 0) // last 30 days

	var articles []Article
	for uuid, entry := range manifest {
		if entry.Info == "" {
			continue
		}

		published := time.Now()
		if entry.Date != "" {
			if t, err := time.Parse("2006-01-02", entry.Date); err == nil {
				published = t
			}
		}
		if published.Before(cutoff) {
			continue
		}

		threatLevel := "medel"
		switch entry.ThreatLevelID {
		case "1":
			threatLevel = "hög"
		case "2":
			threatLevel = "medel"
		case "3":
			threatLevel = "låg"
		}

		articles = append(articles, Article{
			Title:       fmt.Sprintf("MISP: %s", entry.Info),
			Link:        fmt.Sprintf("%s%s.json", baseURL, uuid),
			Description: fmt.Sprintf("CIRCL MISP OSINT-event. Hotnivå: %s. %s", threatLevel, entry.Info),
			Published:   published,
			Source:      source,
		})
	}

	// Sort by date descending, limit to 50 most recent
	sort.Slice(articles, func(i, j int) bool {
		return articles[i].Published.After(articles[j].Published)
	})
	if len(articles) > 50 {
		articles = articles[:50]
	}

	return articles
}

func formatCount(n int) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fMd", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.0fk", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

type FeedSource struct {
	Name    string
	URL     string
	Headers map[string]string
}

type FeedResult struct {
	Name     string
	URL      string
	Articles int
	Error    string
}

func FetchAllDetailed(sources []FeedSource, maxAge time.Duration) ([]Article, []FeedResult) {
	var (
		mu       sync.Mutex
		articles []Article
		results  []FeedResult
		wg       sync.WaitGroup
	)

	cutoff := time.Now().Add(-maxAge)
	// Limit concurrent fetches to avoid resource exhaustion.
	sem := make(chan struct{}, 10)

	for _, src := range sources {
		wg.Add(1)
		go func(s FeedSource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			items, err := fetchOne(s.Name, s.URL, s.Headers)
			fr := FeedResult{Name: s.Name, URL: s.URL}
			if err != nil {
				log.Printf("warning: feed %s: %v", s.Name, err)
				fr.Error = err.Error()
				mu.Lock()
				results = append(results, fr)
				mu.Unlock()
				return
			}
			var kept int
			mu.Lock()
			for _, a := range items {
				if !a.Published.IsZero() && a.Published.After(cutoff) {
					articles = append(articles, a)
					kept++
				}
			}
			fr.Articles = kept
			results = append(results, fr)
			mu.Unlock()
		}(src)
	}

	wg.Wait()
	return articles, results
}

