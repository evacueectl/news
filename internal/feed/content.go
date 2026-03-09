package feed

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// maxContentSize limits fetched article pages to 2 MB.
const maxContentSize = 2 << 20

// maxContentLen caps extracted text at 8000 characters (enough for LLM context).
const maxContentLen = 8000

// contentClient has a shorter timeout than the feed client — we're fetching
// many pages concurrently and don't want one slow site blocking everything.
var contentClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

// Pre-compiled regexes for HTML processing.
var (
	stripTagRe = map[string]*regexp.Regexp{}
	articleRe  = regexp.MustCompile(`(?is)<article[^>]*>([\s\S]*)</article>`)
	mainRe     = regexp.MustCompile(`(?is)<main[^>]*>([\s\S]*)</main>`)
	bodyRe     = regexp.MustCompile(`(?is)<body[^>]*>([\s\S]*)</body>`)
	numEntityRe = regexp.MustCompile(`&#(\d+);`)
)

func init() {
	for _, tag := range []string{"script", "style", "nav", "header", "footer", "aside", "noscript", "svg", "form"} {
		stripTagRe[tag] = regexp.MustCompile(`(?is)<` + tag + `[\s>].*?</` + tag + `>`)
	}
}

// FetchContent fetches the article URL and extracts readable text.
// Returns empty string on any error (non-fatal).
func FetchContent(url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; NewsDigest/1.0)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := contentClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxContentSize))
	if err != nil {
		return ""
	}

	text := extractArticleText(string(body))
	if utf8.RuneCountInString(text) > maxContentLen {
		runes := []rune(text)
		text = string(runes[:maxContentLen])
	}
	return text
}

// FetchContentBatch fetches article content for articles missing Content,
// with concurrency control. Updates articles in-place.
func FetchContentBatch(articles []Article, concurrency int) int {
	if concurrency <= 0 {
		concurrency = 5
	}

	var mu sync.Mutex
	fetched := 0
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range articles {
		if articles[i].Content != "" {
			continue // Already have content from RSS/Atom
		}
		if articles[i].Link == "" {
			continue
		}
		if !strings.HasPrefix(articles[i].Link, "http") {
			continue
		}

		wg.Add(1)
		idx := i
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			content := FetchContent(articles[idx].Link)
			if content != "" {
				articles[idx].Content = content
				mu.Lock()
				fetched++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return fetched
}

// extractArticleText tries to extract the main article text from HTML.
// Uses greedy matching ([\s\S]*) to find the outermost tag, not the first inner close.
func extractArticleText(html string) string {
	// Remove script, style, nav, header, footer, aside, noscript blocks
	for _, tag := range []string{"script", "style", "nav", "header", "footer", "aside", "noscript", "svg", "form"} {
		if re, ok := stripTagRe[tag]; ok {
			html = re.ReplaceAllString(html, " ")
		}
	}

	// Try to extract article or main content (greedy — finds outermost tag)
	text := ""
	if m := articleRe.FindStringSubmatch(html); len(m) > 1 {
		text = m[1]
	} else if m := mainRe.FindStringSubmatch(html); len(m) > 1 {
		text = m[1]
	}

	// Fall back to body
	if text == "" {
		if m := bodyRe.FindStringSubmatch(html); len(m) > 1 {
			text = m[1]
		} else {
			text = html
		}
	}

	// Strip all remaining HTML tags
	text = htmlRe.ReplaceAllString(text, " ")

	// Unescape HTML entities
	text = unescapeHTML(text)

	// Collapse whitespace
	text = strings.Join(strings.Fields(text), " ")
	text = strings.TrimSpace(text)

	// Minimum useful length (rune count for multi-byte safety)
	if utf8.RuneCountInString(text) < 100 {
		return ""
	}

	return text
}

// unescapeHTML handles common HTML entities.
func unescapeHTML(s string) string {
	replacer := strings.NewReplacer(
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&#39;", "'",
		"&apos;", "'",
		"&nbsp;", " ",
	)
	s = replacer.Replace(s)
	// Handle numeric entities (decimal and hex)
	s = numEntityRe.ReplaceAllStringFunc(s, func(m string) string {
		numStr := m[2 : len(m)-1]
		var n int
		for _, c := range numStr {
			if c < '0' || c > '9' {
				return m
			}
			n = n*10 + int(c-'0')
			if n > 0x10FFFF {
				return m // Prevent overflow
			}
		}
		if n > 0 && n < 0x110000 {
			return string(rune(n))
		}
		return m
	})
	return s
}
