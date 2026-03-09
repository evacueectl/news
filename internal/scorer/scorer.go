package scorer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"strings"
	gosync "sync"
	"time"

	"news/internal/config"
	"news/internal/feed"
	"news/internal/store"

	"sync/atomic"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// isBillingError checks if an error is a non-retryable billing/auth error.
func isBillingError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) && apiErr.StatusCode == 400 {
		return strings.Contains(err.Error(), "credit balance") || strings.Contains(err.Error(), "billing")
	}
	return false
}

// CurrentScoreVersion is bumped when prompt logic changes to force rescore of all articles.
const CurrentScoreVersion = 7

// AttackChainStep represents one step in an attack chain.
type AttackChainStep struct {
	Phase  string `json:"phase"`
	Actor  string `json:"actor"`
	TTP    string `json:"ttp"`
	Detail string `json:"detail"`
}

// ExtractedIOC represents an indicator of compromise found in article text.
type ExtractedIOC struct {
	Value string `json:"value"`
	Type  string `json:"type"` // "ipv4", "domain", "md5", "sha1", "sha256"
}

type ScoredArticle struct {
	feed.Article
	Score              float64
	Severity           float64
	Verified           bool
	Scope              int
	Novelty            int
	Summary            string
	Detail             string
	ThreatActor        string
	ThreatActorAliases string
	ActivityType       string
	ActorType          string
	Origin             string
	Country            string
	Region             string
	Impact             string
	Sector             string
	TTPs               string
	AttackChain        []AttackChainStep
	CVEs               []string
	IOCs               []ExtractedIOC
}

type triageResult struct {
	Index        int     `json:"index"`
	Severity     float64 `json:"severity"`
	Verified     bool    `json:"verified"`
	Scope        int     `json:"scope"`
	Novelty      int     `json:"novelty"`
	ActivityType string  `json:"activity_type"`
	Summary      string  `json:"summary"`
}

type enrichResult struct {
	Index              int               `json:"index"`
	Detail             string            `json:"detail"`
	ThreatActor        string            `json:"threat_actor"`
	ThreatActorAliases string            `json:"threat_actor_aliases"`
	ActorType          string            `json:"actor_type"`
	Origin             string            `json:"origin"`
	Country            string            `json:"country"`
	Region             string            `json:"region"`
	Impact             string            `json:"impact"`
	Sector             string            `json:"sector"`
	TTPs               string            `json:"ttps"`
	AttackChain        []AttackChainStep `json:"attack_chain"`
	CVEs               []string          `json:"cves"`
}

// ProgressFunc reports progress during scoring. phase is "triage" or "enrich", done/total are batch counts.
type ProgressFunc func(phase string, done, total int)

func computeScore(severity float64, verified bool, scope, novelty int) float64 {
	// Severity is primary signal (0-10 → 0-6.5)
	base := severity * 0.65
	// Verified: moderate boost, not a binary cliff
	if verified {
		base += 0.5
	}
	// Scope: 1-5 → 0.25-1.25
	base += float64(scope) * 0.25
	// Novelty: 1-3 → 0.35-1.05
	base += float64(novelty) * 0.35
	return math.Min(10, math.Max(1, base))
}

// applyTriageResult applies parsed triage fields to a scored article.
func applyTriageResult(a *ScoredArticle, r triageResult) {
	a.Severity = r.Severity
	a.Verified = r.Verified
	a.Scope = r.Scope
	a.Novelty = r.Novelty
	a.ActivityType = NormalizeActivity(r.ActivityType)
	a.Summary = r.Summary
	a.Score = computeScore(r.Severity, r.Verified, r.Scope, r.Novelty)
}

// applyEnrichResult applies parsed enrich fields and derives region from country.
func applyEnrichResult(a *ScoredArticle, r enrichResult) {
	a.Detail = r.Detail
	a.ThreatActor = NormalizeThreatActor(r.ThreatActor)
	a.ThreatActorAliases = r.ThreatActorAliases
	a.ActorType = NormalizeActorType(r.ActorType)
	a.Origin = NormalizeOrigin(r.Origin)
	a.Country = NormalizeCountry(r.Country)
	a.Sector = NormalizeSector(r.Sector)
	a.Impact = r.Impact
	a.TTPs = r.TTPs
	a.AttackChain = r.AttackChain
	a.CVEs = r.CVEs

	// CVE regex fallback: extract from article text and merge
	a.CVEs = mergeCVEs(a.CVEs, extractCVEs(a.Article))

	// IOC extraction from article text
	a.IOCs = extractIOCs(a.Article)

	// Derive region from country
	country := a.Country
	countries := strings.Split(country, ",")
	regionSet := make(map[string]bool)
	for _, c := range countries {
		c = strings.TrimSpace(c)
		if reg, ok := countryToRegion[c]; ok {
			regionSet[reg] = true
		}
	}
	if len(regionSet) > 1 {
		a.Region = "Globalt"
	} else if len(regionSet) == 1 {
		for reg := range regionSet {
			a.Region = reg
		}
	} else {
		a.Region = NormalizeRegion(r.Region)
		if a.Region == "" {
			a.Region = "Globalt"
		}
	}
}

// profileSectorMatch maps profile sector keywords to NIS2 sector names.
var profileSectorMatch = map[string]map[string]bool{
	"transport":             {"Transporter": true},
	"transporter":           {"Transporter": true},
	"energy":                {"Energi": true},
	"energi":                {"Energi": true},
	"telecom":               {"Digital infrastruktur": true, "IKT-tjänster": true},
	"telekom":               {"Digital infrastruktur": true, "IKT-tjänster": true},
	"kritisk infrastruktur": {"Energi": true, "Transporter": true, "Dricksvatten": true, "Avloppsvatten": true, "Digital infrastruktur": true, "IKT-tjänster": true, "Offentlig förvaltning": true},
}

// profileBoost returns a score bonus based on how well the article matches the user's profile.
func profileBoost(profile config.Profile, country, region, sector string) float64 {
	boost := 0.0

	// Region/country matching — most specific match wins
	regionLower := strings.ToLower(strings.TrimSpace(region))
	for _, pr := range profile.Regions {
		prl := strings.ToLower(strings.TrimSpace(pr))
		// Direct region match (e.g. profile "Norden" == article region "Norden")
		if prl == regionLower {
			b := 0.75 // Europa or other broad region
			if prl == "norden" {
				b = 1.5
			}
			boost = math.Max(boost, b)
		}
		// Country name match (e.g. profile "Sverige" and article country contains "Sverige")
		for _, c := range strings.Split(country, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if strings.EqualFold(c, pr) {
				boost = math.Max(boost, 2.0)
			}
			// Country's derived region matches profile region
			if reg, ok := countryToRegion[c]; ok && strings.EqualFold(reg, pr) {
				b := 0.75
				if strings.EqualFold(pr, "norden") {
					b = 1.5
				}
				boost = math.Max(boost, b)
			}
		}
	}

	// Sector matching
	if sector != "" {
		for _, ps := range profile.Sectors {
			psl := strings.ToLower(strings.TrimSpace(ps))
			if matches, ok := profileSectorMatch[psl]; ok {
				if matches[sector] {
					boost += 0.5
					break
				}
			}
		}
	}

	return boost
}

// Score runs the two-stage pipeline: Triage (fast) → Enrich (deep) → Profile boost.
func Score(ctx context.Context, cfg *config.Config, articles []feed.Article, feedback []store.FeedbackEntry) ([]ScoredArticle, error) {
	return ScoreWithProgress(ctx, cfg, articles, feedback, nil)
}

// ScoreWithProgress is like Score but reports progress via fn.
// Uses the Message Batches API (50% cost reduction) for >= 10 articles,
// realtime API for smaller batches where latency matters more than cost.
func ScoreWithProgress(ctx context.Context, cfg *config.Config, articles []feed.Article, feedback []store.FeedbackEntry, fn ProgressFunc) ([]ScoredArticle, error) {
	const batchThreshold = 10

	if len(articles) >= batchThreshold {
		log.Printf("using batch API for %d articles (50%% cost reduction)", len(articles))
		batchCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()

		triaged, err := triageBatch(batchCtx, cfg, articles, feedback, fn)
		if err != nil {
			return nil, err
		}
		enriched, err := enrichBatch(batchCtx, cfg, triaged, fn)
		if err != nil {
			log.Printf("warning: batch enrichment failed, using triage results: %v", err)
			applyProfileBoost(cfg.Profile, triaged)
			return triaged, nil
		}
		applyProfileBoost(cfg.Profile, enriched)
		return enriched, nil
	}

	log.Printf("using realtime API for %d articles (below batch threshold)", len(articles))
	triaged, err := Triage(ctx, cfg, articles, feedback, fn)
	if err != nil {
		return nil, err
	}
	enriched, err := Enrich(ctx, cfg, triaged, fn)
	if err != nil {
		log.Printf("warning: enrichment failed, using triage results: %v", err)
		applyProfileBoost(cfg.Profile, triaged)
		return triaged, nil
	}
	applyProfileBoost(cfg.Profile, enriched)
	return enriched, nil
}

// applyProfileBoost adds profile-based relevance boost to all scored articles.
func applyProfileBoost(profile config.Profile, articles []ScoredArticle) {
	for i := range articles {
		boost := profileBoost(profile, articles[i].Country, articles[i].Region, articles[i].Sector)
		if boost > 0 {
			articles[i].Score = math.Min(10, articles[i].Score+boost)
		}
	}
}

// Triage scores articles quickly with Haiku: severity, verified, scope, novelty, activity_type, summary.
func Triage(ctx context.Context, cfg *config.Config, articles []feed.Article, feedback []store.FeedbackEntry, fn ProgressFunc) ([]ScoredArticle, error) {
	if len(articles) == 0 {
		return nil, nil
	}

	client := anthropic.NewClient(option.WithAPIKey(cfg.APIKey))
	triagePrompt := buildTriagePrompt(feedback)

	scored := make([]ScoredArticle, len(articles))
	for i, a := range articles {
		scored[i] = ScoredArticle{Article: a}
	}

	const batchSize = 50
	const maxConcurrent = 3
	sem := make(chan struct{}, maxConcurrent)
	var wg gosync.WaitGroup
	var mu gosync.Mutex
	triageCtx, triageCancel := context.WithCancel(ctx)
	defer triageCancel()
	var billingAborted atomic.Bool

	for start := 0; start < len(articles); start += batchSize {
		end := start + batchSize
		if end > len(articles) {
			end = len(articles)
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-triageCtx.Done():
				return
			}
			defer func() { <-sem }()
			batch := articles[s:e]
			userMsg := buildTriageUserMessage(batch, s)

			msg, err := retryAPICall(triageCtx, client, anthropic.MessageNewParams{
				MaxTokens: 16384,
				Model:     anthropic.Model("claude-haiku-4-5-20251001"),
				System: []anthropic.TextBlockParam{
					{Text: triagePrompt, CacheControl: anthropic.NewCacheControlEphemeralParam()},
				},
				Messages: []anthropic.MessageParam{
					anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
				},
			})
			if err != nil {
				if isBillingError(err) && billingAborted.CompareAndSwap(false, true) {
					log.Printf("warning: API billing error — aborting remaining batches: %v", err)
					triageCancel()
				} else if !billingAborted.Load() {
					log.Printf("warning: triage API error (batch %d-%d): %v", s, e-1, err)
				}
				return
			}

			text := extractText(msg)
			results, err := parseTriageResults(text)
			if err != nil {
				log.Printf("warning: triage parse error: %v\nresponse: %s", err, text)
				return
			}

			mu.Lock()
			for _, r := range results {
				if r.Index >= s && r.Index < e {
					applyTriageResult(&scored[r.Index], r)
				}
			}
			mu.Unlock()
			log.Printf("triage batch %d-%d: %d results", s, e-1, len(results))
			if fn != nil {
				fn("triage", e, len(articles))
			}
		}(start, end)
	}
	wg.Wait()

	// Apply defaults
	for i := range scored {
		if scored[i].Region == "" {
			scored[i].Region = "Globalt"
		}
		if scored[i].Country == "" {
			scored[i].Country = "Globalt"
		}
	}

	return scored, nil
}

// Enrich adds deep analysis (detail, threat_actor, country, etc.) for articles with severity >= 5.
func Enrich(ctx context.Context, cfg *config.Config, articles []ScoredArticle, fn ProgressFunc) ([]ScoredArticle, error) {
	// Filter articles that need enrichment (severity >= 5, not already enriched)
	var toEnrich []int
	for i, a := range articles {
		if a.Severity >= 3.0 && a.Detail == "" {
			toEnrich = append(toEnrich, i)
		}
	}
	if len(toEnrich) == 0 {
		return articles, nil
	}

	client := anthropic.NewClient(option.WithAPIKey(cfg.APIKey))
	enrichPrompt := buildEnrichPrompt()

	const batchSize = 30
	const maxConcurrent = 3
	sem := make(chan struct{}, maxConcurrent)
	var wg gosync.WaitGroup
	var mu gosync.Mutex
	enrichCtx, enrichCancel := context.WithCancel(ctx)
	defer enrichCancel()
	var enrichBillingAborted atomic.Bool

	for start := 0; start < len(toEnrich); start += batchSize {
		end := start + batchSize
		if end > len(toEnrich) {
			end = len(toEnrich)
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-enrichCtx.Done():
				return
			}
			defer func() { <-sem }()
			indices := toEnrich[s:e]
			userMsg := buildEnrichUserMessage(articles, indices)

			msg, err := retryAPICall(enrichCtx, client, anthropic.MessageNewParams{
				MaxTokens: 16384,
				Model:     anthropic.Model(cfg.EnrichModel),
				System: []anthropic.TextBlockParam{
					{Text: enrichPrompt, CacheControl: anthropic.NewCacheControlEphemeralParam()},
				},
				Messages: []anthropic.MessageParam{
					anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
				},
			})
			if err != nil {
				if isBillingError(err) && enrichBillingAborted.CompareAndSwap(false, true) {
					log.Printf("warning: API billing error — aborting remaining batches: %v", err)
					enrichCancel()
				} else if !enrichBillingAborted.Load() {
					log.Printf("warning: enrich API error (batch %d-%d): %v", s, e-1, err)
				}
				return
			}

			text := extractText(msg)
			results, err := parseEnrichResults(text)
			if err != nil {
				log.Printf("warning: enrich parse error: %v\nresponse: %s", err, text)
				return
			}

			mu.Lock()
			for _, r := range results {
				if r.Index < 0 || r.Index >= len(indices) {
					continue
				}
				idx := indices[r.Index]
				applyEnrichResult(&articles[idx], r)
			}
			mu.Unlock()
			log.Printf("enrich batch %d-%d: %d results", s, e-1, len(results))
			if fn != nil {
				fn("enrich", e, len(toEnrich))
			}
		}(start, end)
	}
	wg.Wait()

	return articles, nil
}

// retryAPICall wraps client.Messages.New with retry logic for transient errors.
// Retries up to 2 times (3 attempts total) with exponential backoff (2s, 4s).
// Only retries on HTTP 429, 529, 5xx and network errors, not 4xx.
func retryAPICall(ctx context.Context, client anthropic.Client, params anthropic.MessageNewParams) (*anthropic.Message, error) {
	const maxRetries = 2
	backoff := 2 * time.Second

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		msg, err := client.Messages.New(ctx, params)
		if err == nil {
			return msg, nil
		}
		lastErr = err

		// Check if retryable
		var apiErr *anthropic.Error
		if errors.As(err, &apiErr) {
			code := apiErr.StatusCode
			retryable := code == http.StatusTooManyRequests || // 429
				code == 529 || // Anthropic overloaded
				code >= http.StatusInternalServerError // 5xx
			if !retryable {
				return nil, err // non-retryable API error (4xx)
			}
		}
		// Network errors are retryable by default

		if attempt >= maxRetries {
			log.Printf("API call failed (attempt %d/%d): %v — giving up", attempt+1, maxRetries+1, err)
			break
		}
		log.Printf("API call failed (attempt %d/%d): %v — retrying in %s", attempt+1, maxRetries+1, err, backoff)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, lastErr
}

// pollBatch polls a message batch until it ends or context is cancelled.
// Reports progress via fn if provided.
func pollBatch(ctx context.Context, client anthropic.Client, batchID, phase string, totalRequests int, fn ProgressFunc) error {
	start := time.Now()
	interval := 10 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}

		batch, err := client.Messages.Batches.Get(ctx, batchID)
		if err != nil {
			return fmt.Errorf("poll batch %s: %w", batchID, err)
		}

		succeeded := batch.RequestCounts.Succeeded
		processing := batch.RequestCounts.Processing
		log.Printf("batch %s: %d/%d succeeded, %d processing", batchID, succeeded, totalRequests, processing)

		if fn != nil {
			fn(phase, int(succeeded), totalRequests)
		}

		if batch.ProcessingStatus == "ended" {
			errored := batch.RequestCounts.Errored
			expired := batch.RequestCounts.Expired
			canceled := batch.RequestCounts.Canceled
			if errored > 0 || expired > 0 || canceled > 0 {
				log.Printf("batch %s ended: %d succeeded, %d errored, %d expired, %d canceled",
					batchID, succeeded, errored, expired, canceled)
			}
			return nil
		}

		// Increase interval after 2 minutes
		elapsed := time.Since(start)
		if elapsed > 5*time.Minute {
			interval = 60 * time.Second
		} else if elapsed > 2*time.Minute {
			interval = 30 * time.Second
		}
	}
}

// batchExtractText extracts the text content from a batch result message.
func batchExtractText(resp anthropic.MessageBatchIndividualResponse) (string, error) {
	if resp.Result.Type != "succeeded" {
		return "", fmt.Errorf("request %s: result type %s", resp.CustomID, resp.Result.Type)
	}
	msg := resp.Result.AsSucceeded()
	for _, block := range msg.Message.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			return tb.Text, nil
		}
	}
	return "", fmt.Errorf("request %s: no text content in response", resp.CustomID)
}

// triageBatch runs triage scoring using the Message Batches API (50% cost reduction).
func triageBatch(ctx context.Context, cfg *config.Config, articles []feed.Article,
	feedback []store.FeedbackEntry, fn ProgressFunc) ([]ScoredArticle, error) {
	if len(articles) == 0 {
		return nil, nil
	}

	client := anthropic.NewClient(option.WithAPIKey(cfg.APIKey))
	triagePrompt := buildTriagePrompt(feedback)

	scored := make([]ScoredArticle, len(articles))
	for i, a := range articles {
		scored[i] = ScoredArticle{Article: a}
	}

	const batchSize = 50
	var requests []anthropic.MessageBatchNewParamsRequest
	for start := 0; start < len(articles); start += batchSize {
		end := start + batchSize
		if end > len(articles) {
			end = len(articles)
		}
		userMsg := buildTriageUserMessage(articles[start:end], start)
		requests = append(requests, anthropic.MessageBatchNewParamsRequest{
			CustomID: fmt.Sprintf("t-%d", start),
			Params: anthropic.MessageBatchNewParamsRequestParams{
				MaxTokens: 16384,
				Model:     anthropic.Model("claude-haiku-4-5-20251001"),
				System:    []anthropic.TextBlockParam{{Text: triagePrompt}},
				Messages: []anthropic.MessageParam{
					anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
				},
			},
		})
	}

	log.Printf("submitting triage batch (%d requests for %d articles)...", len(requests), len(articles))
	batch, err := client.Messages.Batches.New(ctx, anthropic.MessageBatchNewParams{
		Requests: requests,
	})
	if err != nil {
		return nil, fmt.Errorf("create triage batch: %w", err)
	}
	log.Printf("triage batch created: %s", batch.ID)

	if fn != nil {
		fn("triage", 0, len(articles))
	}

	if err := pollBatch(ctx, client, batch.ID, "triage", len(requests), fn); err != nil {
		return nil, fmt.Errorf("poll triage batch: %w", err)
	}

	// Stream results
	log.Printf("triage batch ended, streaming results...")
	stream := client.Messages.Batches.ResultsStreaming(ctx, batch.ID)
	defer stream.Close()

	var totalResults int
	for stream.Next() {
		resp := stream.Current()
		text, err := batchExtractText(resp)
		if err != nil {
			log.Printf("warning: triage %s", err)
			continue
		}

		results, err := parseTriageResults(text)
		if err != nil {
			log.Printf("warning: triage parse error for %s: %v", resp.CustomID, err)
			continue
		}

		for _, r := range results {
			if r.Index >= 0 && r.Index < len(scored) {
				applyTriageResult(&scored[r.Index], r)
				totalResults++
			}
		}
	}
	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("stream triage results: %w", err)
	}

	log.Printf("triage batch: %d results from %d articles", totalResults, len(articles))

	// Apply defaults
	for i := range scored {
		if scored[i].Region == "" {
			scored[i].Region = "Globalt"
		}
		if scored[i].Country == "" {
			scored[i].Country = "Globalt"
		}
	}

	return scored, nil
}

// enrichBatch runs enrichment using the Message Batches API (50% cost reduction).
func enrichBatch(ctx context.Context, cfg *config.Config, articles []ScoredArticle, fn ProgressFunc) ([]ScoredArticle, error) {
	var toEnrich []int
	for i, a := range articles {
		if a.Severity >= 3.0 && a.Detail == "" {
			toEnrich = append(toEnrich, i)
		}
	}
	if len(toEnrich) == 0 {
		return articles, nil
	}

	client := anthropic.NewClient(option.WithAPIKey(cfg.APIKey))
	enrichPrompt := buildEnrichPrompt()

	const batchSize = 30
	var requests []anthropic.MessageBatchNewParamsRequest
	for start := 0; start < len(toEnrich); start += batchSize {
		end := start + batchSize
		if end > len(toEnrich) {
			end = len(toEnrich)
		}
		indices := toEnrich[start:end]
		userMsg := buildEnrichUserMessage(articles, indices)
		requests = append(requests, anthropic.MessageBatchNewParamsRequest{
			CustomID: fmt.Sprintf("e-%d", start),
			Params: anthropic.MessageBatchNewParamsRequestParams{
				MaxTokens: 16384,
				Model:     anthropic.Model(cfg.EnrichModel),
				System:    []anthropic.TextBlockParam{{Text: enrichPrompt}},
				Messages: []anthropic.MessageParam{
					anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg)),
				},
			},
		})
	}

	log.Printf("submitting enrich batch (%d requests for %d articles)...", len(requests), len(toEnrich))
	batch, err := client.Messages.Batches.New(ctx, anthropic.MessageBatchNewParams{
		Requests: requests,
	})
	if err != nil {
		return nil, fmt.Errorf("create enrich batch: %w", err)
	}
	log.Printf("enrich batch created: %s", batch.ID)

	if fn != nil {
		fn("enrich", 0, len(toEnrich))
	}

	if err := pollBatch(ctx, client, batch.ID, "enrich", len(requests), fn); err != nil {
		return nil, fmt.Errorf("poll enrich batch: %w", err)
	}

	// Stream results
	log.Printf("enrich batch ended, streaming results...")
	stream := client.Messages.Batches.ResultsStreaming(ctx, batch.ID)
	defer stream.Close()

	var totalResults int
	for stream.Next() {
		resp := stream.Current()
		text, err := batchExtractText(resp)
		if err != nil {
			log.Printf("warning: enrich %s", err)
			continue
		}

		// Parse the start index from CustomID to find the right slice of toEnrich
		var batchStart int
		fmt.Sscanf(resp.CustomID, "e-%d", &batchStart)
		batchEnd := batchStart + batchSize
		if batchEnd > len(toEnrich) {
			batchEnd = len(toEnrich)
		}
		indices := toEnrich[batchStart:batchEnd]

		results, err := parseEnrichResults(text)
		if err != nil {
			log.Printf("warning: enrich parse error for %s: %v", resp.CustomID, err)
			continue
		}

		for _, r := range results {
			if r.Index < 0 || r.Index >= len(indices) {
				continue
			}
			idx := indices[r.Index]
			applyEnrichResult(&articles[idx], r)
			totalResults++
		}
	}
	if err := stream.Err(); err != nil {
		return nil, fmt.Errorf("stream enrich results: %w", err)
	}

	log.Printf("enrich batch: %d results from %d articles", totalResults, len(toEnrich))
	return articles, nil
}

func buildTriagePrompt(feedback []store.FeedbackEntry) string {
	var sb strings.Builder
	sb.WriteString(`Du bedömer cybersäkerhetsartiklar objektivt. INGEN geografisk eller sektorsbias.

severity (1.00-10.00): Teknisk allvarlighet.
  9-10: Zero-day med aktiv exploatering, kritisk infrastruktur nere, massiv dataläcka (miljoner poster)
  7-8: CVSS 9+, ransomware på stor org, ny statlig kampanj med teknisk evidens
  5-6: Måttliga CVE:er, commodity-malware, DDoS med bekräftad nedetid
  3-4: Obekräftade claims, låg-allvarlighets CVE, enstaka DDoS utan verifiering
  1-2: Brus, produktnyheter, duplicerat, rena policyartiklar
  OBS DDoS: Obekräftade DDoS-claims (Telegram etc) utan verifierad nedetid = max 3.00.
  DDoS med bekräftad nedetid på stor tjänst = 5-6. DDoS mot kritisk infrastruktur = 7+.

verified (true/false): Bekräftad av OBEROENDE källa eller teknisk evidens?
  true = CERT/CSIRT-advisory, CVE med teknisk analys, tredjepartsbekräftelse, forensisk rapport
  false = Aktörens eget påstående, Telegram-inlägg, obekräftad screenshot, "claimed",
          DDoS-claim utan nedtidsbevis, ransomware-listning utan bekräftelse
  DEFAULT: false. Sätt true ENBART när oberoende verifiering finns i artikeln.

scope (1-5): Hur många drabbas?
  1 = enstaka system/produkt (en specifik app-sårbarhet, en server)
  2 = en organisation (ett företag hackat, en databas läckt)
  3 = sektor/bransch (kampanj mot sjukhus, våg av phishing mot banker)
  4 = nationell/multinationell (statlig kampanj, CERT-varning, landsomfattande störning)
  5 = global (internet-wide sårbarhet typ Log4Shell, globalt botnet)
  OBS: En sårbarhet i en specifik produkt = scope 1-2, INTE 5, även om produkten finns globalt.

novelty (1-3): 1=känt/rutin, 2=ny kampanj/vinkel, 3=helt ny aktör/TTP/vektor

activity_type: EXAKT ett av: "Ransomware", "Phishing", "Malware", "Sårbarhet", "Dataläcka", "DDoS", "Supply chain", "Intrång", "Spionage", "Defacement". Eller ""

RUNDOR/SAMMANFATTNINGAR (podcasts, nyhetsbrev, "week in review", "SANS NewsBites" etc.):
- Dessa täcker FLERA oberoende nyheter. Bedöm ENBART den mest allvarliga enskilda händelsen.
- Basera severity, scope, activity_type på DEN enskilda händelsen, INTE en kombination av alla.
- Summary ska beskriva den primära händelsen, inte hela artikeln.

summary: kort sammanfattning på svenska (1 mening)

Använd hela skalan med två decimaler (t.ex. 7.34, 3.15, 2.10) för naturlig spridning. Undvik att klumpa allt i 7-8.
`)

	if len(feedback) > 0 {
		sb.WriteString("\nKalibrering baserad på användarfeedback:\n")
		for _, f := range feedback {
			icon := "+"
			if f.Vote == "down" {
				icon = "-"
			}
			fmt.Fprintf(&sb, "  [%s] %s\n", icon, f.Title)
		}
		sb.WriteString("Artiklar liknande [+] bör få högre severity, artiklar liknande [-] bör få lägre.\n")
	}

	sb.WriteString(`
Svara ENBART med en JSON-array:
[{"index":0, "severity":7.34, "verified":true, "scope":3, "novelty":2, "activity_type":"...", "summary":"..."}, ...]
Ingen annan text.`)

	return sb.String()
}

// triageText returns a short article text for triage scoring.
// Title + 800 chars is enough for severity/scope/novelty assessment.
func triageText(a feed.Article) string {
	text := a.Description
	if a.Content != "" {
		text = a.Content
	}
	const maxChars = 800
	if len(text) > maxChars {
		cut := text[:maxChars]
		if idx := strings.LastIndex(cut, " "); idx > maxChars/2 {
			cut = cut[:idx]
		}
		return cut + "…"
	}
	return text
}

// enrichText returns fuller article text for deep analysis.
func enrichText(a feed.Article) string {
	text := a.Description
	if a.Content != "" {
		text = a.Content
	}
	const maxChars = 2000
	if len(text) > maxChars {
		cut := text[:maxChars]
		if idx := strings.LastIndex(cut, " "); idx > maxChars/2 {
			cut = cut[:idx]
		}
		return cut + "…"
	}
	return text
}

func buildTriageUserMessage(articles []feed.Article, offset int) string {
	var sb strings.Builder
	sb.WriteString("Bedöm dessa artiklar:\n\n")
	for i, a := range articles {
		fmt.Fprintf(&sb, "[%d] %s\n%s\nSource: %s\n\n", offset+i, a.Title, triageText(a), a.Source)
	}
	return sb.String()
}

func buildEnrichPrompt() string {
	return `Analysera dessa cybersäkerhetsartiklar och extrahera strukturerad data.
Varje artikel har redan bedömts — severity, activity_type och summary ges som kontext.

VIKTIGT om RUNDOR/SAMMANFATTNINGAR (podcasts, nyhetsbrev, veckosammanfattningar):
- Artiklar som "Risky Business #808", "SANS NewsBites", "Week in Review" etc. täcker FLERA OBEROENDE nyheter.
- Fokusera ENBART på den huvudsakliga/mest allvarliga händelsen (vanligtvis nämnd i titeln).
- Blanda ALDRIG ihop aktörer/länder/CVE:er från olika nyheter i samma artikel.
- Om titeln nämner en specifik händelse (t.ex. "Entra megabug"), analysera BARA den. Ignorera övriga nyheter i artikeln.
- En aktör som NÄMNS i artikeln men inte är ansvarig för huvudhändelsen ska INTE anges som threat_actor.

VIKTIGT om hotaktörer:
- threat_actor: Använd MITRE ATT&CK / Mandiant-namn som primärt namn (t.ex. "APT28", "APT29", "Lazarus Group", "Sandworm"). Ransomware-grupper: deras eget namn (t.ex. "LockBit", "Akira"). Hacktivister: deras eget namn (t.ex. "NoName057(16)").
- threat_actor_aliases: Ange alias från alla stora leverantörer. Exempel: APT28 → "Fancy Bear, Forest Blizzard, Sofacy, Sednit, Pawn Storm". APT29 → "Cozy Bear, Midnight Blizzard, Nobelium, The Dukes".
- Ange ALDRIG malware-namn (AsyncRAT, Remcos, Cobalt Strike, Mirai, etc.) som threat_actor. Malware är verktyg, inte aktörer.
- Om ingen specifik aktörsgrupp kan identifieras, lämna threat_actor tom ("").
- OMNÄMNANDE ≠ ATTRIBUTION: att en aktör nämns i en artikel betyder INTE att de är ansvariga för händelsen. Attributera ENBART den aktör som UTFÖR angreppet som artikeln primärt handlar om.

För varje artikel:
- detail: längre analys på svenska (3-5 meningar) som förklarar vad som hänt, vilka som drabbats, tekniska detaljer och varför det är relevant
- threat_actor: EXAKT EN hotaktör — den som utför primärangreppet. Använd MITRE/Mandiant-standard. Ange ALDRIG kommaseparerade namn. Om artikeln nämner flera grupper, välj den MEST RELEVANTA. Eller "" om okänd
- threat_actor_aliases: kända alias kommaseparerade, eller ""
- actor_type: EXAKT ett av: "Statlig", "Kriminell", "Hacktivist", "Forskare". Eller "" om okänt. Härled från kontext (ransomware → "Kriminell", APT → "Statlig")
- origin: EXAKT ETT land — aktörens URSPRUNGSLAND (attribution). Skriv på svenska. T.ex. "Ryssland" för APT28/NoName057(16), "Nordkorea" för Lazarus, "Kina" för APT41. Ange ALDRIG kommaseparerade länder — välj det MEST SANNOLIKA ursprungslandet. "" om okänt
- country: länderna som DRABBAS (målet, INTE aktörens ursprung). Skriv på svenska. Lista ALLA specifika länder som nämns, kommaseparerade. T.ex. "Danmark, Sverige, Finland" eller "USA, Storbritannien, Tyskland". Använd ALDRIG "Globalt" om specifika länder nämns i artikeln — även om det är många länder, lista dem. Använd "Globalt" ENBART om artikeln inte nämner något specifikt land alls
- DDoS-claims från Telegram/hacktivist-kanaler: extrahera alla nämnda målländer, men markera INTE som verified
- region: härled från country. Om flera länder i olika regioner, välj den MEST specifika/relevanta. EXAKT ett av: "Norden", "Europa", "Östeuropa", "Nordamerika", "Sydamerika", "Asien", "Mellanöstern", "Afrika", "Oceanien", "Globalt". Använd ALDRIG "Globalt" om en region kan härledas från länderna
- impact: kort påverkan på svenska, max 8 ord
- sector: NIS2-sektor för det DRABBADE målet. EXAKT ett av: "Energi", "Transporter", "Bankverksamhet", "Finansmarknadsinfrastruktur", "Hälso- och sjukvård", "Dricksvatten", "Avloppsvatten", "Digital infrastruktur", "IKT-tjänster", "Offentlig förvaltning", "Rymden", "Post och bud", "Avfallshantering", "Kemikalier", "Livsmedel", "Tillverkning", "Digitala leverantörer", "Forskning". Eller ""
- ttps: MITRE ATT&CK-tekniker. Kommaseparerade technique-ID:n med namn, t.ex. "T1566 Phishing, T1059 Command and Scripting Interpreter". Max 5 tekniker. Eller ""
- attack_chain: Om artikeln beskriver ett angrepp med flera steg eller flera aktörer, beskriv kedjan som en array:
  [{"phase":"initial_access","actor":"APT28","ttp":"T1566","detail":"Phishing-kampanj mot myndigheter"},
   {"phase":"execution","actor":"APT28","ttp":"T1059","detail":"PowerShell-exekvering av payload"}]
  Tillgängliga faser: initial_access, execution, persistence, privilege_escalation, defense_evasion, credential_access, discovery, lateral_movement, collection, exfiltration, impact.
  Om bara en aktör/steg finns: en-elements-array. Om okänt eller ej tillämpligt: tom array [].
  Om flera aktörer samarbetar, beskriv varje aktörs roll i ett eget steg.
- cves: Lista ALLA CVE-nummer som nämns i artikeln, t.ex. ["CVE-2024-1234", "CVE-2024-5678"]. Om inga CVE:er nämns: tom array [].

Svara ENBART med en JSON-array:
[{"index":0, "detail":"...", "threat_actor":"...", "threat_actor_aliases":"...", "actor_type":"...", "origin":"...", "country":"...", "region":"...", "impact":"...", "sector":"...", "ttps":"...", "attack_chain":[...], "cves":[...]}, ...]
Ingen annan text.`
}

func buildEnrichUserMessage(articles []ScoredArticle, indices []int) string {
	var sb strings.Builder
	sb.WriteString("Analysera dessa artiklar:\n\n")
	for i, idx := range indices {
		a := articles[idx]
		text := enrichText(feed.Article{Content: a.Content, Description: a.Description})
		fmt.Fprintf(&sb, "[%d] %s\n%s\nSource: %s\nSeverity: %.2f | Activity: %s | Summary: %s\n\n",
			i, a.Title, text, a.Source, a.Severity, a.ActivityType, a.Summary)
	}
	return sb.String()
}

func extractText(msg *anthropic.Message) string {
	for _, block := range msg.Content {
		if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
			return tb.Text
		}
	}
	return ""
}

var validActivityTypes = map[string]string{
	"ransomware":   "Ransomware",
	"phishing":     "Phishing",
	"malware":      "Malware",
	"sårbarhet":    "Sårbarhet",
	"dataläcka":    "Dataläcka",
	"ddos":         "DDoS",
	"supply chain": "Supply chain",
	"intrång":      "Intrång",
	"spionage":     "Spionage",
	"defacement":   "Defacement",
}

// Explicit mappings for common LLM mistakes
var activityAliases = map[string]string{
	"sårbarhet exploatering":               "Sårbarhet",
	"cyberattack mot kritisk infrastruktur": "Intrång",
	"bedrägeri":      "Phishing",
	"backdoor":       "Malware",
	"ip-stöld":       "Spionage",
	"cryptojacking":  "Malware",
	"multipel":       "",
	"exploit":        "Sårbarhet",
	"sårbarheit":     "Sårbarhet",
	"zero-day":       "Sårbarhet",
	"credential theft": "Intrång",
	"brute force":    "Intrång",
	"watering hole":  "Intrång",
	"wiper":          "Malware",
	"erpressning":    "Ransomware",
	"bedrägerier":    "Phishing",
	"utpressning":    "Ransomware",
	"extortion":      "Ransomware",
	"fraud":          "Phishing",
	"infostealer":    "Malware",
	"apt":            "Intrång",
	"botnet":         "Malware",
	"skimming":       "Intrång",
	"dos":            "DDoS",
}

var validActorTypes = map[string]string{
	"statlig":    "Statlig",
	"kriminell":  "Kriminell",
	"hacktivist": "Hacktivist",
	"forskare":   "Forskare",
}

var actorTypeAliases = map[string]string{
	"okänd": "",
	"unknown": "",
	"state-sponsored": "Statlig",
	"nation-state": "Statlig",
}

var validRegions = map[string]string{
	"norden":       "Norden",
	"europa":       "Europa",
	"östeuropa":    "Östeuropa",
	"nordamerika":  "Nordamerika",
	"sydamerika":   "Sydamerika",
	"asien":        "Asien",
	"mellanöstern": "Mellanöstern",
	"afrika":       "Afrika",
	"oceanien":     "Oceanien",
	"globalt":      "Globalt",
}

var validSectors = map[string]string{
	"energi":                      "Energi",
	"transporter":                 "Transporter",
	"bankverksamhet":              "Bankverksamhet",
	"finansmarknadsinfrastruktur": "Finansmarknadsinfrastruktur",
	"hälso- och sjukvård":         "Hälso- och sjukvård",
	"dricksvatten":                "Dricksvatten",
	"avloppsvatten":               "Avloppsvatten",
	"digital infrastruktur":       "Digital infrastruktur",
	"ikt-tjänster":                "IKT-tjänster",
	"offentlig förvaltning":       "Offentlig förvaltning",
	"rymden":                      "Rymden",
	"post och bud":                "Post och bud",
	"avfallshantering":            "Avfallshantering",
	"kemikalier":                  "Kemikalier",
	"livsmedel":                   "Livsmedel",
	"tillverkning":                "Tillverkning",
	"digitala leverantörer":       "Digitala leverantörer",
	"forskning":                   "Forskning",
}

var sectorAliases = map[string]string{
	"telekom":            "Digital infrastruktur",
	"telekommunikation":  "Digital infrastruktur",
	"telecommunications": "Digital infrastruktur",
	"it":                 "IKT-tjänster",
	"finans":             "Bankverksamhet",
	"transport":          "Transporter",
	"sjukvård":           "Hälso- och sjukvård",
	"hälsovård":          "Hälso- och sjukvård",
	"healthcare":         "Hälso- och sjukvård",
	"försvar":            "Offentlig förvaltning",
}

func normalizeEnum(val string, valid map[string]string, aliases map[string]string) string {
	if val == "" {
		return ""
	}
	low := strings.ToLower(strings.TrimSpace(val))
	// Direct match
	if canonical, ok := valid[low]; ok {
		return canonical
	}
	// Explicit alias
	if aliases != nil {
		if canonical, ok := aliases[low]; ok {
			return canonical
		}
	}
	// Prefix match
	for k, v := range valid {
		if strings.HasPrefix(low, k) {
			return v
		}
	}
	log.Printf("warning: enum value %q not recognized, discarding", val)
	return ""
}

// threatActorAliases maps variant names to canonical actor names.
var threatActorAliases = map[string]string{
	// APT groups — MITRE/Mandiant canonical names
	"lazarus":            "Lazarus Group",
	"lazarus group":      "Lazarus Group",
	"apt38":              "Lazarus Group",
	"diamond sleet":      "Lazarus Group",
	"hidden cobra":       "Lazarus Group",
	"labyrinth chollima": "Lazarus Group",
	"apt28":              "APT28",
	"fancy bear":         "APT28",
	"forest blizzard":    "APT28",
	"sofacy":             "APT28",
	"sednit":             "APT28",
	"pawn storm":         "APT28",
	"apt29":              "APT29",
	"cozy bear":          "APT29",
	"midnight blizzard":  "APT29",
	"nobelium":           "APT29",
	"the dukes":          "APT29",
	"apt41":              "APT41",
	"double dragon":      "APT41",
	"brass typhoon":      "APT41",
	"wicked panda":       "APT41",
	"muddywater":         "MuddyWater",
	"muddy water":        "MuddyWater",
	"mango sandstorm":    "MuddyWater",
	"sandworm":           "Sandworm",
	"voodoo bear":        "Sandworm",
	"seashell blizzard":  "Sandworm",
	"iridium":            "Sandworm",
	"turla":              "Turla",
	"venomous bear":      "Turla",
	"secret blizzard":    "Turla",
	"waterbug":           "Turla",
	"kimsuky":            "Kimsuky",
	"emerald sleet":      "Kimsuky",
	"velvet chollima":    "Kimsuky",
	"apt43":              "Kimsuky",
	"volt typhoon":       "Volt Typhoon",
	"bronze silhouette":  "Volt Typhoon",
	"salt typhoon":       "Salt Typhoon",
	"ghostemperor":       "Salt Typhoon",
	"cloud atlas":        "Cloud Atlas",
	"inception":          "Cloud Atlas",
	"eye pyramid":        "Eye Pyramid",
	"charming kitten":    "APT35",
	"apt35":              "APT35",
	"mint sandstorm":     "APT35",
	"uac-0050":           "UAC-0050",
	"unc6201":            "UNC6201",
	"unc6384":            "UNC6384",
	"unc2814":            "UNC2814",
	"mercenary akula":    "Mercenary Akula",
	// Ransomware groups
	"lockbit":         "LockBit",
	"lockbit2":        "LockBit",
	"lockbit3":        "LockBit",
	"lockbit5":        "LockBit",
	"qilin":           "Qilin",
	"akira":           "Akira",
	"play":            "Play",
	"rhysida":         "Rhysida",
	"cloak":           "Cloak",
	"dragonforce":     "DragonForce",
	"thegentlemen":    "The Gentlemen",
	"the gentlemen":   "The Gentlemen",
	"incransom":       "IncRansom",
	"inc ransom":      "IncRansom",
	"coinbasecartel":  "CoinbaseCartel",
	"coinbase cartel": "CoinbaseCartel",
	"cipherforce":     "CipherForce",
	"shinyhunters":    "ShinyHunters",
	"shiny hunters":   "ShinyHunters",
	"killsec":         "KillSec",
	"killsec3":        "KillSec",
	"anubis":          "Anubis",
	"lynx":            "Lynx",
	"nova":            "Nova",
	"kittykatkrew":    "KittyKatKrew",
	"nightspire":      "Nightspire",
	"beast":           "Beast",
	"medusa":          "Medusa",
	"everest":         "Everest",
	"termite":         "Termite",
	"atomsilo":        "AtomSilo",
	"nefilim":         "Nefilim",
	"conti":           "Conti",
	"shadowbyt3$":     "ShadowByt3$",
	"leaknet":         "Leaknet",
	"payoutsking":     "Payoutsking",
	"leakeddata":      "Leakeddata",
	"payload":         "Payload",
	"vect":            "Vect",
	"handala":         "Handala",
	"silentransomgroup": "SilentRansomGroup",
	// Hacktivists
	"ddosia":              "NoName057(16)",
	"noname057(16)":       "NoName057(16)",
	"noname057":           "NoName057(16)",
	"it army of ukraine":  "IT Army of Ukraine",
	"it army of russia":   "IT Army of Russia",
	"anonymous fénix":     "Anonymous Fénix",
	"diesel vortex":       "Diesel Vortex",
	"savvy seahorse":      "Savvy Seahorse",
	"graycharlie":         "GrayCharlie",
	"operation zero":      "Operation Zero",
	// DDoS groups from Telegram
	"server killers":      "Server Killers",
	"dark storm team":     "Dark Storm Team",
	"z-pentest alliance":  "Z-Pentest Alliance",
	"z-pentest":           "Z-Pentest Alliance",
	"thunder cyber":       "THUNDER CYBER",
	"thunder cyber team":  "THUNDER CYBER",
	"crew russia":         "CREW RUSSIA",
	"we are killnet":      "WE ARE KILLNET",
	"killnet":             "KillNet",
	"dienet":              "DieNet",
	"revolusi hime666":    "REVOLUSI HIME666",
	"keymous+":            "Keymous+",
	"keymous":             "Keymous+",
	"coup team":           "Coup Team",
	"dcg":                 "DCG",
	"dcg muslims":         "DCG",
	"inteid":              "Inteid",
	"furqan alliance":     "Furqan Alliance",
	"al furqan":           "Furqan Alliance",
	"tunisian maskers":    "Tunisian Maskers",
	"cyberforce tn":       "Tunisian Maskers",
	"avangardsec":         "AvangardSec",
	"rubiconh4ck":         "RubiconH4CK",
	"rubicon hack":        "RubiconH4CK",
	"floodhacking":        "FloodHacking",
	"flood hacking":       "FloodHacking",
	"рубеж":               "РУБЕЖ",
	"rubezh":              "РУБЕЖ",
	"holy league":         "Holy League",
	"rippersec":           "RipperSec",
	"cybervolk":           "CyberVolk",
	"overflame":           "OverFlame",
	"mr hamza":            "Mr Hamza",
	"wolf cyber army":     "Wolf Cyber Army",
	"usersec":             "UserSec",
}

// NormalizeThreatActor cleans up threat actor names from LLM.
func NormalizeThreatActor(actor string) string {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return ""
	}
	low := strings.ToLower(actor)
	// Discard generic descriptions that aren't real actor names
	junk := []string{"rysk statlig aktör", "kinesisk statlig", "iransk statlig",
		"okänd", "unknown", "n/a", "ej känd", "ingen", "multiple", "diverse",
		"kinesiska apt", "russisk regering", "iransk regering", "nordkoreansk",
		"statlig aktör", "state actor", "unnamed", "unidentified"}
	for _, j := range junk {
		if low == j || strings.HasPrefix(low, j) {
			return ""
		}
	}
	// Discard country names used as actor names
	countries := []string{"iran", "kina", "nordkorea", "ryssland", "usa", "kenya",
		"ukraine", "ukraina", "pakistan", "indien", "israel", "sydkorea", "japan"}
	for _, c := range countries {
		if low == c {
			return ""
		}
	}
	// Discard malware family names (tools, not actors)
	malware := map[string]bool{
		"asyncrat": true, "remcos": true, "xworm": true, "vidar": true,
		"lumma stealer": true, "lumma": true, "stealc": true, "strelc": true,
		"strelacstealer": true, "strelastealer": true,
		"valleyrat": true, "ghost rat": true, "njrat": true, "dcrat": true,
		"venom rat": true, "xtreme rat": true, "darkcomet": true, "spynote": true,
		"mirai": true, "bashlite": true, "aisuru": true,
		"qakbot": true, "emotet": true, "trickbot": true, "icedid": true,
		"cobalt strike": true, "brute ratel": true, "sliver": true,
		"havoc": true, "deimsosc2": true, "deimosc2": true, "adaptixc2": true,
		"metasploit": true, "kongtuke": true, "smartloader": true,
		"redline stealer": true, "redline": true, "raccoon stealer": true,
		"deerstealer": true, "loki password stealer": true,
		"hook": true, "empire downloader": true, "xmrig": true,
		"iclickfix": true, "clearfake": true, "socgholish": true,
		"1campaign": true, "silver fox": true,
		"wannacry": true, "notpetya": true, "ryuk": true,
		"arkanix": true, "ransomhub": true,
	}
	if malware[low] {
		return ""
	}
	// If comma-separated, keep only the first actor name
	if idx := strings.Index(actor, ","); idx >= 0 {
		actor = strings.TrimSpace(actor[:idx])
		if actor == "" {
			return ""
		}
		low = strings.ToLower(actor)
	}
	// Check MITRE ATT&CK aliases first (authoritative)
	if canonical, ok := LookupActorAlias(low); ok {
		return canonical
	}
	// Fallback to manual alias map (covers non-ATT&CK actors: DDoS groups, hacktivists, ransomware)
	if canonical, ok := threatActorAliases[low]; ok {
		return canonical
	}
	return actor
}

// IsKnownActor checks if a name matches a known threat actor in MITRE ATT&CK
// or the manual alias map. Unlike NormalizeThreatActor, this does NOT pass through
// unknown names — it returns true only for confirmed matches.
func IsKnownActor(name string) bool {
	if name == "" {
		return false
	}
	low := strings.ToLower(strings.TrimSpace(name))
	if _, ok := LookupActorAlias(low); ok {
		return true
	}
	_, ok := threatActorAliases[low]
	return ok
}

// Exported normalize helpers for use by web layer on cached data.
// actorNamingTable maps MITRE/Mandiant canonical names to other naming conventions.
// Key: MITRE name. Value: map of convention → display name.
var actorNamingTable = map[string]map[string]string{
	"APT28":         {"microsoft": "Forest Blizzard", "crowdstrike": "Fancy Bear"},
	"APT29":         {"microsoft": "Midnight Blizzard", "crowdstrike": "Cozy Bear"},
	"APT41":         {"microsoft": "Brass Typhoon", "crowdstrike": "Wicked Panda"},
	"APT35":         {"microsoft": "Mint Sandstorm", "crowdstrike": "Charming Kitten"},
	"Lazarus Group": {"microsoft": "Diamond Sleet", "crowdstrike": "Labyrinth Chollima"},
	"Sandworm":      {"microsoft": "Seashell Blizzard", "crowdstrike": "Voodoo Bear"},
	"Turla":         {"microsoft": "Secret Blizzard", "crowdstrike": "Venomous Bear"},
	"Kimsuky":       {"microsoft": "Emerald Sleet", "crowdstrike": "Velvet Chollima"},
	"MuddyWater":    {"microsoft": "Mango Sandstorm"},
	"Volt Typhoon":  {"crowdstrike": "Bronze Silhouette"},
	"Salt Typhoon":  {"microsoft": "Salt Typhoon"},
	"Cloud Atlas":   {"crowdstrike": "Inception"},
}

// DisplayActorName returns the actor name in the given naming convention.
// Falls back to MITRE name if no mapping exists for the convention.
func DisplayActorName(mitreName, convention string) string {
	if mitreName == "" {
		return ""
	}
	if convention == "" || convention == "mitre" {
		return mitreName
	}
	if names, ok := actorNamingTable[mitreName]; ok {
		if display, ok := names[convention]; ok {
			return display
		}
	}
	return mitreName
}

// countryAliases maps common non-Swedish country names to their Swedish equivalents.
var countryAliases = map[string]string{
	"germany": "Tyskland", "deutschland": "Tyskland",
	"france": "Frankrike", "italy": "Italien", "italien": "Italien",
	"spain": "Spanien", "united states": "USA", "united kingdom": "Storbritannien",
	"uk": "Storbritannien", "us": "USA", "russia": "Ryssland",
	"china": "Kina", "japan": "Japan", "south korea": "Sydkorea",
	"north korea": "Nordkorea", "india": "Indien", "brazil": "Brasilien",
	"canada": "Kanada", "australia": "Australien", "new zealand": "Nya Zeeland",
	"netherlands": "Nederländerna", "belgium": "Belgien", "switzerland": "Schweiz",
	"austria": "Österrike", "portugal": "Portugal", "poland": "Polen",
	"czech republic": "Tjeckien", "czechia": "Tjeckien", "romania": "Rumänien",
	"hungary": "Ungern", "greece": "Grekland", "ireland": "Irland",
	"ukraine": "Ukraina", "denmark": "Danmark", "sweden": "Sverige",
	"norway": "Norge", "finland": "Finland", "iceland": "Island",
	"turkey": "Turkiet", "israel": "Israel", "iran": "Iran", "iraq": "Irak",
	"saudi arabia": "Saudiarabien", "egypt": "Egypten", "south africa": "Sydafrika",
	"nigeria": "Nigeria", "kenya": "Kenya", "morocco": "Marocko",
	"taiwan": "Taiwan", "singapore": "Singapore", "thailand": "Thailand",
	"vietnam": "Vietnam", "indonesia": "Indonesien", "malaysia": "Malaysia",
	"philippines": "Filippinerna", "pakistan": "Pakistan",
	"mexico": "Mexiko", "colombia": "Colombia", "argentina": "Argentina",
	"global": "Globalt", "worldwide": "Globalt",
}

// NormalizeCountry normalizes a country name to Swedish, handling comma-separated
// values and common aliases. Region-like values are discarded.
func NormalizeCountry(v string) string {
	if v == "" {
		return "Globalt"
	}
	// Regions that should not appear as country values
	regionNames := map[string]bool{
		"nordamerika": true, "sydamerika": true, "europa": true,
		"asien": true, "afrika": true, "mellanöstern": true,
		"sydostasien": true, "östeuropa": true, "norden": true,
		"oceania": true, "oceanien": true,
	}
	// Handle comma-separated or "och"-separated
	parts := strings.Split(v, ",")
	if len(parts) == 1 {
		parts = strings.Split(v, " och ")
	}
	var normalized []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		low := strings.ToLower(p)
		// Skip region-like values
		if regionNames[low] {
			continue
		}
		// Check alias
		if sv, ok := countryAliases[low]; ok {
			p = sv
		}
		// Check if it's a known country in countryToRegion
		if _, ok := countryToRegion[p]; ok {
			normalized = append(normalized, p)
		}
	}
	if len(normalized) == 0 {
		return "Globalt"
	}
	return strings.Join(normalized, ", ")
}

// NormalizeOrigin normalizes an origin country name to Swedish.
// Unlike NormalizeCountry, origin should be a single country (attacker attribution).
// If comma-separated, only the first country is kept.
func NormalizeOrigin(v string) string {
	if v == "" {
		return ""
	}
	// If comma-separated, keep only the first
	if idx := strings.Index(v, ","); idx >= 0 {
		v = strings.TrimSpace(v[:idx])
	}
	if v == "" {
		return ""
	}
	result := NormalizeCountry(v)
	if result == "Globalt" {
		return ""
	}
	return result
}

func NormalizeActivity(v string) string  { return normalizeEnum(v, validActivityTypes, activityAliases) }
func NormalizeActorType(v string) string { return normalizeEnum(v, validActorTypes, actorTypeAliases) }
func NormalizeRegion(v string) string    { return normalizeEnum(v, validRegions, nil) }
func NormalizeSector(v string) string    { return normalizeEnum(v, validSectors, sectorAliases) }

// countryToRegion maps Swedish country names to their correct NIS2/geo region.
var countryToRegion = map[string]string{
	"Sverige": "Norden", "Danmark": "Norden", "Norge": "Norden", "Finland": "Norden", "Island": "Norden",
	"Frankrike": "Europa", "Tyskland": "Europa", "Italien": "Europa", "Spanien": "Europa",
	"Nederländerna": "Europa", "Belgien": "Europa", "Schweiz": "Europa", "Österrike": "Europa", "Portugal": "Europa",
	"Polen": "Europa", "Tjeckien": "Europa", "Rumänien": "Europa", "Ungern": "Europa", "Grekland": "Europa",
	"Irland": "Europa", "Bulgarien": "Europa", "Kroatien": "Europa", "Slovakien": "Europa",
	"Estland": "Europa", "Lettland": "Europa", "Litauen": "Europa", "Slovenien": "Europa", "Luxemburg": "Europa",
	"Serbien": "Europa", "Albanien": "Europa", "Nordmakedonien": "Europa", "Montenegro": "Europa", "Bosnien": "Europa",
	"Storbritannien": "Europa",
	"Ukraina": "Östeuropa", "Ryssland": "Östeuropa", "Belarus": "Östeuropa", "Moldavien": "Östeuropa", "Georgien": "Östeuropa",
	"USA": "Nordamerika", "Kanada": "Nordamerika", "Mexiko": "Nordamerika",
	"Brasilien": "Sydamerika", "Argentina": "Sydamerika", "Colombia": "Sydamerika", "Chile": "Sydamerika",
	"Peru": "Sydamerika", "Venezuela": "Sydamerika", "Ecuador": "Sydamerika",
	"Kina": "Asien", "Japan": "Asien", "Sydkorea": "Asien", "Nordkorea": "Asien",
	"Indien": "Asien", "Pakistan": "Asien", "Bangladesh": "Asien", "Sri Lanka": "Asien",
	"Indonesien": "Asien", "Malaysia": "Asien", "Thailand": "Asien", "Vietnam": "Asien", "Filippinerna": "Asien",
	"Singapore": "Asien", "Myanmar": "Asien", "Kambodja": "Asien", "Laos": "Asien", "Taiwan": "Asien",
	"Afghanistan": "Asien", "Uzbekistan": "Asien", "Kazakstan": "Asien",
	"Australien": "Oceanien", "Nya Zeeland": "Oceanien",
	"Iran": "Mellanöstern", "Irak": "Mellanöstern", "Saudiarabien": "Mellanöstern",
	"Förenade Arabemiraten": "Mellanöstern", "Israel": "Mellanöstern", "Turkiet": "Mellanöstern",
	"Qatar": "Mellanöstern", "Kuwait": "Mellanöstern", "Bahrain": "Mellanöstern", "Oman": "Mellanöstern",
	"Jordanien": "Mellanöstern", "Libanon": "Mellanöstern",
	"Armenien": "Mellanöstern", "Azerbajdzjan": "Mellanöstern",
	"Egypten": "Afrika", "Sydafrika": "Afrika", "Nigeria": "Afrika",
	"Kenya": "Afrika", "Etiopien": "Afrika", "Marocko": "Afrika", "Algeriet": "Afrika", "Tunisien": "Afrika",
	"Ghana": "Afrika", "Tanzania": "Afrika", "Uganda": "Afrika", "Mozambique": "Afrika", "Angola": "Afrika",
}

// regionIncludes maps parent regions to child regions (Europa includes Norden).
var regionIncludes = map[string][]string{
	"Europa": {"Norden"},
}

// MatchRegion returns true if an article with the given region and country fields
// belongs to the target region. Mirrors the stats page matchRegion() logic:
// 1. Direct region match
// 2. Parent-child (Europa includes Norden)
// 3. Country-to-region lookup (comma-separated countries)
// 4. "Globalt" always matches any region filter
func MatchRegion(articleRegion, articleCountry, targetRegion string) bool {
	if articleRegion == targetRegion || articleRegion == "Globalt" {
		return true
	}
	// Check parent-child (e.g. Norden articles match Europa filter)
	if children, ok := regionIncludes[targetRegion]; ok {
		for _, child := range children {
			if articleRegion == child {
				return true
			}
		}
	}
	// Check individual countries
	for _, c := range strings.Split(articleCountry, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if reg, ok := countryToRegion[c]; ok {
			if reg == targetRegion {
				return true
			}
			// Check parent-child for country's region
			if children, ok := regionIncludes[targetRegion]; ok {
				for _, child := range children {
					if reg == child {
						return true
					}
				}
			}
		}
	}
	return false
}

func parseJSON(text string) ([]byte, error) {
	start := strings.Index(text, "[")
	end := strings.LastIndex(text, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array found")
	}
	return []byte(text[start : end+1]), nil
}

func parseTriageResults(text string) ([]triageResult, error) {
	data, err := parseJSON(text)
	if err != nil {
		return nil, err
	}
	var results []triageResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func parseEnrichResults(text string) ([]enrichResult, error) {
	data, err := parseJSON(text)
	if err != nil {
		return nil, err
	}
	var results []enrichResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	return results, nil
}

// cveRe matches CVE identifiers in text.
var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// extractCVEs finds all CVE identifiers in article text.
func extractCVEs(a feed.Article) []string {
	text := a.Title + " " + a.Description
	if a.Content != "" {
		text += " " + a.Content
	}
	matches := cveRe.FindAllString(text, -1)
	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, m := range matches {
		if !seen[m] {
			seen[m] = true
			unique = append(unique, m)
		}
	}
	return unique
}

// mergeCVEs combines LLM-extracted and regex-extracted CVEs, deduplicating.
func mergeCVEs(llm, regex []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, c := range llm {
		if !seen[c] {
			seen[c] = true
			result = append(result, c)
		}
	}
	for _, c := range regex {
		if !seen[c] {
			seen[c] = true
			result = append(result, c)
		}
	}
	return result
}

// IOC extraction regexes.
var (
	iocIPv4Re   = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	iocMD5Re    = regexp.MustCompile(`\b([a-fA-F0-9]{32})\b`)
	iocSHA1Re   = regexp.MustCompile(`\b([a-fA-F0-9]{40})\b`)
	iocSHA256Re = regexp.MustCompile(`\b([a-fA-F0-9]{64})\b`)
	iocDomainRe = regexp.MustCompile(`\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:` + strings.Join(abusedTLDs, "|") + `))\b`)
)

// abusedTLDs are TLDs commonly used in malicious infrastructure.
var abusedTLDs = []string{
	"ru", "cn", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
	"buzz", "rest", "icu", "su", "cc", "pw", "ws", "bid",
	"click", "link", "work", "party", "date", "racing",
	"download", "win", "review", "stream", "trade",
	"onion", "bit", "bazar", "zz",
}

// rfc1918 checks if an IPv4 address is in private range.
func rfc1918(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return true // malformed → filter
	}
	a, b := parts[0], parts[1]
	switch {
	case a == "10":
		return true
	case a == "172" && b >= "16" && b <= "31":
		return true
	case a == "192" && b == "168":
		return true
	case a == "127":
		return true
	case a == "0" || a == "255":
		return true
	}
	return false
}

// validIPv4 checks that each octet is 0-255.
func validIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// benignDomains are common domains that should not be extracted as IOCs.
var benignDomains = map[string]bool{
	"google.ru": true, "yandex.ru": true, "mail.ru": true, "vk.ru": true,
	"baidu.cn": true, "qq.cn": true, "weibo.cn": true,
}

// extractIOCs finds IOCs (IPv4, domain, hash) in article text.
func extractIOCs(a feed.Article) []ExtractedIOC {
	text := a.Title + " " + a.Description
	if a.Content != "" {
		text += " " + a.Content
	}

	seen := make(map[string]bool)
	var iocs []ExtractedIOC
	add := func(val, typ string) {
		key := typ + ":" + val
		if !seen[key] {
			seen[key] = true
			iocs = append(iocs, ExtractedIOC{Value: val, Type: typ})
		}
	}

	// SHA256 first (longest), then SHA1, then MD5 — remove matched ranges to avoid substring false positives
	for _, m := range iocSHA256Re.FindAllString(text, -1) {
		add(strings.ToLower(m), "sha256")
	}
	textNoSHA256 := iocSHA256Re.ReplaceAllString(text, "")

	for _, m := range iocSHA1Re.FindAllString(textNoSHA256, -1) {
		add(strings.ToLower(m), "sha1")
	}
	textNoHashes := iocSHA1Re.ReplaceAllString(textNoSHA256, "")

	for _, m := range iocMD5Re.FindAllString(textNoHashes, -1) {
		add(strings.ToLower(m), "md5")
	}

	// IPv4
	for _, m := range iocIPv4Re.FindAllStringSubmatch(text, -1) {
		ip := m[1]
		if validIPv4(ip) && !rfc1918(ip) {
			add(ip, "ipv4")
		}
	}

	// Domains with abused TLDs
	for _, m := range iocDomainRe.FindAllStringSubmatch(text, -1) {
		domain := strings.ToLower(m[1])
		if !benignDomains[domain] {
			add(domain, "domain")
		}
	}

	return iocs
}
