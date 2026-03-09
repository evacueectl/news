package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	gosync "sync"
	"time"

	"news/internal/config"
	"news/internal/scorer"
	"news/internal/store"
	"news/internal/sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

//go:embed templates/digest.html templates/stats.html templates/feeds.html templates/actor.html templates/settings.html templates/report.html templates/brief.html templates/base.css.html templates/worldmap.svg.html
var templateFS embed.FS

type ArticleJSON struct {
	Title              string   `json:"title"`
	Link               string   `json:"link"`
	Summary            string   `json:"summary"`
	Detail             string   `json:"detail"`
	Source             string   `json:"source"`
	Sources            []string `json:"sources,omitempty"`
	Time               string   `json:"time"`
	Published          string   `json:"published"`
	Score              float64  `json:"score"`
	Severity           float64  `json:"severity"`
	Verified           bool     `json:"verified"`
	Scope              int      `json:"scope"`
	Novelty            int      `json:"novelty"`
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
	AttackChain        string   `json:"attack_chain,omitempty"`
	CVEs               string   `json:"cves,omitempty"`
}

type FeedEntry struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Report types

type ReportData struct {
	Title              string
	Subtitle           string
	Generated          string
	Depth              string // "executive", "tactical", "technical"
	DepthLabel         string // "Ledning", "Analytiker", "Threat Hunt"
	FilterActor        string
	FilterRegion       string
	FilterSectors      []string
	DateFrom           string
	DateTo             string
	TotalArticles      int
	VerifiedCount      int
	AvgScore           float64
	ActivityBreakdown  map[string]int
	RegionBreakdown    map[string]int
	SectorBreakdown    map[string]int
	Actors             []ReportActor
	UngroupedArticles  []ReportArticle // articles without a known actor
	Exec               *ExecData       // non-nil only for executive depth
}

// Executive-specific types

type ExecData struct {
	ThreatLevel         string        // "KRITISK", "FÖRHÖJD", "MEDEL", "LÅG"
	ThreatColor         string        // "red", "amber", "yellow", "green"
	ThreatSummary       string        // one-sentence auto-generated summary
	Metrics             [4]MetricCard
	TopActorsSeverity   []ExecActor
	TopActorsLikelihood []ExecActor
	WeekLabels          []string // ["v9","v10",...]
	ActivityTrends      []ActivityTrend
	Assessments         []string
}

type MetricCard struct {
	Label     string
	Value     string    // formatted: "1140", "65%", "4.3"
	Delta     float64   // percent change vs previous period
	DeltaAbs  string    // "+168", "-0.4", "—"
	Sparkline []float64 // weekly data points for SVG
	UpIsBad   bool      // true = positive delta shown in red
}

type ExecActor struct {
	Name            string
	Type            string
	Description     string
	Activities      []string
	Regions         []string
	Sectors         []string
	ArticleCount    int
	AvgSeverity     float64
	Trend           string  // "ny", "ökande", "stabil", "minskande"
	LikelihoodScore float64 // 0-100, populated for likelihood list
	LastSeen        string  // ISO date of most recent article
	ActiveDays      int     // distinct days with articles in the period
}

type ActivityTrend struct {
	Type  string // "DDoS", "Ransomware", etc.
	Weeks []int  // count per week, aligned with WeekLabels
}

type WeekBucket struct {
	WeekStart      string
	ArticleCount   int
	VerifiedCount  int
	SumSeverity    float64
	ActorSet       map[string]bool
	ActivityCounts map[string]int
}

type PeriodStats struct {
	Articles     int
	VerifiedPct  float64
	AvgSeverity  float64
	ActiveActors int
}

type ReportTTP struct {
	ID    string
	Name  string
	Count int
}

type ReportActor struct {
	Name         string
	Aliases      string
	Type         string
	Description  string
	ArticleCount int
	AvgScore     float64
	Activities   []string
	Regions      []string
	Sectors      []string
	TTPs         []ReportTTP      // tactical+technical
	CVEs         []string         // tactical+technical
	IOCs         []store.IOCEntry // technical only
	Articles     []ReportArticle
}

type ReportArticle struct {
	Title        string
	Link         string
	Source       string
	Published    string
	Score        float64
	Severity     float64
	Verified     bool
	Summary      string
	ActivityType string
	Country      string
	Region       string
	Sector       string
	Detail       string // tactical+technical
	Impact       string
	TTPs         string   // tactical+technical
	CVEs         []string // tactical+technical
	IOCs         []store.IOCEntry             // technical only
	AttackChain  []scorer.AttackChainStep     // technical only
}

// Brief types

type BriefData struct {
	DaysBack          int
	DateFrom          string
	DateTo            string
	TotalArticles     int
	VerifiedCount     int
	AvgSeverity       float64
	Summary           string
	TopArticles       []BriefArticle
	ActiveActors      []BriefActor
	ActivityBreakdown []BriefBreakdownItem
}

type BriefArticle struct {
	Title        string
	Link         string
	Summary      string
	Score        float64
	Verified     bool
	ThreatActor  string
	ActorType    string
	ActivityType string
	Region       string
	Sector       string
	Published    string
	Source       string
}

type BriefActor struct {
	Name         string
	Type         string
	ArticleCount int
	Activities   []string
}

type BriefBreakdownItem struct {
	Label   string
	Count   int
	Percent float64
}

type Server struct {
	mu         gosync.RWMutex
	articles   []ArticleJSON
	feeds      []FeedEntry
	syncStatus *store.SyncStatusData
	engine     *sync.SyncEngine
	cfg        *config.Config
	configPath string
	generated  string
	db         *store.DB
	devMode    bool
	tmplDir    string

	autoCancel context.CancelFunc
	autoMu     gosync.Mutex
}

func NewServer(cfg *config.Config, configPath string, engine *sync.SyncEngine, feeds []FeedEntry, db *store.DB) *Server {
	s := &Server{
		cfg:        cfg,
		configPath: configPath,
		engine:     engine,
		feeds:      feeds,
		db:         db,
		generated:  time.Now().Format("2006-01-02 15:04"),
	}
	s.ReloadArticles()
	s.reloadSyncStatus()
	return s
}

func (s *Server) SetDevMode(tmplDir string) {
	s.devMode = true
	s.tmplDir = tmplDir
	log.Printf("Dev mode: loading templates from %s (no restart needed)", tmplDir)
}

func (s *Server) parseTemplate(funcMap template.FuncMap, files ...string) (*template.Template, error) {
	if s.devMode {
		paths := make([]string, len(files))
		for i, f := range files {
			paths[i] = filepath.Join(s.tmplDir, f)
		}
		return template.New(filepath.Base(files[0])).Funcs(funcMap).ParseFiles(paths...)
	}
	fsFiles := make([]string, len(files))
	for i, f := range files {
		fsFiles[i] = "templates/" + f
	}
	return template.New(files[0]).Funcs(funcMap).ParseFS(templateFS, fsFiles...)
}

func (s *Server) ReloadArticles() {
	allCached, _ := s.db.LoadArticles()
	all := s.cachedToJSON(allCached)
	s.mu.Lock()
	s.articles = all
	s.generated = time.Now().UTC().Format(time.RFC3339)
	s.mu.Unlock()
}

func (s *Server) reloadSyncStatus() {
	status, _ := s.db.LoadSyncStatus()
	s.mu.Lock()
	s.syncStatus = status
	s.mu.Unlock()
}

func (s *Server) Serve(addr string) error {
	funcMap := template.FuncMap{
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"sparkline": sparklinePoints,
	}

	type tmplSpec struct {
		files []string
	}
	specs := map[string]tmplSpec{
		"digest":   {[]string{"digest.html", "base.css.html"}},
		"stats":    {[]string{"stats.html", "base.css.html", "worldmap.svg.html"}},
		"feeds":    {[]string{"feeds.html", "base.css.html"}},
		"actor":    {[]string{"actor.html", "base.css.html"}},
		"settings": {[]string{"settings.html", "base.css.html"}},
		"report":   {[]string{"report.html", "base.css.html"}},
		"brief":    {[]string{"brief.html", "base.css.html"}},
	}
	getTmpl := func(name string) (*template.Template, error) {
		return s.parseTemplate(funcMap, specs[name].files...)
	}

	// In production mode, parse once at startup
	var tmplCache map[string]*template.Template
	if !s.devMode {
		tmplCache = make(map[string]*template.Template)
		for name := range specs {
			t, err := getTmpl(name)
			if err != nil {
				return fmt.Errorf("parse %s template: %w", name, err)
			}
			tmplCache[name] = t
		}
	}
	execTmpl := func(name string, w http.ResponseWriter, data interface{}) {
		var t *template.Template
		var err error
		if s.devMode {
			t, err = getTmpl(name)
			if err != nil {
				http.Error(w, fmt.Sprintf("template error: %v", err), 500)
				return
			}
		} else {
			t = tmplCache[name]
		}
		if err := t.Execute(w, data); err != nil {
			log.Printf("error: render %s: %v", name, err)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		data := map[string]interface{}{
			"Generated":   s.generated,
			"Articles":    s.articles,
			"DefaultTags": s.cfg.DefaultTags,
		}
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		execTmpl("digest", w, data)
	})

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		data := map[string]interface{}{
			"Generated":       s.generated,
			"Articles":        s.articles,
			"DefaultTags":     s.cfg.DefaultTags,
			"MapAlertMinutes": s.cfg.MapAlertMinutes,
		}
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		execTmpl("stats", w, data)
	})

	mux.HandleFunc("/actor", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		data := map[string]interface{}{
			"Articles": s.articles,
		}
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		execTmpl("actor", w, data)
	})

	mux.HandleFunc("/feeds", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		syncStatus := s.syncStatus
		feeds := s.feeds
		s.mu.RUnlock()

		// Get feed health and pending channels
		feedHealth, _ := s.db.FeedHealthStatus()
		pendingChannels, _ := s.db.PendingChannels()

		data := map[string]interface{}{
			"Feeds":            feeds,
			"SyncStatus":       syncStatus,
			"FeedHealth":       feedHealth,
			"PendingChannels":  pendingChannels,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		execTmpl("feeds", w, data)
	})

	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		data := map[string]interface{}{
			"Settings": map[string]interface{}{
				"min_score":         s.cfg.MinScore,
				"top_n":             s.cfg.TopN,
				"model":             s.cfg.Model,
				"fetch_window":      s.cfg.FetchWindow,
				"auto_sync":         s.cfg.AutoSync,
				"sync_interval":     s.cfg.SyncInterval,
				"actor_naming":      s.cfg.ActorNaming,
				"map_alert_minutes": s.cfg.MapAlertMinutes,
			},
			"SyncStatus":   s.syncStatus,
			"ArticleCount": len(s.articles),
		}
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		execTmpl("settings", w, data)
	})

	mux.HandleFunc("/api/feeds", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.mu.RLock()
			f := s.feeds
			s.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(f)
		case http.MethodPut:
			var updated []FeedEntry
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.feeds = updated
			s.cfg.Feeds = make([]config.Feed, len(updated))
			for i, f := range updated {
				s.cfg.Feeds[i] = config.Feed{Name: f.Name, URL: f.URL}
			}
			cfgCopy := *s.cfg
			s.mu.Unlock()
			if err := config.Save(s.configPath, &cfgCopy); err != nil {
				http.Error(w, "save error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.engine.OnBatch = func() {
			s.ReloadArticles()
		}
		go func() {
			result, err := s.engine.Run(context.Background())
			s.engine.OnBatch = nil
			if err != nil {
				log.Printf("async sync error: %v", err)
				return
			}
			s.ReloadArticles()
			s.reloadSyncStatus()
			log.Printf("async sync done: %d fetched, %d new, %d scored (%s)",
				result.Fetched, result.New, result.Scored, result.Duration.Round(time.Second))
		}()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "started"})
	})

	mux.HandleFunc("/api/sync/progress", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.engine.Progress())
	})

	mux.HandleFunc("/api/articles", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		arts := s.articles
		gen := s.generated
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"articles":  arts,
			"generated": gen,
		})
	})

	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.mu.RLock()
			settings := map[string]interface{}{
				"min_score":         s.cfg.MinScore,
				"top_n":             s.cfg.TopN,
				"model":             s.cfg.Model,
				"fetch_window":      s.cfg.FetchWindow,
				"auto_sync":         s.cfg.AutoSync,
				"sync_interval":     s.cfg.SyncInterval,
				"actor_naming":      s.cfg.ActorNaming,
				"map_alert_minutes": s.cfg.MapAlertMinutes,
			}
			s.mu.RUnlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(settings)
		case http.MethodPut:
			var req struct {
				MinScore        *float64 `json:"min_score"`
				TopN            *int     `json:"top_n"`
				Model           *string  `json:"model"`
				FetchWindow     *int     `json:"fetch_window"`
				AutoSync        *bool    `json:"auto_sync"`
				SyncInterval    *int     `json:"sync_interval"`
				ActorNaming     *string  `json:"actor_naming"`
				MapAlertMinutes *int     `json:"map_alert_minutes"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			if req.MinScore != nil {
				s.cfg.MinScore = *req.MinScore
			}
			if req.TopN != nil {
				s.cfg.TopN = *req.TopN
			}
			if req.Model != nil {
				s.cfg.Model = *req.Model
			}
			if req.FetchWindow != nil {
				s.cfg.FetchWindow = *req.FetchWindow
			}
			restartAutoSync := false
			if req.AutoSync != nil {
				if *req.AutoSync != s.cfg.AutoSync {
					restartAutoSync = true
				}
				s.cfg.AutoSync = *req.AutoSync
			}
			if req.SyncInterval != nil {
				if *req.SyncInterval != s.cfg.SyncInterval {
					restartAutoSync = true
				}
				s.cfg.SyncInterval = *req.SyncInterval
			}
			if req.MapAlertMinutes != nil {
				v := *req.MapAlertMinutes
				if v < 5 {
					v = 5
				}
				if v > 1440 {
					v = 1440
				}
				s.cfg.MapAlertMinutes = v
			}
			reloadNaming := false
			if req.ActorNaming != nil {
				switch *req.ActorNaming {
				case "mitre", "microsoft", "crowdstrike":
					if *req.ActorNaming != s.cfg.ActorNaming {
						reloadNaming = true
					}
					s.cfg.ActorNaming = *req.ActorNaming
				default:
					s.mu.Unlock()
					http.Error(w, "invalid actor_naming value", http.StatusBadRequest)
					return
				}
			}
			cfgCopy := *s.cfg
			autoSync := s.cfg.AutoSync
			s.mu.Unlock()

			if err := config.Save(s.configPath, &cfgCopy); err != nil {
				http.Error(w, "save error", http.StatusInternalServerError)
				return
			}

			if restartAutoSync {
				s.StopAutoSync()
				if autoSync {
					s.StartAutoSync()
				}
			}
			if reloadNaming {
				s.ReloadArticles()
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/feedback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			URL   string `json:"url"`
			Title string `json:"title"`
			Vote  string `json:"vote"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Vote != "up" && req.Vote != "down" {
			http.Error(w, "vote must be 'up' or 'down'", http.StatusBadRequest)
			return
		}
		entry := store.FeedbackEntry{
			URL:   req.URL,
			Title: req.Title,
			Vote:  req.Vote,
			Time:  time.Now().Format(time.RFC3339),
		}
		if err := s.db.SaveFeedback(entry); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/actor-description", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		// Check cache first
		cached, _ := s.db.LoadActorDescriptions()
		if desc, ok := cached[req.Name]; ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"description": desc})
			return
		}

		// Collect article context for this actor
		s.mu.RLock()
		var summaries []string
		for _, a := range s.articles {
			if a.ThreatActor == req.Name {
				line := a.Summary
				if line == "" {
					line = a.Title
				}
				if a.ActivityType != "" {
					line += " (" + a.ActivityType + ")"
				}
				summaries = append(summaries, line)
			}
		}
		apiKey := s.cfg.APIKey
		model := s.cfg.Model
		s.mu.RUnlock()

		if len(summaries) == 0 {
			http.Error(w, "actor not found", http.StatusNotFound)
			return
		}

		actorContext := strings.Join(summaries, "\n")
		prompt := fmt.Sprintf(`Beskriv hotaktören "%s" i 2-3 meningar på svenska. Inkludera typ (statlig/kriminell/hacktivist), ursprungsland om känt, primär verksamhet och typiska mål. Basera på följande artikelsammanfattningar:

%s

Svara ENBART med beskrivningen, ingen annan text.`, req.Name, actorContext)

		client := anthropic.NewClient(option.WithAPIKey(apiKey))
		msg, err := client.Messages.New(r.Context(), anthropic.MessageNewParams{
			MaxTokens: 256,
			Model:     anthropic.Model(model),
			Messages: []anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
			},
		})
		if err != nil {
			log.Printf("actor description error: %v", err)
			http.Error(w, "LLM error", http.StatusInternalServerError)
			return
		}

		var desc string
		for _, block := range msg.Content {
			if tb, ok := block.AsAny().(anthropic.TextBlock); ok {
				desc = strings.TrimSpace(tb.Text)
				break
			}
		}

		if desc != "" {
			if err := s.db.SaveActorDescription(req.Name, desc); err != nil {
				log.Printf("warning: save actor description: %v", err)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"description": desc})
	})

	// Pending channels API
	mux.HandleFunc("/api/channels/pending", func(w http.ResponseWriter, r *http.Request) {
		channels, _ := s.db.PendingChannels()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(channels)
	})

	mux.HandleFunc("/api/channels/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Add to config
		s.mu.Lock()
		s.cfg.TelegramChannels = append(s.cfg.TelegramChannels, config.TelegramChannel{
			Name:     req.Username,
			Username: req.Username,
		})
		cfgCopy := *s.cfg
		s.mu.Unlock()
		config.Save(s.configPath, &cfgCopy)
		s.db.RemovePendingChannel(req.Username)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/channels/dismiss", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s.db.RemovePendingChannel(req.Username)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Feed health API
	mux.HandleFunc("/api/feed-health", func(w http.ResponseWriter, r *http.Request) {
		health, _ := s.db.FeedHealthStatus()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(health)
	})

	mux.HandleFunc("/api/iocs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		actor := r.URL.Query().Get("actor")
		if actor == "" {
			json.NewEncoder(w).Encode(map[string]string{"error": "actor parameter required"})
			return
		}
		iocs, err := s.db.LoadIOCsForActor(actor)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(iocs)
	})

	mux.HandleFunc("/api/iocs/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		q := r.URL.Query().Get("q")
		if q == "" {
			json.NewEncoder(w).Encode(map[string]string{"error": "q parameter required"})
			return
		}
		iocs, err := s.db.SearchIOCs(q)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(iocs)
	})

	mux.HandleFunc("/api/mitre/techniques", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		actor := r.URL.Query().Get("actor")
		if actor == "" {
			json.NewEncoder(w).Encode(map[string]string{"error": "actor parameter required"})
			return
		}
		techIDs := scorer.ActorTechniques(actor)
		type technique struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		var techs []technique
		for _, id := range techIDs {
			name := scorer.LookupTechnique(id)
			techs = append(techs, technique{ID: id, Name: name})
		}
		json.NewEncoder(w).Encode(techs)
	})

	mux.HandleFunc("/brief", func(w http.ResponseWriter, r *http.Request) {
		daysBack := 1
		if v := r.URL.Query().Get("days"); v != "" {
			fmt.Sscanf(v, "%d", &daysBack)
			if daysBack < 1 {
				daysBack = 1
			}
			if daysBack > 365 {
				daysBack = 365
			}
		}

		now := time.Now()
		filter := store.ReportFilter{
			After:  now.AddDate(0, 0, -daysBack),
			Before: now,
		}

		briefData, err := s.buildBriefData(filter, daysBack)
		if err != nil {
			http.Error(w, "brief error: "+err.Error(), 500)
			return
		}

		data := map[string]interface{}{
			"Brief": briefData,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		execTmpl("brief", w, data)
	})

	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		depth := q.Get("depth")
		if depth != "executive" && depth != "tactical" && depth != "technical" {
			depth = "tactical"
		}

		now := time.Now()
		dateFrom := now.AddDate(0, 0, -30)
		dateTo := now
		if v := q.Get("from"); v != "" {
			if t, err := time.Parse("2006-01-02", v); err == nil {
				dateFrom = t
			}
		}
		if v := q.Get("to"); v != "" {
			if t, err := time.Parse("2006-01-02", v); err == nil {
				dateTo = t
			}
		}

		var minScore float64
		if v := q.Get("min_score"); v != "" {
			fmt.Sscanf(v, "%f", &minScore)
		}

		var sectors []string
		if v := q.Get("sector"); v != "" {
			for _, s := range strings.Split(v, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					sectors = append(sectors, s)
				}
			}
		}

		filter := store.ReportFilter{
			Actor:    q.Get("actor"),
			Region:   q.Get("region"),
			Sectors:  sectors,
			MinScore: minScore,
			After:    dateFrom,
			Before:   dateTo,
		}

		reportData, err := s.buildReportData(filter, depth)
		if err != nil {
			http.Error(w, "report error: "+err.Error(), 500)
			return
		}

		data := map[string]interface{}{
			"Report":   reportData,
			"ShowForm": q.Get("print") != "1",
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		execTmpl("report", w, data)
	})

	if s.cfg.AutoSync {
		s.StartAutoSync()
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	fmt.Printf("Serving feed at http://%s\n", addr)
	return srv.ListenAndServe()
}

func (s *Server) StartAutoSync() {
	s.autoMu.Lock()
	defer s.autoMu.Unlock()
	if s.autoCancel != nil {
		return
	}
	s.mu.RLock()
	interval := time.Duration(s.cfg.SyncInterval) * time.Minute
	s.mu.RUnlock()
	ctx, cancel := context.WithCancel(context.Background())
	s.autoCancel = cancel
	log.Printf("auto-sync started (every %s)", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Println("auto-sync: starting...")
				if _, err := s.engine.Run(ctx); err != nil {
					log.Printf("auto-sync error: %v", err)
				} else {
					s.ReloadArticles()
					s.reloadSyncStatus()
					log.Println("auto-sync: complete")
				}
			}
		}
	}()
}

func (s *Server) StopAutoSync() {
	s.autoMu.Lock()
	defer s.autoMu.Unlock()
	if s.autoCancel != nil {
		s.autoCancel()
		s.autoCancel = nil
		log.Println("auto-sync stopped")
	}
}

func (s *Server) cachedToJSON(articles []store.CachedArticle) []ArticleJSON {
	s.mu.RLock()
	actorNaming := s.cfg.ActorNaming
	s.mu.RUnlock()
	out := make([]ArticleJSON, 0, len(articles))
	for _, a := range articles {
		published := a.Published
		if published != "" && !strings.HasSuffix(published, "Z") && !strings.Contains(published, "+") && (len(published) < 6 || !strings.ContainsAny(published[len(published)-6:], "+-")) {
			published += "Z"
		}
		activityType := scorer.NormalizeActivity(a.ActivityType)
		actorType := scorer.NormalizeActorType(a.ActorType)
		region := scorer.NormalizeRegion(a.Region)
		if region == "" {
			region = "Globalt"
		}
		country := scorer.NormalizeCountry(a.Country)
		sector := scorer.NormalizeSector(a.Sector)
		threatActor := scorer.NormalizeThreatActor(a.ThreatActor)
		threatActor = scorer.DisplayActorName(threatActor, actorNaming)

		sources := a.Sources
		if len(sources) == 0 && a.Source != "" {
			sources = []string{a.Source}
		}

		out = append(out, ArticleJSON{
			Title:              a.Title,
			Link:               a.Link,
			Summary:            a.Summary,
			Detail:             a.Detail,
			Source:             a.Source,
			Sources:            sources,
			Time:               "",
			Published:          published,
			Score:              a.Score,
			Severity:           a.Severity,
			Verified:           a.Verified,
			Scope:              a.Scope,
			Novelty:            a.Novelty,
			ThreatActor:        threatActor,
			ThreatActorAliases: a.ThreatActorAliases,
			ActivityType:       activityType,
			ActorType:          actorType,
			Origin:             scorer.NormalizeOrigin(a.Origin),
			Country:            country,
			Region:             region,
			Impact:             a.Impact,
			Sector:             sector,
			TTPs:               a.TTPs,
			AttackChain:        a.AttackChain,
			CVEs:               a.CVEs,
		})
	}
	return out
}

// bucketByWeek groups articles into ISO week buckets (Monday start).
func bucketByWeek(articles []store.CachedArticle) []WeekBucket {
	bucketMap := make(map[string]*WeekBucket)
	for _, a := range articles {
		pub := parsePublished(a.Published)
		if pub.IsZero() {
			continue
		}
		// Find Monday of this week
		weekday := int(pub.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		monday := pub.AddDate(0, 0, -(weekday - 1))
		key := monday.Format("2006-01-02")

		b, ok := bucketMap[key]
		if !ok {
			b = &WeekBucket{
				WeekStart:      key,
				ActorSet:       make(map[string]bool),
				ActivityCounts: make(map[string]int),
			}
			bucketMap[key] = b
		}
		b.ArticleCount++
		b.SumSeverity += a.Severity
		if a.Verified {
			b.VerifiedCount++
		}
		actor := scorer.NormalizeThreatActor(a.ThreatActor)
		if actor != "" {
			b.ActorSet[actor] = true
		}
		activity := scorer.NormalizeActivity(a.ActivityType)
		if activity != "" {
			b.ActivityCounts[activity]++
		}
	}
	var weeks []WeekBucket
	for _, b := range bucketMap {
		weeks = append(weeks, *b)
	}
	sort.Slice(weeks, func(i, j int) bool {
		return weeks[i].WeekStart < weeks[j].WeekStart
	})
	return weeks
}

// computePeriodStats computes aggregate stats for a set of articles.
func computePeriodStats(articles []store.CachedArticle) PeriodStats {
	if len(articles) == 0 {
		return PeriodStats{}
	}
	var sumSev float64
	var verified int
	actors := make(map[string]bool)
	for _, a := range articles {
		sumSev += a.Severity
		if a.Verified {
			verified++
		}
		actor := scorer.NormalizeThreatActor(a.ThreatActor)
		if actor != "" {
			actors[actor] = true
		}
	}
	return PeriodStats{
		Articles:     len(articles),
		VerifiedPct:  float64(verified) / float64(len(articles)) * 100,
		AvgSeverity:  sumSev / float64(len(articles)),
		ActiveActors: len(actors),
	}
}

// computeThreatLevel returns a threat level label and color based on current stats.
func computeThreatLevel(current, previous PeriodStats, volumeTrend float64) (string, string) {
	sevNorm := current.AvgSeverity / 10.0
	verNorm := current.VerifiedPct / 100.0
	volNorm := (volumeTrend + 1.0) / 2.0
	if volNorm > 1 {
		volNorm = 1
	}
	if volNorm < 0 {
		volNorm = 0
	}
	actorNorm := math.Min(float64(current.ActiveActors), 30) / 30.0

	score := sevNorm*0.35 + verNorm*0.20 + volNorm*0.25 + actorNorm*0.20

	switch {
	case score >= 0.70:
		return "KRITISK", "red"
	case score >= 0.50:
		return "FÖRHÖJD", "amber"
	case score >= 0.30:
		return "MEDEL", "yellow"
	default:
		return "LÅG", "green"
	}
}

// actorTrend classifies an actor's trend based on article count change.
func actorTrend(currentCount, previousCount int) string {
	if previousCount == 0 && currentCount > 0 {
		return "ny"
	}
	if currentCount == 0 {
		return "minskande"
	}
	ratio := float64(currentCount) / float64(previousCount)
	if previousCount == 0 {
		ratio = 2.0
	}
	switch {
	case ratio >= 1.5:
		return "ökande"
	case ratio <= 0.6:
		return "minskande"
	default:
		return "stabil"
	}
}

// computeLikelihood calculates a 0-100 likelihood score for an actor bucket.
func computeLikelihood(
	articles []store.CachedArticle,
	w config.LikelihoodWeights,
	refTime time.Time,
	periodDays int,
	filterRegion string,
	p95ArticleCount float64,
) float64 {
	if len(articles) == 0 {
		return 0
	}

	freq := math.Min(float64(len(articles))/p95ArticleCount, 1.0)

	daySet := make(map[string]bool)
	var latestPub time.Time
	var verifiedCount, geoMatchCount int

	for _, a := range articles {
		pub := parsePublished(a.Published)
		if !pub.IsZero() {
			daySet[pub.Format("2006-01-02")] = true
			if pub.After(latestPub) {
				latestPub = pub
			}
		}
		if a.Verified {
			verifiedCount++
		}
		if filterRegion != "" {
			region := scorer.NormalizeRegion(a.Region)
			if region == filterRegion {
				geoMatchCount++
			} else if region != "Globalt" {
				for _, c := range strings.Split(a.Country, ",") {
					c = strings.TrimSpace(c)
					if c != "" && scorer.MatchRegion("", c, filterRegion) {
						geoMatchCount++
						break
					}
				}
			}
		}
	}

	persist := 0.0
	if periodDays > 0 {
		persist = math.Min(float64(len(daySet))/float64(periodDays), 1.0)
	}

	recency := 0.0
	if !latestPub.IsZero() {
		hours := refTime.Sub(latestPub).Hours()
		if hours < 0 {
			hours = 0
		}
		recency = math.Exp(-hours / w.HalfLifeH)
	}

	verifiedRatio := float64(verifiedCount) / float64(len(articles))

	geoFit := 0.0
	if filterRegion != "" {
		geoFit = float64(geoMatchCount) / float64(len(articles))
	} else {
		geoFit = 1.0
	}

	return w.Frequency*freq + w.Persistence*persist +
		w.Recency*recency + w.Verified*verifiedRatio + w.GeoFit*geoFit
}

// generateThreatSummary creates a one-sentence Swedish summary of the period.
func generateThreatSummary(stats PeriodStats, actBreakdown map[string]int, region string) string {
	// Find top activity type
	var topAct string
	var topCount int
	for act, count := range actBreakdown {
		if count > topCount {
			topAct = act
			topCount = count
		}
	}
	regionStr := ""
	if region != "" {
		regionStr = " med fokus på " + region
	}
	if topAct != "" && stats.Articles > 0 {
		pct := float64(topCount) / float64(stats.Articles) * 100
		return fmt.Sprintf("Under perioden observerades %d artiklar%s, dominerat av %s (%.0f%%) med genomsnittlig allvarlighetsgrad %.1f.",
			stats.Articles, regionStr, topAct, pct, stats.AvgSeverity)
	}
	return fmt.Sprintf("Under perioden observerades %d artiklar%s med genomsnittlig allvarlighetsgrad %.1f.",
		stats.Articles, regionStr, stats.AvgSeverity)
}

// generateAssessments creates 2-3 deterministic assessment bullets.
func generateAssessments(topActors []ExecActor, current, previous PeriodStats, actBreakdown map[string]int) []string {
	var out []string

	// 1. Volume trend
	if previous.Articles > 0 {
		delta := float64(current.Articles-previous.Articles) / float64(previous.Articles) * 100
		if delta > 20 {
			out = append(out, fmt.Sprintf("Vi bedömer med hög tillförlitlighet att hotaktiviteten ökar, med %.0f%% fler observationer jämfört med föregående period.", delta))
		} else if delta < -20 {
			out = append(out, fmt.Sprintf("Hotaktiviteten har minskat med %.0f%% jämfört med föregående period.", -delta))
		} else {
			out = append(out, "Hotaktiviteten ligger på en stabil nivå jämfört med föregående period.")
		}
	} else {
		out = append(out, fmt.Sprintf("Under perioden observerades %d artiklar. Ingen föregående period finns att jämföra med.", current.Articles))
	}

	// 2. Dominant activity type
	var topAct string
	var topCount int
	for act, count := range actBreakdown {
		if count > topCount {
			topAct = act
			topCount = count
		}
	}
	if topAct != "" && current.Articles > 0 {
		pct := float64(topCount) / float64(current.Articles) * 100
		out = append(out, fmt.Sprintf("Dominerande aktivitetstyp: %s (%.0f%% av observationerna).", topAct, pct))
	}

	// 3. Watch list — first increasing high-severity actor
	for _, a := range topActors {
		if a.Trend == "ökande" && a.AvgSeverity >= 5.0 {
			out = append(out, fmt.Sprintf("Bevaka %s som visar ökad aktivitet med genomsnittlig allvarlighetsgrad %.1f.", a.Name, a.AvgSeverity))
			break
		}
	}

	return out
}

// sparklinePoints converts a float slice to SVG polyline points string.
func sparklinePoints(data []float64) string {
	if len(data) == 0 {
		return ""
	}
	maxVal := 0.0
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}
	w := 70.0
	h := 24.0
	step := w / float64(len(data)-1)
	if len(data) == 1 {
		step = 0
	}
	var points []string
	for i, v := range data {
		x := float64(i) * step
		y := h - (v/maxVal)*h*0.85 - h*0.05
		points = append(points, fmt.Sprintf("%.1f,%.1f", x, y))
	}
	return strings.Join(points, " ")
}

// parsePublished tries common time formats for article published fields.
func parsePublished(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (s *Server) buildReportData(filter store.ReportFilter, depth string) (*ReportData, error) {
	allArticles, err := s.db.LoadFilteredArticles(filter)
	if err != nil {
		return nil, err
	}

	// Go-side region filtering (mirrors stats page matchRegion logic)
	var articles []store.CachedArticle
	if filter.Region != "" {
		for _, a := range allArticles {
			if scorer.MatchRegion(a.Region, a.Country, filter.Region) {
				articles = append(articles, a)
			}
		}
	} else {
		articles = allArticles
	}

	s.mu.RLock()
	actorNaming := s.cfg.ActorNaming
	likelihoodWeights := s.cfg.LikelihoodWeights
	s.mu.RUnlock()

	depthLabels := map[string]string{
		"executive": "Ledning",
		"tactical":  "Analytiker",
		"technical": "Threat Hunt",
	}

	// Build title
	title := "Hotrapport"
	if filter.Actor != "" {
		title += ": " + filter.Actor
	} else if filter.Region != "" {
		title += ": " + filter.Region
	} else if len(filter.Sectors) > 0 {
		title += ": " + strings.Join(filter.Sectors, ", ")
	}

	subtitle := filter.After.Format("2006-01-02") + " — " + filter.Before.Format("2006-01-02")

	rd := &ReportData{
		Title:             title,
		Subtitle:          subtitle,
		Generated:         time.Now().Format("2006-01-02 15:04"),
		Depth:             depth,
		DepthLabel:        depthLabels[depth],
		FilterActor:       filter.Actor,
		FilterRegion:      filter.Region,
		FilterSectors:     filter.Sectors,
		DateFrom:          filter.After.Format("2006-01-02"),
		DateTo:            filter.Before.Format("2006-01-02"),
		TotalArticles:     len(articles),
		ActivityBreakdown: make(map[string]int),
		RegionBreakdown:   make(map[string]int),
		SectorBreakdown:   make(map[string]int),
	}

	// Load actor descriptions for display
	actorDescs, _ := s.db.LoadActorDescriptions()

	// Group articles by actor
	type actorBucket struct {
		articles []store.CachedArticle
		sumScore float64
	}
	actorMap := make(map[string]*actorBucket)
	var totalScore float64
	var ungrouped []store.CachedArticle

	for _, a := range articles {
		actor := scorer.NormalizeThreatActor(a.ThreatActor)
		actor = scorer.DisplayActorName(actor, actorNaming)
		activity := scorer.NormalizeActivity(a.ActivityType)
		region := scorer.NormalizeRegion(a.Region)
		if region == "" {
			region = "Globalt"
		}
		sector := scorer.NormalizeSector(a.Sector)

		// Global stats
		totalScore += a.Score
		if a.Verified {
			rd.VerifiedCount++
		}
		if activity != "" {
			rd.ActivityBreakdown[activity]++
		}
		if region != "" {
			rd.RegionBreakdown[region]++
		}
		if sector != "" {
			rd.SectorBreakdown[sector]++
		}

		// Group by actor (or collect ungrouped)
		if actor != "" {
			bucket, ok := actorMap[actor]
			if !ok {
				bucket = &actorBucket{}
				actorMap[actor] = bucket
			}
			bucket.articles = append(bucket.articles, a)
			bucket.sumScore += a.Score
		} else {
			// Unattributed DDoS articles get a synthetic bucket for likelihood ranking
			if activity == "DDoS" {
				const syntheticDDoS = "Okänd DDoS-aktör"
				bucket, ok := actorMap[syntheticDDoS]
				if !ok {
					bucket = &actorBucket{}
					actorMap[syntheticDDoS] = bucket
				}
				bucket.articles = append(bucket.articles, a)
				bucket.sumScore += a.Score
			}
			ungrouped = append(ungrouped, a)
		}
	}

	if rd.TotalArticles > 0 {
		rd.AvgScore = totalScore / float64(rd.TotalArticles)
	}

	// Build actor sections, sorted by importance (based on stats page scatter logic).
	// Per-article relevance = freshness + scope + novelty + verified + geo bonus.
	// Actor maxRelevance = max(articleRelevance) + activityBonus + hotBonus + freqSpread.
	// Importance = maxRelevance × avg(maxSeverity, maxRelevance), weighting relevance
	// higher than pure sev×rel so campaign actors rank above single high-sev articles.
	type actorSort struct {
		name       string
		importance float64
	}
	// Use report end date as reference for freshness (not time.Now())
	refTime := filter.Before
	if refTime.IsZero() {
		refTime = time.Now()
	}
	// Freshness lookup table (mirrors stats page _FRESH)
	freshTable := [][2]float64{
		{0, 0.75}, {3, 0.68}, {6, 0.6}, {12, 0.5}, {24, 0.4},
		{48, 0.33}, {72, 0.28}, {96, 0.23}, {120, 0.19}, {144, 0.15},
		{168, 0.13}, {336, 0.06}, {720, 0.025}, {2160, 0},
	}
	freshness := func(hours float64) float64 {
		if hours <= 0 {
			return freshTable[0][1]
		}
		for i := 1; i < len(freshTable); i++ {
			if hours <= freshTable[i][0] {
				h0, v0 := freshTable[i-1][0], freshTable[i-1][1]
				h1, v1 := freshTable[i][0], freshTable[i][1]
				return v0 + (v1-v0)*(hours-h0)/(h1-h0)
			}
		}
		return 0
	}
	// Compute per-article relevance (mirrors stats computeRelevance)
	articleRelevance := func(a store.CachedArticle) float64 {
		rel := 0.0
		// Freshness (0–0.75)
		pub := parsePublished(a.Published)
		if !pub.IsZero() {
			hours := refTime.Sub(pub).Hours()
			if hours < 0 {
				hours = 0
			}
			rel += freshness(hours)
		}
		// Scope: 1-5 → 0.5–2.5
		scope := a.Scope
		if scope < 1 {
			scope = 1
		}
		rel += float64(scope) * 0.5
		// Novelty: 1-3 → 0.5–1.5
		novelty := a.Novelty
		if novelty < 1 {
			novelty = 1
		}
		rel += float64(novelty) * 0.5
		// Verified: +1.5
		if a.Verified {
			rel += 1.5
		}
		// Geographic bonus when region filter is active (+2.5 for match)
		if filter.Region != "" {
			region := scorer.NormalizeRegion(a.Region)
			if region == filter.Region {
				// Direct region match
				rel += 2.5
			} else {
				// Matched via country→region or parent region or Globalt
				// Check if any country maps to the target region
				for _, c := range strings.Split(a.Country, ",") {
					c = strings.TrimSpace(c)
					if c == "" {
						continue
					}
					if scorer.MatchRegion("", c, filter.Region) {
						rel += 2.5
						break
					}
				}
			}
		}
		if rel > 10 {
			rel = 10
		}
		return rel
	}
	var sorted []actorSort
	for name, b := range actorMap {
		var maxSeverity, maxRel float64
		var recent7d, recent48h int
		for _, a := range b.articles {
			if a.Severity > maxSeverity {
				maxSeverity = a.Severity
			}
			// Fallback: use score if severity is 0
			if maxSeverity == 0 && a.Score > maxSeverity {
				maxSeverity = a.Score
			}
			rel := articleRelevance(a)
			if rel > maxRel {
				maxRel = rel
			}
			pub := parsePublished(a.Published)
			if !pub.IsZero() {
				hours := refTime.Sub(pub).Hours()
				if hours < 7*24 {
					recent7d++
				}
				if hours < 48 {
					recent48h++
				}
			}
		}
		// Activity bonus: log2(recent7d + 1) * 0.85, max 2.0
		activityBonus := math.Min(2.0, math.Log2(float64(recent7d)+1)*0.85)
		// Hot campaign bonus: 3+ in 48h = +0.5, 2 = +0.25
		var hotBonus float64
		if recent48h >= 3 {
			hotBonus = 0.5
		} else if recent48h >= 2 {
			hotBonus = 0.25
		}
		// Frequency spread (breaks ties for actors with many articles)
		freqSpread := math.Min(0.3, float64(len(b.articles))*0.03)
		maxRelevance := math.Min(10, maxRel+activityBonus+hotBonus+freqSpread)
		// Importance = maxRelevance × avg(maxSeverity, maxRelevance).
		// This weights relevance more than pure sev×rel, so campaign actors
		// (high relevance, moderate severity) rank above single high-sev articles.
		importance := maxRelevance * (maxSeverity + maxRelevance) / 2.0
		sorted = append(sorted, actorSort{name, importance})
	}
	// Sort descending
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].importance > sorted[i].importance {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	// Filter out synthetic DDoS bucket from severity ranking
	const syntheticDDoS = "Okänd DDoS-aktör"
	var sortedSeverity []actorSort
	for _, s := range sorted {
		if s.name != syntheticDDoS {
			sortedSeverity = append(sortedSeverity, s)
		}
	}

	if depth != "executive" {
		// Tactical/technical: limit to top 20
		if len(sortedSeverity) > 20 {
			sortedSeverity = sortedSeverity[:20]
		}
		sorted = sortedSeverity
	}

	// Executive depth: build compact ExecData and return early
	if depth == "executive" {
		if len(sortedSeverity) > 5 {
			sortedSeverity = sortedSeverity[:5]
		}

		// Compute likelihood ranking (includes synthetic DDoS bucket)
		var allCounts []int
		for _, b := range actorMap {
			allCounts = append(allCounts, len(b.articles))
		}
		sort.Ints(allCounts)
		p95 := float64(allCounts[len(allCounts)-1])
		if len(allCounts) >= 20 {
			idx := int(float64(len(allCounts)) * 0.95)
			if idx >= len(allCounts) {
				idx = len(allCounts) - 1
			}
			p95 = float64(allCounts[idx])
		}
		if p95 < 1 {
			p95 = 1
		}

		periodDaysForLikelihood := int(filter.Before.Sub(filter.After).Hours() / 24)
		if periodDaysForLikelihood < 1 {
			periodDaysForLikelihood = 30
		}

		type likelihoodSort struct {
			name  string
			score float64
		}
		var sortedLikelihood []likelihoodSort
		for name, b := range actorMap {
			ls := computeLikelihood(b.articles, likelihoodWeights, refTime, periodDaysForLikelihood, filter.Region, p95)
			sortedLikelihood = append(sortedLikelihood, likelihoodSort{name, ls})
		}
		sort.Slice(sortedLikelihood, func(i, j int) bool {
			return sortedLikelihood[i].score > sortedLikelihood[j].score
		})
		if len(sortedLikelihood) > 5 {
			sortedLikelihood = sortedLikelihood[:5]
		}
		// Load previous period for comparison
		periodDays := int(filter.Before.Sub(filter.After).Hours() / 24)
		if periodDays < 1 {
			periodDays = 30
		}
		prevFilter := store.ReportFilter{
			Actor:    filter.Actor,
			Sectors:  filter.Sectors,
			MinScore: filter.MinScore,
			After:    filter.After.AddDate(0, 0, -periodDays),
			Before:   filter.After,
		}
		prevAll, _ := s.db.LoadFilteredArticles(prevFilter)
		var prevArticles []store.CachedArticle
		if filter.Region != "" {
			for _, a := range prevAll {
				if scorer.MatchRegion(a.Region, a.Country, filter.Region) {
					prevArticles = append(prevArticles, a)
				}
			}
		} else {
			prevArticles = prevAll
		}

		currentStats := computePeriodStats(articles)
		prevStats := computePeriodStats(prevArticles)

		// Volume trend
		volumeTrend := 0.0
		if prevStats.Articles > 0 {
			volumeTrend = float64(currentStats.Articles-prevStats.Articles) / float64(prevStats.Articles)
		}
		if volumeTrend > 1 {
			volumeTrend = 1
		}
		if volumeTrend < -1 {
			volumeTrend = -1
		}

		level, color := computeThreatLevel(currentStats, prevStats, volumeTrend)

		// Weekly buckets
		weeks := bucketByWeek(articles)

		// Sparkline data (pad to at least a few points)
		var sparkArticles, sparkVerified, sparkSeverity, sparkActors []float64
		var weekLabels []string
		for _, w := range weeks {
			sparkArticles = append(sparkArticles, float64(w.ArticleCount))
			if w.ArticleCount > 0 {
				sparkVerified = append(sparkVerified, float64(w.VerifiedCount)/float64(w.ArticleCount)*100)
				sparkSeverity = append(sparkSeverity, w.SumSeverity/float64(w.ArticleCount))
			} else {
				sparkVerified = append(sparkVerified, 0)
				sparkSeverity = append(sparkSeverity, 0)
			}
			sparkActors = append(sparkActors, float64(len(w.ActorSet)))
			// Week label: "v" + ISO week number
			t, _ := time.Parse("2006-01-02", w.WeekStart)
			_, wn := t.ISOWeek()
			weekLabels = append(weekLabels, fmt.Sprintf("v%d", wn))
		}

		// Metric cards
		pctDelta := func(curr, prev float64) (float64, string) {
			if prev == 0 {
				if curr == 0 {
					return 0, "—"
				}
				return 100, "—"
			}
			d := (curr - prev) / prev * 100
			return d, fmt.Sprintf("%+.0f%%", d)
		}
		absDelta := func(curr, prev int) (float64, string) {
			if prev == 0 {
				return 0, "—"
			}
			d := float64(curr-prev) / float64(prev) * 100
			return d, fmt.Sprintf("%+d", curr-prev)
		}

		artDelta, artDeltaAbs := absDelta(currentStats.Articles, prevStats.Articles)
		verDelta, verDeltaAbs := pctDelta(currentStats.VerifiedPct, prevStats.VerifiedPct)
		sevDelta, sevDeltaAbs := pctDelta(currentStats.AvgSeverity, prevStats.AvgSeverity)
		actDelta, actDeltaAbs := absDelta(currentStats.ActiveActors, prevStats.ActiveActors)

		metrics := [4]MetricCard{
			{Label: "Artiklar", Value: fmt.Sprintf("%d", currentStats.Articles), Delta: artDelta, DeltaAbs: artDeltaAbs, Sparkline: sparkArticles, UpIsBad: true},
			{Label: "Verifierade", Value: fmt.Sprintf("%.0f%%", currentStats.VerifiedPct), Delta: verDelta, DeltaAbs: verDeltaAbs, Sparkline: sparkVerified, UpIsBad: false},
			{Label: "Allvarlighet", Value: fmt.Sprintf("%.1f", currentStats.AvgSeverity), Delta: sevDelta, DeltaAbs: sevDeltaAbs, Sparkline: sparkSeverity, UpIsBad: true},
			{Label: "Aktörer", Value: fmt.Sprintf("%d", currentStats.ActiveActors), Delta: actDelta, DeltaAbs: actDeltaAbs, Sparkline: sparkActors, UpIsBad: true},
		}

		// Previous period actor counts for trend comparison
		prevActorCounts := make(map[string]int)
		for _, a := range prevArticles {
			actor := scorer.NormalizeThreatActor(a.ThreatActor)
			actor = scorer.DisplayActorName(actor, actorNaming)
			if actor != "" {
				prevActorCounts[actor]++
			}
		}

		// Build ExecActor from a bucket
		makeExecActor := func(name string, bucket *actorBucket, likelihoodScore float64) ExecActor {
			ea := ExecActor{
				Name:            name,
				ArticleCount:    len(bucket.articles),
				Trend:           actorTrend(len(bucket.articles), prevActorCounts[name]),
				LikelihoodScore: likelihoodScore,
			}
			if desc, ok := actorDescs[name]; ok {
				ea.Description = desc
			}
			activitiesSet := make(map[string]bool)
			regionsSet := make(map[string]bool)
			sectorsSet := make(map[string]bool)
			daySet := make(map[string]bool)
			var sumSev float64
			var latestPub time.Time
			for _, a := range bucket.articles {
				if ea.Type == "" {
					ea.Type = scorer.NormalizeActorType(a.ActorType)
				}
				act := scorer.NormalizeActivity(a.ActivityType)
				if act != "" {
					activitiesSet[act] = true
				}
				reg := scorer.NormalizeRegion(a.Region)
				if reg != "" {
					regionsSet[reg] = true
				}
				sec := scorer.NormalizeSector(a.Sector)
				if sec != "" {
					sectorsSet[sec] = true
				}
				sumSev += a.Severity
				pub := parsePublished(a.Published)
				if !pub.IsZero() {
					daySet[pub.Format("2006-01-02")] = true
					if pub.After(latestPub) {
						latestPub = pub
					}
				}
			}
			for k := range activitiesSet {
				ea.Activities = append(ea.Activities, k)
			}
			for k := range regionsSet {
				ea.Regions = append(ea.Regions, k)
			}
			for k := range sectorsSet {
				ea.Sectors = append(ea.Sectors, k)
			}
			if len(bucket.articles) > 0 {
				ea.AvgSeverity = sumSev / float64(len(bucket.articles))
			}
			if !latestPub.IsZero() {
				ea.LastSeen = latestPub.Format("2006-01-02")
			}
			ea.ActiveDays = len(daySet)
			if name == syntheticDDoS {
				ea.Type = "Hacktivist"
			}
			return ea
		}

		// Top actors by severity
		var topSeverity []ExecActor
		for _, as := range sortedSeverity {
			topSeverity = append(topSeverity, makeExecActor(as.name, actorMap[as.name], 0))
		}

		// Top actors by likelihood
		var topLikelihood []ExecActor
		for _, ls := range sortedLikelihood {
			topLikelihood = append(topLikelihood, makeExecActor(ls.name, actorMap[ls.name], ls.score))
		}

		// Activity trends per week (exclude "Sårbarhet" from executive view — it's CVE noise, not threat activity)
		excludeActivity := map[string]bool{"Sårbarhet": true}
		allActivities := make(map[string]bool)
		for _, w := range weeks {
			for act := range w.ActivityCounts {
				if !excludeActivity[act] {
					allActivities[act] = true
				}
			}
		}
		var actNames []string
		for act := range allActivities {
			actNames = append(actNames, act)
		}
		// Sort by total count descending
		totalByAct := make(map[string]int)
		for _, w := range weeks {
			for act, cnt := range w.ActivityCounts {
				totalByAct[act] += cnt
			}
		}
		sort.Slice(actNames, func(i, j int) bool {
			return totalByAct[actNames[i]] > totalByAct[actNames[j]]
		})
		// Limit to top 8 activity types
		if len(actNames) > 8 {
			actNames = actNames[:8]
		}
		var actTrends []ActivityTrend
		for _, act := range actNames {
			at := ActivityTrend{Type: act}
			for _, w := range weeks {
				at.Weeks = append(at.Weeks, w.ActivityCounts[act])
			}
			actTrends = append(actTrends, at)
		}

		// Build filtered breakdown excluding non-threat activity types
		execBreakdown := make(map[string]int)
		for act, cnt := range rd.ActivityBreakdown {
			if !excludeActivity[act] {
				execBreakdown[act] = cnt
			}
		}
		summary := generateThreatSummary(currentStats, execBreakdown, filter.Region)
		assessments := generateAssessments(topSeverity, currentStats, prevStats, execBreakdown)

		rd.Exec = &ExecData{
			ThreatLevel:         level,
			ThreatColor:         color,
			ThreatSummary:       summary,
			Metrics:             metrics,
			TopActorsSeverity:   topSeverity,
			TopActorsLikelihood: topLikelihood,
			WeekLabels:          weekLabels,
			ActivityTrends:      actTrends,
			Assessments:         assessments,
		}

		return rd, nil
	}

	for _, as := range sorted {
		bucket := actorMap[as.name]
		ra := ReportActor{
			Name:         as.name,
			ArticleCount: len(bucket.articles),
		}

		if desc, ok := actorDescs[as.name]; ok {
			ra.Description = desc
		}

		activitiesSet := make(map[string]bool)
		regionsSet := make(map[string]bool)
		sectorsSet := make(map[string]bool)
		ttpCount := make(map[string]int)
		cvesSet := make(map[string]bool)
		var sumScore float64

		for _, a := range bucket.articles {
			actorType := scorer.NormalizeActorType(a.ActorType)
			activity := scorer.NormalizeActivity(a.ActivityType)
			region := scorer.NormalizeRegion(a.Region)
			if region == "" {
				region = "Globalt"
			}
			country := scorer.NormalizeCountry(a.Country)
			sector := scorer.NormalizeSector(a.Sector)
			sumScore += a.Score

			if ra.Type == "" && actorType != "" {
				ra.Type = actorType
			}
			if ra.Aliases == "" && a.ThreatActorAliases != "" {
				ra.Aliases = a.ThreatActorAliases
			}
			if activity != "" {
				activitiesSet[activity] = true
			}
			if region != "" {
				regionsSet[region] = true
			}
			if sector != "" {
				sectorsSet[sector] = true
			}

			// Build article for report
			rart := ReportArticle{
				Title:        a.Title,
				Link:         a.Link,
				Source:       a.Source,
				Published:    a.Published,
				Score:        a.Score,
				Severity:     a.Severity,
				Verified:     a.Verified,
				Summary:      a.Summary,
				ActivityType: activity,
				Country:      country,
				Region:       region,
				Sector:       sector,
				Impact:       a.Impact,
			}

			if depth != "executive" {
				rart.Detail = a.Detail
				rart.TTPs = a.TTPs

				// Collect TTPs
				for _, ttp := range strings.FieldsFunc(a.TTPs, func(r rune) bool {
					return r == ',' || r == '\n'
				}) {
					ttp = strings.TrimSpace(ttp)
					if ttp != "" {
						ttpCount[ttp]++
					}
				}

				// Collect CVEs
				if a.CVEs != "" {
					var cveList []string
					json.Unmarshal([]byte(a.CVEs), &cveList)
					for _, cve := range cveList {
						cvesSet[cve] = true
					}
					rart.CVEs = cveList
				}
			}

			if depth == "technical" {
				// Parse attack chain
				if a.AttackChain != "" {
					var chain []scorer.AttackChainStep
					json.Unmarshal([]byte(a.AttackChain), &chain)
					rart.AttackChain = chain
				}
				// Load IOCs for this article
				iocs, _ := s.db.LoadIOCsForArticle(a.Link)
				rart.IOCs = iocs
			}

			ra.Articles = append(ra.Articles, rart)
		}

		ra.AvgScore = sumScore / float64(len(bucket.articles))

		for act := range activitiesSet {
			ra.Activities = append(ra.Activities, act)
		}
		for reg := range regionsSet {
			ra.Regions = append(ra.Regions, reg)
		}
		for sec := range sectorsSet {
			ra.Sectors = append(ra.Sectors, sec)
		}

		if depth != "executive" {
			// Build sorted TTP list
			for ttpID, count := range ttpCount {
				name := scorer.LookupTechnique(ttpID)
				if name == "" {
					name = ttpID
				}
				ra.TTPs = append(ra.TTPs, ReportTTP{ID: ttpID, Name: name, Count: count})
			}
			// Sort TTPs by count desc
			for i := 0; i < len(ra.TTPs); i++ {
				for j := i + 1; j < len(ra.TTPs); j++ {
					if ra.TTPs[j].Count > ra.TTPs[i].Count {
						ra.TTPs[i], ra.TTPs[j] = ra.TTPs[j], ra.TTPs[i]
					}
				}
			}
			for cve := range cvesSet {
				ra.CVEs = append(ra.CVEs, cve)
			}
		}

		if depth == "technical" {
			// Load all IOCs for the actor
			iocs, _ := s.db.LoadIOCsForActor(ra.Name)
			ra.IOCs = iocs
		}

		rd.Actors = append(rd.Actors, ra)
	}

	// Build ungrouped articles (no known actor), limited to top 50 by score
	limit := len(ungrouped)
	if limit > 50 {
		limit = 50
	}
	for _, a := range ungrouped[:limit] {
		activity := scorer.NormalizeActivity(a.ActivityType)
		region := scorer.NormalizeRegion(a.Region)
		if region == "" {
			region = "Globalt"
		}
		country := scorer.NormalizeCountry(a.Country)
		sector := scorer.NormalizeSector(a.Sector)

		rart := ReportArticle{
			Title:        a.Title,
			Link:         a.Link,
			Source:       a.Source,
			Published:    a.Published,
			Score:        a.Score,
			Severity:     a.Severity,
			Verified:     a.Verified,
			Summary:      a.Summary,
			ActivityType: activity,
			Country:      country,
			Region:       region,
			Sector:       sector,
			Impact:       a.Impact,
		}
		if depth != "executive" {
			rart.Detail = a.Detail
			rart.TTPs = a.TTPs
			if a.CVEs != "" {
				var cveList []string
				json.Unmarshal([]byte(a.CVEs), &cveList)
				rart.CVEs = cveList
			}
		}
		rd.UngroupedArticles = append(rd.UngroupedArticles, rart)
	}

	return rd, nil
}

func (s *Server) buildBriefData(filter store.ReportFilter, daysBack int) (*BriefData, error) {
	articles, err := s.db.LoadFilteredArticles(filter)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	actorNaming := s.cfg.ActorNaming
	s.mu.RUnlock()

	bd := &BriefData{
		DaysBack: daysBack,
		DateFrom: filter.After.Format("2006-01-02"),
		DateTo:   filter.Before.Format("2006-01-02"),
	}

	activityMap := make(map[string]int)
	type actorBucket struct {
		actorType  string
		count      int
		activities map[string]bool
	}
	actorBuckets := make(map[string]*actorBucket)
	var sumSeverity float64

	for _, a := range articles {
		sumSeverity += a.Severity
		if a.Verified {
			bd.VerifiedCount++
		}

		activity := scorer.NormalizeActivity(a.ActivityType)
		actor := scorer.NormalizeThreatActor(a.ThreatActor)
		if actor != "" {
			actor = scorer.DisplayActorName(actor, actorNaming)
		}
		actorType := scorer.NormalizeActorType(a.ActorType)

		if activity != "" {
			activityMap[activity]++
		}

		if actor != "" {
			b, ok := actorBuckets[actor]
			if !ok {
				b = &actorBucket{actorType: actorType, activities: make(map[string]bool)}
				actorBuckets[actor] = b
			}
			b.count++
			if activity != "" {
				b.activities[activity] = true
			}
		}
	}

	bd.TotalArticles = len(articles)
	if len(articles) > 0 {
		bd.AvgSeverity = sumSeverity / float64(len(articles))
	}

	// Top articles (already sorted by score DESC)
	topN := 15
	if len(articles) < topN {
		topN = len(articles)
	}
	for _, a := range articles[:topN] {
		actor := scorer.NormalizeThreatActor(a.ThreatActor)
		if actor != "" {
			actor = scorer.DisplayActorName(actor, actorNaming)
		}
		bd.TopArticles = append(bd.TopArticles, BriefArticle{
			Title:        a.Title,
			Link:         a.Link,
			Summary:      a.Summary,
			Score:        a.Score,
			Verified:     a.Verified,
			ThreatActor:  actor,
			ActorType:    scorer.NormalizeActorType(a.ActorType),
			ActivityType: scorer.NormalizeActivity(a.ActivityType),
			Region:       scorer.NormalizeRegion(a.Region),
			Sector:       scorer.NormalizeSector(a.Sector),
			Published:    a.Published,
			Source:        a.Source,
		})
	}

	// Active actors sorted by article count desc
	type actorSort struct {
		name string
		b    *actorBucket
	}
	var actors []actorSort
	for name, b := range actorBuckets {
		actors = append(actors, actorSort{name, b})
	}
	sort.Slice(actors, func(i, j int) bool {
		return actors[i].b.count > actors[j].b.count
	})
	for _, as := range actors {
		var activities []string
		for act := range as.b.activities {
			activities = append(activities, act)
		}
		sort.Strings(activities)
		bd.ActiveActors = append(bd.ActiveActors, BriefActor{
			Name:         as.name,
			Type:         as.b.actorType,
			ArticleCount: as.b.count,
			Activities:   activities,
		})
	}

	// Activity breakdown sorted desc
	total := 0
	for _, c := range activityMap {
		total += c
	}
	type actPair struct {
		label string
		count int
	}
	var actPairs []actPair
	for label, count := range activityMap {
		actPairs = append(actPairs, actPair{label, count})
	}
	sort.Slice(actPairs, func(i, j int) bool {
		return actPairs[i].count > actPairs[j].count
	})
	for _, ap := range actPairs {
		pct := 0.0
		if total > 0 {
			pct = float64(ap.count) / float64(total) * 100
		}
		bd.ActivityBreakdown = append(bd.ActivityBreakdown, BriefBreakdownItem{
			Label:   ap.label,
			Count:   ap.count,
			Percent: pct,
		})
	}

	// Summary
	stats := computePeriodStats(articles)
	bd.Summary = generateThreatSummary(stats, activityMap, "")

	return bd, nil
}
