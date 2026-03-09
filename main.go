package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"news/internal/config"
	"news/internal/feed"
	"news/internal/scorer"
	"news/internal/store"
	appSync "news/internal/sync"
	"news/internal/web"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	fetchOnly := flag.Bool("fetch-only", false, "fetch and score, print to stdout, don't serve")
	skipRescore := flag.Bool("no-rescore", false, "skip rescoring incomplete articles during sync")
	rescore := flag.Bool("rescore", false, "re-score articles missing fields or with score 0, then exit")
	rescoreAll := flag.Bool("rescore-all", false, "re-score ALL cached articles (full rescore), then exit")
	telegramAuth := flag.String("telegram-auth", "", "authenticate Telegram with phone number (e.g. +46701234567)")
	devMode := flag.Bool("dev", false, "dev mode: reload templates from disk on every request")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if cfg.APIKey == "" {
		log.Fatal("no API key: set api_key in config or ANTHROPIC_API_KEY env var")
	}

	if *telegramAuth != "" {
		tgCfg := feed.TelegramConfig{
			APIID:   cfg.TelegramAPIID,
			APIHash: cfg.TelegramAPIHash,
		}
		if tgCfg.APIID == 0 || tgCfg.APIHash == "" {
			log.Fatal("telegram_api_id and telegram_api_hash must be set in config")
		}
		if err := feed.AuthTelegram(context.Background(), tgCfg, *telegramAuth); err != nil {
			log.Fatalf("telegram auth: %v", err)
		}
		log.Println("telegram authentication successful")
		return
	}

	// Open SQLite database
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("user home: %v", err)
	}
	dbDir := filepath.Join(home, ".newsdigest")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}
	dbPath := filepath.Join(dbDir, "newsdigest.db")

	db, err := store.OpenDB(dbPath)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer db.Close()

	// Auto-migrate from JSON if needed
	if store.NeedsMigration() {
		log.Println("detected JSON data files, migrating to SQLite...")
		if err := store.MigrateFromJSON(db); err != nil {
			log.Printf("warning: migration error: %v", err)
		}
	}

	// Recalculate scores if formula changed (no API calls needed)
	if affected, err := db.RecalcScores(scorer.CurrentScoreVersion); err != nil {
		log.Printf("warning: score recalculation: %v", err)
	} else if affected > 0 {
		log.Printf("recalculated %d article scores (formula v%d)", affected, scorer.CurrentScoreVersion)
	}

	if *rescore || *rescoreAll {
		doRescore(cfg, db, *rescoreAll)
		return
	}

	engine := &appSync.SyncEngine{
		Cfg:         cfg,
		DB:          db,
		ConfigPath:  *configPath,
		SkipRescore: *skipRescore,
	}

	if *fetchOnly {
		result, err := engine.Run(context.Background())
		if err != nil {
			log.Printf("sync error: %v", err)
		}
		if result != nil {
			filtered := engine.FilteredArticles()
			sort.Slice(filtered, func(i, j int) bool {
				return filtered[i].Score > filtered[j].Score
			})
			for _, a := range filtered {
				fmt.Printf("[%.2f] %s\n", a.Score, a.Title)
				if a.Summary != "" {
					fmt.Printf("    %s\n", a.Summary)
				}
				tags := ""
				if a.Country != "" {
					tags += " [" + a.Country + "]"
				}
				if a.Region != "" {
					tags += " [" + a.Region + "]"
				}
				if a.ThreatActor != "" {
					tags += " [" + a.ThreatActor + "]"
				}
				if a.ActivityType != "" {
					tags += " [" + a.ActivityType + "]"
				}
				if a.ActorType != "" {
					tags += " [" + a.ActorType + "]"
				}
				if tags != "" {
					fmt.Printf("   %s\n", tags)
				}
				fmt.Printf("    %s\n    %s — %s\n\n",
					a.Link, a.Source, a.Published.Format("15:04"))
			}
		}
		return
	}

	feeds := make([]web.FeedEntry, len(cfg.Feeds))
	for i, f := range cfg.Feeds {
		feeds[i] = web.FeedEntry{Name: f.Name, URL: f.URL}
	}

	// Start server immediately with cached data, run sync in background
	server := web.NewServer(cfg, *configPath, engine, feeds, db)
	if *devMode {
		// Find template dir relative to working directory
		tmplDir := filepath.Join("internal", "web", "templates")
		if _, err := os.Stat(tmplDir); err == nil {
			server.SetDevMode(tmplDir)
		} else {
			log.Printf("warning: -dev flag set but %s not found, using embedded templates", tmplDir)
		}
	}
	go func() {
		if _, err := engine.Run(context.Background()); err != nil {
			log.Printf("sync error: %v", err)
		}
	}()
	if err := server.Serve(cfg.Listen); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func doRescore(cfg *config.Config, db *store.DB, all bool) {
	cached, err := db.LoadArticles()
	if err != nil {
		log.Fatalf("load articles: %v", err)
	}
	if len(cached) == 0 {
		log.Fatal("no cached articles to rescore")
	}

	var toRescore []store.CachedArticle
	if all {
		toRescore = cached
	} else {
		for _, a := range cached {
			if store.NeedsRescore(a, scorer.CurrentScoreVersion) {
				toRescore = append(toRescore, a)
			}
		}
	}

	if len(toRescore) == 0 {
		log.Printf("all %d articles already have complete scores, nothing to rescore (use --rescore-all to force)", len(cached))
		return
	}

	log.Printf("rescoring %d of %d articles with %s...", len(toRescore), len(cached), cfg.Model)

	feedback, err := db.LoadFeedback()
	if err != nil {
		log.Printf("warning: load feedback: %v", err)
	}
	recentFeedback := store.RecentFeedback(feedback, 50)

	articles := make([]feed.Article, len(toRescore))
	for i, a := range toRescore {
		t, _ := time.Parse("2006-01-02T15:04", a.Published)
		articles[i] = feed.Article{
			Title:       a.Title,
			Link:        a.Link,
			Description: a.Description,
			Content:     a.Content,
			Source:      a.Source,
			Published:   t,
		}
	}

	start := time.Now()
	scored, err := scorer.Score(context.Background(), cfg, articles, recentFeedback)
	if err != nil {
		log.Fatalf("scorer: %v", err)
	}

	// Update each rescored article
	for i, s := range scored {
		ca := store.CachedArticle{
			Title:              s.Title,
			Link:               s.Link,
			Description:        s.Description,
			Content:            toRescore[i].Content,
			Source:             s.Source,
			Sources:            toRescore[i].Sources,
			Published:          toRescore[i].Published,
			Score:              s.Score,
			Severity:           s.Severity,
			Verified:           s.Verified,
			Scope:              s.Scope,
			Novelty:            s.Novelty,
			Summary:            s.Summary,
			Detail:             s.Detail,
			ThreatActor:        s.ThreatActor,
			ThreatActorAliases: s.ThreatActorAliases,
			ActivityType:       s.ActivityType,
			ActorType:          s.ActorType,
			Origin:             s.Origin,
			Country:            s.Country,
			Region:             s.Region,
			Impact:             s.Impact,
			Sector:             s.Sector,
			TTPs:               s.TTPs,
			ScoreVersion:       scorer.CurrentScoreVersion,
		}
		if err := db.UpdateArticle(ca); err != nil {
			log.Printf("warning: update article: %v", err)
		}
	}

	dur := time.Since(start).Round(time.Second)
	log.Printf("rescore complete: %d rescored, %d kept, %d total in %s",
		len(toRescore), len(cached)-len(toRescore), len(cached), dur)
}
