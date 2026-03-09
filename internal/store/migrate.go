package store

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

// MigrateFromJSON migrates all JSON data files to the SQLite database.
// Renames processed files to .json.migrated.
// Safe to call multiple times — skips if JSON files don't exist.
func MigrateFromJSON(db *DB) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".newsdigest")

	migrated := false

	// Migrate articles.json
	articlesFile := filepath.Join(dir, "articles.json")
	if data, err := os.ReadFile(articlesFile); err == nil && len(data) > 2 {
		var articles []CachedArticle
		if err := json.Unmarshal(data, &articles); err != nil {
			log.Printf("warning: parse articles.json: %v", err)
		} else {
			// Backfill Sources
			for i := range articles {
				if len(articles[i].Sources) == 0 && articles[i].Source != "" {
					articles[i].Sources = []string{articles[i].Source}
				}
			}
			log.Printf("migrating %d articles from JSON to SQLite...", len(articles))
			if err := db.SaveArticles(articles); err != nil {
				return err
			}
			os.Rename(articlesFile, articlesFile+".migrated")
			migrated = true
			log.Printf("migrated %d articles", len(articles))
		}
	}

	// Migrate seen.json
	seenFile := filepath.Join(dir, "seen.json")
	if data, err := os.ReadFile(seenFile); err == nil && len(data) > 2 {
		var seen map[string]time.Time
		if err := json.Unmarshal(data, &seen); err != nil {
			log.Printf("warning: parse seen.json: %v", err)
		} else {
			log.Printf("migrating %d seen entries...", len(seen))
			for url := range seen {
				db.Mark(url)
			}
			os.Rename(seenFile, seenFile+".migrated")
			migrated = true
			log.Printf("migrated %d seen entries", len(seen))
		}
	}

	// Migrate feedback.json
	fbFile := filepath.Join(dir, "feedback.json")
	if data, err := os.ReadFile(fbFile); err == nil && len(data) > 2 {
		var entries []FeedbackEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			log.Printf("warning: parse feedback.json: %v", err)
		} else {
			log.Printf("migrating %d feedback entries...", len(entries))
			for _, e := range entries {
				db.SaveFeedback(e)
			}
			os.Rename(fbFile, fbFile+".migrated")
			migrated = true
		}
	}

	// Migrate syncstatus.json
	ssFile := filepath.Join(dir, "syncstatus.json")
	if data, err := os.ReadFile(ssFile); err == nil && len(data) > 2 {
		var status SyncStatusData
		if err := json.Unmarshal(data, &status); err != nil {
			log.Printf("warning: parse syncstatus.json: %v", err)
		} else {
			db.SaveSyncStatus(&status)
			os.Rename(ssFile, ssFile+".migrated")
			migrated = true
		}
	}

	// Migrate actor-descriptions.json
	adFile := filepath.Join(dir, "actor-descriptions.json")
	if data, err := os.ReadFile(adFile); err == nil && len(data) > 2 {
		var descs map[string]string
		if err := json.Unmarshal(data, &descs); err != nil {
			log.Printf("warning: parse actor-descriptions.json: %v", err)
		} else {
			log.Printf("migrating %d actor descriptions...", len(descs))
			for name, desc := range descs {
				db.SaveActorDescription(name, desc)
			}
			os.Rename(adFile, adFile+".migrated")
			migrated = true
		}
	}

	if migrated {
		log.Println("JSON to SQLite migration complete")
	}
	return nil
}

// NeedsMigration returns true if JSON article data exists but hasn't been migrated.
func NeedsMigration() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	articlesFile := filepath.Join(home, ".newsdigest", "articles.json")
	info, err := os.Stat(articlesFile)
	if err != nil {
		return false
	}
	return info.Size() > 10
}
