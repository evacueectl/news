package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database for article storage.
type DB struct {
	db   *sql.DB
	mu   sync.Mutex // serializes writes
	path string
}

// Path returns the database file path.
func (d *DB) Path() string { return d.path }

// OpenDB opens (or creates) the SQLite database at path.
func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Apply schema
	if _, err := db.Exec(schemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// Check/set schema version and run migrations
	var currentVersion int
	db.QueryRow("SELECT COUNT(*) FROM schema_version").Scan(&currentVersion)
	if currentVersion == 0 {
		db.Exec("INSERT INTO schema_version (version) VALUES (?)", schemaVersion)
	} else {
		db.QueryRow("SELECT version FROM schema_version LIMIT 1").Scan(&currentVersion)
		if currentVersion < schemaVersion {
			migrateSchema(db, currentVersion)
			db.Exec("UPDATE schema_version SET version = ?", schemaVersion)
		}
	}
	return &DB{db: db, path: path}, nil
}

// migrateSchema applies incremental migrations between schema versions.
func migrateSchema(db *sql.DB, from int) {
	if from < 2 {
		// v2: added iocs + article_iocs tables, status column on pending_channels
		db.Exec("ALTER TABLE pending_channels ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
	}
}

// Close closes the database.
func (d *DB) Close() error {
	return d.db.Close()
}

// ContentHash computes a dedup hash from normalized title + link domain.
func ContentHash(title, link string) string {
	nt := NormalizeTitle(title)
	domain := extractDomain(link)
	h := sha256.Sum256([]byte(nt + "|" + domain))
	return fmt.Sprintf("%x", h[:16])
}

func extractDomain(link string) string {
	// Strip protocol
	u := link
	if idx := strings.Index(u, "://"); idx >= 0 {
		u = u[idx+3:]
	}
	// Strip path
	if idx := strings.IndexByte(u, '/'); idx >= 0 {
		u = u[:idx]
	}
	return strings.ToLower(u)
}

// SaveArticles upserts articles into the database, merging sources for duplicates.
func (d *DB) SaveArticles(articles []CachedArticle) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsertStmt, err := tx.Prepare(`
		INSERT INTO articles (
			link, title, normalized_title, description, content, source, published,
			score, severity, verified, scope, novelty,
			summary, detail, threat_actor, threat_actor_aliases,
			activity_type, actor_type, origin, country, region,
			impact, sector, ttps, score_version, content_hash,
			attack_chain, cves
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(link) DO UPDATE SET
			title = CASE WHEN excluded.score > articles.score THEN excluded.title ELSE articles.title END,
			normalized_title = CASE WHEN excluded.score > articles.score THEN excluded.normalized_title ELSE articles.normalized_title END,
			description = CASE WHEN excluded.score > articles.score THEN excluded.description ELSE articles.description END,
			content = CASE WHEN articles.content = '' THEN excluded.content ELSE articles.content END,
			score = CASE WHEN excluded.score > articles.score THEN excluded.score ELSE articles.score END,
			severity = CASE WHEN excluded.score > articles.score THEN excluded.severity ELSE articles.severity END,
			verified = CASE WHEN excluded.score > articles.score THEN excluded.verified ELSE articles.verified END,
			scope = CASE WHEN excluded.score > articles.score THEN excluded.scope ELSE articles.scope END,
			novelty = CASE WHEN excluded.score > articles.score THEN excluded.novelty ELSE articles.novelty END,
			summary = CASE WHEN excluded.score > articles.score THEN excluded.summary ELSE articles.summary END,
			detail = CASE WHEN excluded.score > articles.score THEN excluded.detail ELSE articles.detail END,
			threat_actor = CASE WHEN excluded.score > articles.score THEN excluded.threat_actor ELSE articles.threat_actor END,
			threat_actor_aliases = CASE WHEN excluded.score > articles.score THEN excluded.threat_actor_aliases ELSE articles.threat_actor_aliases END,
			activity_type = CASE WHEN excluded.score > articles.score THEN excluded.activity_type ELSE articles.activity_type END,
			actor_type = CASE WHEN excluded.score > articles.score THEN excluded.actor_type ELSE articles.actor_type END,
			origin = CASE WHEN excluded.score > articles.score THEN excluded.origin ELSE articles.origin END,
			country = CASE WHEN excluded.score > articles.score THEN excluded.country ELSE articles.country END,
			region = CASE WHEN excluded.score > articles.score THEN excluded.region ELSE articles.region END,
			impact = CASE WHEN excluded.score > articles.score THEN excluded.impact ELSE articles.impact END,
			sector = CASE WHEN excluded.score > articles.score THEN excluded.sector ELSE articles.sector END,
			ttps = CASE WHEN excluded.score > articles.score THEN excluded.ttps ELSE articles.ttps END,
			score_version = CASE WHEN excluded.score > articles.score THEN excluded.score_version ELSE articles.score_version END,
			content_hash = CASE WHEN excluded.score > articles.score THEN excluded.content_hash ELSE articles.content_hash END,
			attack_chain = CASE WHEN excluded.score > articles.score THEN excluded.attack_chain ELSE articles.attack_chain END,
			cves = CASE WHEN excluded.score > articles.score THEN excluded.cves ELSE articles.cves END
	`)
	if err != nil {
		return err
	}
	defer upsertStmt.Close()

	sourceStmt, err := tx.Prepare(`INSERT OR IGNORE INTO article_sources (article_id, source) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer sourceStmt.Close()

	getIDStmt, err := tx.Prepare(`SELECT id FROM articles WHERE link = ?`)
	if err != nil {
		return err
	}
	defer getIDStmt.Close()

	for _, a := range articles {
		nt := NormalizeTitle(a.Title)
		ch := ContentHash(a.Title, a.Link)
		verified := 0
		if a.Verified {
			verified = 1
		}
		attackChain := "[]"
		if a.AttackChain != "" {
			attackChain = a.AttackChain
		}
		cves := "[]"
		if a.CVEs != "" {
			cves = a.CVEs
		}

		_, err := upsertStmt.Exec(
			a.Link, a.Title, nt, a.Description, a.Content, a.Source, a.Published,
			a.Score, a.Severity, verified, a.Scope, a.Novelty,
			a.Summary, a.Detail, a.ThreatActor, a.ThreatActorAliases,
			a.ActivityType, a.ActorType, a.Origin, a.Country, a.Region,
			a.Impact, a.Sector, a.TTPs, a.ScoreVersion, ch,
			attackChain, cves,
		)
		if err != nil {
			log.Printf("warning: upsert article %q: %v", a.Link, err)
			continue
		}

		// Get article ID for sources
		var id int64
		if err := getIDStmt.QueryRow(a.Link).Scan(&id); err != nil {
			continue
		}

		// Insert sources
		sources := a.Sources
		if len(sources) == 0 && a.Source != "" {
			sources = []string{a.Source}
		}
		for _, src := range sources {
			if src != "" {
				sourceStmt.Exec(id, src)
			}
		}
	}

	return tx.Commit()
}

// articleColumns is the SELECT column list shared by article queries.
const articleColumns = `a.id, a.link, a.title, a.description, a.content, a.source, a.published,
	a.score, a.severity, a.verified, a.scope, a.novelty,
	a.summary, a.detail, a.threat_actor, a.threat_actor_aliases,
	a.activity_type, a.actor_type, a.origin, a.country, a.region,
	a.impact, a.sector, a.ttps, a.score_version,
	a.attack_chain, a.cves`

// scanArticleRows scans rows into CachedArticle slice, attaching sources from sourceMap.
func scanArticleRows(rows *sql.Rows, sourceMap map[int64][]string) ([]CachedArticle, error) {
	var articles []CachedArticle
	for rows.Next() {
		var a CachedArticle
		var id int64
		var verified int
		var attackChain, cves string
		err := rows.Scan(
			&id, &a.Link, &a.Title, &a.Description, &a.Content, &a.Source, &a.Published,
			&a.Score, &a.Severity, &verified, &a.Scope, &a.Novelty,
			&a.Summary, &a.Detail, &a.ThreatActor, &a.ThreatActorAliases,
			&a.ActivityType, &a.ActorType, &a.Origin, &a.Country, &a.Region,
			&a.Impact, &a.Sector, &a.TTPs, &a.ScoreVersion,
			&attackChain, &cves,
		)
		if err != nil {
			log.Printf("warning: scan article: %v", err)
			continue
		}
		a.Verified = verified != 0
		a.AttackChain = attackChain
		a.CVEs = cves
		if sources, ok := sourceMap[id]; ok {
			a.Sources = sources
		} else if a.Source != "" {
			a.Sources = []string{a.Source}
		}
		articles = append(articles, a)
	}
	return articles, rows.Err()
}

// LoadArticles returns all cached articles, ordered by score descending.
func (d *DB) LoadArticles() ([]CachedArticle, error) {
	rows, err := d.db.Query(`SELECT ` + articleColumns + ` FROM articles a ORDER BY a.score DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sourceMap, err := d.loadAllSources()
	if err != nil {
		log.Printf("warning: load sources: %v", err)
		sourceMap = make(map[int64][]string)
	}

	return scanArticleRows(rows, sourceMap)
}

// ReportFilter specifies criteria for loading articles for reports.
type ReportFilter struct {
	Actor    string
	Region   string
	Sectors  []string
	MinScore float64
	After    time.Time
	Before   time.Time
}

// LoadFilteredArticles returns articles matching the filter, ordered by score DESC.
func (d *DB) LoadFilteredArticles(f ReportFilter) ([]CachedArticle, error) {
	var clauses []string
	var args []interface{}

	if f.Actor != "" {
		clauses = append(clauses, "a.threat_actor = ?")
		args = append(args, f.Actor)
	}
	// Region filtering is done in Go via scorer.MatchRegion to mirror the
	// stats page logic (parent-child regions + country-to-region matching).
	if len(f.Sectors) > 0 {
		ph := make([]string, len(f.Sectors))
		for i, s := range f.Sectors {
			ph[i] = "?"
			args = append(args, s)
		}
		clauses = append(clauses, "a.sector IN ("+strings.Join(ph, ",")+")")
	}
	if f.MinScore > 0 {
		clauses = append(clauses, "a.score >= ?")
		args = append(args, f.MinScore)
	}
	if !f.After.IsZero() {
		clauses = append(clauses, "a.published >= ?")
		args = append(args, f.After.Format("2006-01-02"))
	}
	if !f.Before.IsZero() {
		// Use < day+1 to include articles published on the Before date with time components
		// (e.g. "2026-02-28T14:00" would fail a string <= "2026-02-28" comparison)
		clauses = append(clauses, "a.published < ?")
		args = append(args, f.Before.AddDate(0, 0, 1).Format("2006-01-02"))
	}

	query := `SELECT ` + articleColumns + ` FROM articles a`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY a.score DESC"

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sourceMap, err := d.loadAllSources()
	if err != nil {
		log.Printf("warning: load sources: %v", err)
		sourceMap = make(map[int64][]string)
	}

	return scanArticleRows(rows, sourceMap)
}

func (d *DB) loadAllSources() (map[int64][]string, error) {
	rows, err := d.db.Query(`SELECT article_id, source FROM article_sources ORDER BY article_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := make(map[int64][]string)
	for rows.Next() {
		var id int64
		var src string
		if err := rows.Scan(&id, &src); err != nil {
			continue
		}
		m[id] = append(m[id], src)
	}
	return m, rows.Err()
}

// OverwriteArticles replaces all articles (used by rescore).
func (d *DB) OverwriteArticles(articles []CachedArticle) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete all existing
	tx.Exec("DELETE FROM article_sources")
	tx.Exec("DELETE FROM articles")

	// Re-insert all
	stmt, err := tx.Prepare(`
		INSERT INTO articles (
			link, title, normalized_title, description, content, source, published,
			score, severity, verified, scope, novelty,
			summary, detail, threat_actor, threat_actor_aliases,
			activity_type, actor_type, origin, country, region,
			impact, sector, ttps, score_version, content_hash,
			attack_chain, cves
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	sourceStmt, err := tx.Prepare(`INSERT OR IGNORE INTO article_sources (article_id, source) VALUES (?, ?)`)
	if err != nil {
		return err
	}
	defer sourceStmt.Close()

	for _, a := range articles {
		nt := NormalizeTitle(a.Title)
		ch := ContentHash(a.Title, a.Link)
		verified := 0
		if a.Verified {
			verified = 1
		}
		attackChain := "[]"
		if a.AttackChain != "" {
			attackChain = a.AttackChain
		}
		cves := "[]"
		if a.CVEs != "" {
			cves = a.CVEs
		}

		res, err := stmt.Exec(
			a.Link, a.Title, nt, a.Description, a.Content, a.Source, a.Published,
			a.Score, a.Severity, verified, a.Scope, a.Novelty,
			a.Summary, a.Detail, a.ThreatActor, a.ThreatActorAliases,
			a.ActivityType, a.ActorType, a.Origin, a.Country, a.Region,
			a.Impact, a.Sector, a.TTPs, a.ScoreVersion, ch,
			attackChain, cves,
		)
		if err != nil {
			log.Printf("warning: insert article %q: %v", a.Link, err)
			continue
		}
		id, _ := res.LastInsertId()
		sources := a.Sources
		if len(sources) == 0 && a.Source != "" {
			sources = []string{a.Source}
		}
		for _, src := range sources {
			if src != "" {
				sourceStmt.Exec(id, src)
			}
		}
	}

	return tx.Commit()
}

// NeedsRescoreList returns articles that need rescoring.
func (d *DB) NeedsRescoreList(currentVersion int) ([]CachedArticle, error) {
	rows, err := d.db.Query(`
		SELECT a.id, a.link, a.title, a.description, a.content, a.source, a.published,
			a.score, a.severity, a.verified, a.scope, a.novelty,
			a.summary, a.detail, a.threat_actor, a.threat_actor_aliases,
			a.activity_type, a.actor_type, a.origin, a.country, a.region,
			a.impact, a.sector, a.ttps, a.score_version,
			a.attack_chain, a.cves
		FROM articles a
		WHERE a.score_version != ?
			OR a.severity <= 0
			OR a.summary = ''
			OR a.activity_type = ''
			OR a.region = ''
			OR a.country = ''
	`, currentVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sourceMap, _ := d.loadAllSources()
	if sourceMap == nil {
		sourceMap = make(map[int64][]string)
	}

	var articles []CachedArticle
	for rows.Next() {
		var a CachedArticle
		var id int64
		var verified int
		var attackChain, cves string
		err := rows.Scan(
			&id, &a.Link, &a.Title, &a.Description, &a.Content, &a.Source, &a.Published,
			&a.Score, &a.Severity, &verified, &a.Scope, &a.Novelty,
			&a.Summary, &a.Detail, &a.ThreatActor, &a.ThreatActorAliases,
			&a.ActivityType, &a.ActorType, &a.Origin, &a.Country, &a.Region,
			&a.Impact, &a.Sector, &a.TTPs, &a.ScoreVersion,
			&attackChain, &cves,
		)
		if err != nil {
			continue
		}
		a.Verified = verified != 0
		a.AttackChain = attackChain
		a.CVEs = cves
		if sources, ok := sourceMap[id]; ok {
			a.Sources = sources
		}
		articles = append(articles, a)
	}
	return articles, rows.Err()
}

// PruneArticles removes articles from feeds not in activeSources.
func (d *DB) PruneArticles(activeSources ...string) (kept, removed int, err error) {
	if len(activeSources) == 0 {
		return 0, 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get total count
	var total int
	d.db.QueryRow("SELECT COUNT(*) FROM articles").Scan(&total)

	// Build placeholders
	placeholders := make([]string, len(activeSources))
	args := make([]interface{}, len(activeSources))
	for i, s := range activeSources {
		placeholders[i] = "?"
		args[i] = s
	}
	inClause := strings.Join(placeholders, ",")

	// Delete articles where neither source nor any article_source is in the active set
	_, err = d.db.Exec(fmt.Sprintf(`
		DELETE FROM articles WHERE id NOT IN (
			SELECT DISTINCT a.id FROM articles a
			LEFT JOIN article_sources s ON s.article_id = a.id
			WHERE a.source IN (%s) OR s.source IN (%s)
		)
	`, inClause, inClause), append(args, args...)...)
	if err != nil {
		return 0, 0, err
	}

	// Clean orphaned sources
	d.db.Exec("DELETE FROM article_sources WHERE article_id NOT IN (SELECT id FROM articles)")

	var remaining int
	d.db.QueryRow("SELECT COUNT(*) FROM articles").Scan(&remaining)
	return remaining, total - remaining, nil
}

// IsNew returns true if the URL has not been seen before.
func (d *DB) IsNew(url string) bool {
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM seen WHERE url = ?", url).Scan(&count)
	return count == 0
}

// Mark records a URL as seen.
func (d *DB) Mark(url string) {
	d.db.Exec("INSERT OR IGNORE INTO seen (url) VALUES (?)", url)
}

// PruneSeen removes seen entries older than maxAge.
func (d *DB) PruneSeen(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge).UTC().Format(time.RFC3339)
	d.db.Exec("DELETE FROM seen WHERE first_seen < ?", cutoff)
}

// SaveFeedback appends a feedback entry, keeping last 200.
func (d *DB) SaveFeedback(entry FeedbackEntry) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("INSERT INTO feedback (url, title, vote, time) VALUES (?, ?, ?, ?)",
		entry.URL, entry.Title, entry.Vote, entry.Time)
	if err != nil {
		return err
	}
	// Keep last 200
	d.db.Exec(`DELETE FROM feedback WHERE id NOT IN (SELECT id FROM feedback ORDER BY id DESC LIMIT 200)`)
	return nil
}

// LoadFeedback returns all feedback entries.
func (d *DB) LoadFeedback() ([]FeedbackEntry, error) {
	rows, err := d.db.Query("SELECT url, title, vote, time FROM feedback ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []FeedbackEntry
	for rows.Next() {
		var e FeedbackEntry
		if err := rows.Scan(&e.URL, &e.Title, &e.Vote, &e.Time); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// SaveSyncStatus saves the sync status (single row, upserted).
func (d *DB) SaveSyncStatus(status *SyncStatusData) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tx.Exec(`INSERT INTO sync_status (id, last_run, fetched, new_articles, scored, duration)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_run = excluded.last_run,
			fetched = excluded.fetched,
			new_articles = excluded.new_articles,
			scored = excluded.scored,
			duration = excluded.duration`,
		status.LastRun, status.Fetched, status.New, status.Scored, status.Duration)

	// Save per-feed status
	tx.Exec("DELETE FROM feed_status")
	stmt, err := tx.Prepare("INSERT INTO feed_status (name, url, articles, error, last_sync, last_data) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range status.Feeds {
		stmt.Exec(f.Name, f.URL, f.Articles, f.Error, f.LastSync, f.LastData)
	}

	return tx.Commit()
}

// LoadSyncStatus loads the sync status.
func (d *DB) LoadSyncStatus() (*SyncStatusData, error) {
	status := &SyncStatusData{}
	err := d.db.QueryRow("SELECT last_run, fetched, new_articles, scored, duration FROM sync_status WHERE id = 1").
		Scan(&status.LastRun, &status.Fetched, &status.New, &status.Scored, &status.Duration)
	if err == sql.ErrNoRows {
		return &SyncStatusData{}, nil
	}
	if err != nil {
		return &SyncStatusData{}, nil
	}

	rows, err := d.db.Query("SELECT name, url, articles, error, last_sync, last_data FROM feed_status")
	if err != nil {
		return status, nil
	}
	defer rows.Close()
	for rows.Next() {
		var f FeedSyncStatus
		if err := rows.Scan(&f.Name, &f.URL, &f.Articles, &f.Error, &f.LastSync, &f.LastData); err != nil {
			continue
		}
		status.Feeds = append(status.Feeds, f)
	}
	return status, nil
}

// LoadActorDescriptions returns all cached actor descriptions.
func (d *DB) LoadActorDescriptions() (map[string]string, error) {
	rows, err := d.db.Query("SELECT name, description FROM actor_descriptions")
	if err != nil {
		return make(map[string]string), nil
	}
	defer rows.Close()
	m := make(map[string]string)
	for rows.Next() {
		var name, desc string
		if err := rows.Scan(&name, &desc); err != nil {
			continue
		}
		m[name] = desc
	}
	return m, nil
}

// SaveActorDescription saves an actor description.
func (d *DB) SaveActorDescription(name, description string) error {
	_, err := d.db.Exec(`INSERT INTO actor_descriptions (name, description) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET description = excluded.description`, name, description)
	return err
}

// AddPendingChannel adds or updates a pending Telegram channel.
func (d *DB) AddPendingChannel(username string, mentionCount int) error {
	_, err := d.db.Exec(`INSERT INTO pending_channels (username, mention_count) VALUES (?, ?)
		ON CONFLICT(username) DO UPDATE SET mention_count = mention_count + excluded.mention_count`,
		username, mentionCount)
	return err
}

// PendingChannels returns all pending channels.
func (d *DB) PendingChannels() ([]PendingChannel, error) {
	rows, err := d.db.Query("SELECT username, discovered_at, mention_count, status FROM pending_channels ORDER BY mention_count DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var channels []PendingChannel
	for rows.Next() {
		var ch PendingChannel
		if err := rows.Scan(&ch.Username, &ch.DiscoveredAt, &ch.MentionCount, &ch.Status); err != nil {
			continue
		}
		channels = append(channels, ch)
	}
	return channels, nil
}

// FlagPendingChannel marks a channel as flagged (e.g., unreachable during revalidation).
func (d *DB) FlagPendingChannel(username string) error {
	_, err := d.db.Exec("UPDATE pending_channels SET status = 'flagged' WHERE username = ?", username)
	return err
}

// RemovePendingChannel removes a pending channel (approved or dismissed).
func (d *DB) RemovePendingChannel(username string) error {
	_, err := d.db.Exec("DELETE FROM pending_channels WHERE username = ?", username)
	return err
}

// ArticleCount returns the total number of articles.
func (d *DB) ArticleCount() int {
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM articles").Scan(&count)
	return count
}

// UpdateArticle updates a single article's scored fields by link.
func (d *DB) UpdateArticle(a CachedArticle) error {
	verified := 0
	if a.Verified {
		verified = 1
	}
	attackChain := "[]"
	if a.AttackChain != "" {
		attackChain = a.AttackChain
	}
	cves := "[]"
	if a.CVEs != "" {
		cves = a.CVEs
	}
	_, err := d.db.Exec(`
		UPDATE articles SET
			score = ?, severity = ?, verified = ?, scope = ?, novelty = ?,
			summary = ?, detail = ?, threat_actor = ?, threat_actor_aliases = ?,
			activity_type = ?, actor_type = ?, origin = ?, country = ?, region = ?,
			impact = ?, sector = ?, ttps = ?, score_version = ?,
			attack_chain = ?, cves = ?
		WHERE link = ?`,
		a.Score, a.Severity, verified, a.Scope, a.Novelty,
		a.Summary, a.Detail, a.ThreatActor, a.ThreatActorAliases,
		a.ActivityType, a.ActorType, a.Origin, a.Country, a.Region,
		a.Impact, a.Sector, a.TTPs, a.ScoreVersion,
		attackChain, cves,
		a.Link,
	)
	return err
}

// RecalcScores recalculates all article scores using the current formula
// based on existing severity/verified/scope/novelty values.
// This avoids expensive API calls — no LLM needed.
func (d *DB) RecalcScores(targetVersion int) (int64, error) {
	res, err := d.db.Exec(`
		UPDATE articles SET
			score = MIN(10, MAX(1,
				severity * 0.65 +
				verified * 0.5 +
				scope * 0.25 +
				novelty * 0.35
			)),
			score_version = ?
		WHERE score_version != ? OR score != MIN(10, MAX(1,
			severity * 0.65 +
			verified * 0.5 +
			scope * 0.25 +
			novelty * 0.35
		))`, targetVersion, targetVersion)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FeedHealthStatus computes health status for feeds based on feed_status data.
func (d *DB) FeedHealthStatus() (map[string]string, error) {
	rows, err := d.db.Query("SELECT name, error, last_data FROM feed_status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now()
	result := make(map[string]string)
	for rows.Next() {
		var name, errStr, lastData string
		if err := rows.Scan(&name, &errStr, &lastData); err != nil {
			continue
		}
		if errStr != "" {
			result[name] = "failing"
			continue
		}
		if lastData == "" {
			result[name] = "dead"
			continue
		}
		t, err := time.Parse(time.RFC3339, lastData)
		if err != nil {
			result[name] = "dead"
			continue
		}
		age := now.Sub(t)
		switch {
		case age < 48*time.Hour:
			result[name] = "healthy"
		case age < 7*24*time.Hour:
			result[name] = "degraded"
		case age < 14*24*time.Hour:
			result[name] = "failing"
		default:
			result[name] = "dead"
		}
	}
	return result, nil
}

// PendingChannel represents a discovered but not yet approved Telegram channel.
type PendingChannel struct {
	Username     string `json:"username"`
	DiscoveredAt string `json:"discovered_at"`
	MentionCount int    `json:"mention_count"`
	Status       string `json:"status"` // "pending", "flagged"
}

// SaveIOCs upserts IOC entries and links them to an article (by link).
func (d *DB) SaveIOCs(articleLink string, iocs []IOCEntry) error {
	if len(iocs) == 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Get article ID
	var articleID int64
	err = tx.QueryRow("SELECT id FROM articles WHERE link = ?", articleLink).Scan(&articleID)
	if err != nil {
		return fmt.Errorf("article not found: %s", articleLink)
	}

	upsertIOC, err := tx.Prepare(`
		INSERT INTO iocs (value, type, source, threat_actor, malware_family, confidence)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(value, type) DO UPDATE SET
			threat_actor = CASE WHEN excluded.threat_actor != '' THEN excluded.threat_actor ELSE iocs.threat_actor END,
			malware_family = CASE WHEN excluded.malware_family != '' THEN excluded.malware_family ELSE iocs.malware_family END,
			confidence = MAX(iocs.confidence, excluded.confidence),
			last_seen = datetime('now')
	`)
	if err != nil {
		return err
	}
	defer upsertIOC.Close()

	getIOCID, err := tx.Prepare("SELECT id FROM iocs WHERE value = ? AND type = ?")
	if err != nil {
		return err
	}
	defer getIOCID.Close()

	linkStmt, err := tx.Prepare("INSERT OR IGNORE INTO article_iocs (article_id, ioc_id) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer linkStmt.Close()

	for _, ioc := range iocs {
		_, err := upsertIOC.Exec(ioc.Value, ioc.Type, ioc.Source, ioc.ThreatActor, ioc.MalwareFamily, ioc.Confidence)
		if err != nil {
			log.Printf("warning: upsert IOC %q: %v", ioc.Value, err)
			continue
		}
		var iocID int64
		if err := getIOCID.QueryRow(ioc.Value, ioc.Type).Scan(&iocID); err != nil {
			continue
		}
		linkStmt.Exec(articleID, iocID)
	}

	return tx.Commit()
}

// LoadIOCsForActor returns IOCs associated with a threat actor.
func (d *DB) LoadIOCsForActor(actor string) ([]IOCEntry, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT i.id, i.value, i.type, i.source, i.threat_actor,
			i.malware_family, i.confidence, i.first_seen, i.last_seen
		FROM iocs i
		LEFT JOIN article_iocs ai ON ai.ioc_id = i.id
		LEFT JOIN articles a ON a.id = ai.article_id
		WHERE i.threat_actor = ? OR a.threat_actor = ?
		ORDER BY i.last_seen DESC
	`, actor, actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIOCs(rows)
}

// SearchIOCs searches for IOCs by value prefix.
func (d *DB) SearchIOCs(query string) ([]IOCEntry, error) {
	rows, err := d.db.Query(`
		SELECT id, value, type, source, threat_actor,
			malware_family, confidence, first_seen, last_seen
		FROM iocs
		WHERE value LIKE ?
		ORDER BY last_seen DESC
		LIMIT 100
	`, query+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIOCs(rows)
}

// LoadIOCsForArticle returns IOCs linked to a specific article.
func (d *DB) LoadIOCsForArticle(articleLink string) ([]IOCEntry, error) {
	rows, err := d.db.Query(`
		SELECT i.id, i.value, i.type, i.source, i.threat_actor,
			i.malware_family, i.confidence, i.first_seen, i.last_seen
		FROM iocs i
		JOIN article_iocs ai ON ai.ioc_id = i.id
		JOIN articles a ON a.id = ai.article_id
		WHERE a.link = ?
		ORDER BY i.type, i.value
	`, articleLink)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanIOCs(rows)
}

// IOCCount returns the total number of IOCs.
func (d *DB) IOCCount() int {
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM iocs").Scan(&count)
	return count
}

func scanIOCs(rows *sql.Rows) ([]IOCEntry, error) {
	var iocs []IOCEntry
	for rows.Next() {
		var ioc IOCEntry
		err := rows.Scan(&ioc.ID, &ioc.Value, &ioc.Type, &ioc.Source,
			&ioc.ThreatActor, &ioc.MalwareFamily, &ioc.Confidence,
			&ioc.FirstSeen, &ioc.LastSeen)
		if err != nil {
			continue
		}
		iocs = append(iocs, ioc)
	}
	return iocs, rows.Err()
}

// ParseCVEs parses JSON CVE list from string.
func ParseCVEs(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var cves []string
	if err := json.Unmarshal([]byte(s), &cves); err != nil {
		return nil
	}
	return cves
}
