package store

// schemaVersion tracks the current DDL version. Bump when schema changes.
const schemaVersion = 2

// schemaDDL contains all CREATE TABLE/INDEX statements for the database.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS articles (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	link            TEXT UNIQUE NOT NULL,
	title           TEXT NOT NULL DEFAULT '',
	normalized_title TEXT NOT NULL DEFAULT '',
	description     TEXT NOT NULL DEFAULT '',
	content         TEXT NOT NULL DEFAULT '',
	source          TEXT NOT NULL DEFAULT '',
	published       TEXT NOT NULL DEFAULT '',
	score           REAL NOT NULL DEFAULT 0,
	severity        REAL NOT NULL DEFAULT 0,
	verified        INTEGER NOT NULL DEFAULT 0,
	scope           INTEGER NOT NULL DEFAULT 0,
	novelty         INTEGER NOT NULL DEFAULT 0,
	summary         TEXT NOT NULL DEFAULT '',
	detail          TEXT NOT NULL DEFAULT '',
	threat_actor    TEXT NOT NULL DEFAULT '',
	threat_actor_aliases TEXT NOT NULL DEFAULT '',
	activity_type   TEXT NOT NULL DEFAULT '',
	actor_type      TEXT NOT NULL DEFAULT '',
	origin          TEXT NOT NULL DEFAULT '',
	country         TEXT NOT NULL DEFAULT '',
	region          TEXT NOT NULL DEFAULT '',
	impact          TEXT NOT NULL DEFAULT '',
	sector          TEXT NOT NULL DEFAULT '',
	ttps            TEXT NOT NULL DEFAULT '',
	score_version   INTEGER NOT NULL DEFAULT 0,
	content_hash    TEXT NOT NULL DEFAULT '',
	created_at      TEXT NOT NULL DEFAULT (datetime('now')),
	-- Fas 2 fields stored as JSON in article row for simplicity
	attack_chain    TEXT NOT NULL DEFAULT '[]',
	cves            TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_articles_score ON articles(score);
CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published);
CREATE INDEX IF NOT EXISTS idx_articles_normalized_title ON articles(normalized_title);
CREATE INDEX IF NOT EXISTS idx_articles_content_hash ON articles(content_hash);
CREATE INDEX IF NOT EXISTS idx_articles_threat_actor ON articles(threat_actor);
CREATE INDEX IF NOT EXISTS idx_articles_score_version ON articles(score_version);

CREATE TABLE IF NOT EXISTS article_sources (
	article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
	source     TEXT NOT NULL,
	PRIMARY KEY (article_id, source)
);

CREATE TABLE IF NOT EXISTS seen (
	url        TEXT PRIMARY KEY,
	first_seen TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS feedback (
	id    INTEGER PRIMARY KEY AUTOINCREMENT,
	url   TEXT NOT NULL DEFAULT '',
	title TEXT NOT NULL DEFAULT '',
	vote  TEXT NOT NULL DEFAULT '',
	time  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sync_status (
	id           INTEGER PRIMARY KEY CHECK (id = 1),
	last_run     TEXT NOT NULL DEFAULT '',
	fetched      INTEGER NOT NULL DEFAULT 0,
	new_articles INTEGER NOT NULL DEFAULT 0,
	scored       INTEGER NOT NULL DEFAULT 0,
	duration     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS feed_status (
	name      TEXT PRIMARY KEY,
	url       TEXT NOT NULL DEFAULT '',
	articles  INTEGER NOT NULL DEFAULT 0,
	error     TEXT NOT NULL DEFAULT '',
	last_sync TEXT NOT NULL DEFAULT '',
	last_data TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS actor_descriptions (
	name        TEXT PRIMARY KEY,
	description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS pending_channels (
	username      TEXT PRIMARY KEY,
	discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
	mention_count INTEGER NOT NULL DEFAULT 0,
	status        TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS iocs (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	value           TEXT NOT NULL,
	type            TEXT NOT NULL,
	source          TEXT NOT NULL DEFAULT '',
	threat_actor    TEXT NOT NULL DEFAULT '',
	malware_family  TEXT NOT NULL DEFAULT '',
	confidence      INTEGER NOT NULL DEFAULT 50,
	first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
	last_seen       TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_value_type ON iocs(value, type);
CREATE INDEX IF NOT EXISTS idx_iocs_threat_actor ON iocs(threat_actor);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);

CREATE TABLE IF NOT EXISTS article_iocs (
	article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
	ioc_id     INTEGER NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
	PRIMARY KEY (article_id, ioc_id)
);
`
