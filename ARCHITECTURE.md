# Architecture — News Digest

## Overview

News Digest is a cybersecurity threat intelligence aggregator that ingests articles from ~76 RSS feeds, Telegram channels, DDoSia snapshots, and Cloudflare Radar. Articles pass through a two-stage LLM scoring pipeline (triage + enrichment) and are presented in a glassmorphism web UI in Swedish.

## Package Dependency Graph

```
main.go
├── config      Load/save YAML configuration
├── feed        Fetch articles from all source types
├── scorer      Two-stage LLM scoring pipeline
├── store       SQLite database (~/.newsdigest/newsdigest.db)
├── sync        Orchestrates fetch → dedup → score → cache → prune → rescore
└── web         HTTP server, templates, REST API
     ├── config
     ├── scorer    (actor naming conversion)
     ├── store
     └── sync      (trigger sync, read progress)
```

No package imports another cyclically. `feed` and `scorer` define the core data types (`Article`, `ScoredArticle`) consumed downstream.

---

## Data Flow

```
 ┌─────────────────────────────────────────────────┐
 │                  SOURCES                        │
 │  RSS/Atom (70+)  │  JSON APIs  │  Telegram (23) │
 │  Cloudflare Radar │  DDoSia    │  CISA KEV      │
 └────────────┬────────────────────────────────────┘
              │ feed.FetchAllDetailed() — max 10 concurrent
              ▼
       ┌──────────────┐
       │  []Article    │  Title, Link, Description, Published, Source
       └──────┬───────┘
              │ store.IsNew(link) — URL-based dedup
              ▼
       ┌──────────────┐
       │  New articles │
       └──────┬───────┘
              │
   ┌──────────┴──────────┐
   │  STAGE 1: TRIAGE     │  Haiku · batch 50 · 3 concurrent
   │  severity, verified,  │
   │  scope, novelty,      │
   │  activity_type,       │
   │  summary              │
   └──────────┬───────────┘
              │ computeScore()
              │   severity×0.65 + verified×0.5 + scope×0.25 + novelty×0.35
              │   clamped [1, 10]
              ▼
   ┌──────────────────────┐
   │  STAGE 2: ENRICH      │  Configurable model · batch 30 · 3 concurrent
   │  (only severity ≥ 5)  │  detail, threat_actor, aliases, actor_type,
   │                        │  origin, country, region, impact, sector, TTPs
   └──────────┬───────────┘
              │ profileBoost()
              │   +0.75–2.0 region/country match
              │   +0.5 sector match
              ▼
       ┌──────────────┐
       │ ScoredArticle │
       └──────┬───────┘
              │ store.DB.SaveArticles() — upsert into SQLite
              ▼
       ~/.newsdigest/newsdigest.db
              │
              │ web.Server.ReloadArticles()
              ▼
       ┌──────────────┐
       │  Web UI (/)   │  Filtering, sorting, detail expansion
       └──────────────┘
```

---

## Packages in Detail

### `config` — Configuration

**File:** `internal/config/config.go`

Loads and saves `config.yaml`. Key types:

| Type | Fields |
|------|--------|
| `Config` | Feeds, Profile, Model, EnrichModel, TopN, MinScore, Listen, APIKey, OTXApiKey, CloudflareKey, TelegramAPIID/Hash, TelegramChannels, FetchWindow, AutoSync, SyncInterval, ActorNaming, DefaultTags |
| `Feed` | Name, URL |
| `Profile` | Role, Interests, Sectors, Regions |
| `TelegramChannel` | Name, Username |
| `TagSet` | Regions, Sectors, Activities |

Defaults: Haiku for triage, 7-day fetch window, listen on `127.0.0.1:8080`, 360 min sync interval.

---

### `feed` — Source Ingestion

**Files:** `internal/feed/feed.go`, `internal/feed/telegram.go`

Fetches articles from multiple source types and normalizes them to a common `Article` struct.

**Source types and their parsers:**

| Source | Parser | Notes |
|--------|--------|-------|
| RSS/Atom | `gofeed` | Standard feed parsing |
| Telegram (preview) | Regex HTML scraper | `t.me/s/<channel>` public preview pages |
| Telegram (MTProto) | `gotd/td` library | Full message history, requires auth |
| AlienVault OTX | JSON API | Paginated pulse API (up to 5 pages) |
| ThreatFox | JSON API | abuse.ch malware IOC feed |
| Ransomware.live | JSON API | Victim list (v1+v2 field support) |
| RansomLook | JSON API | Alternative ransomware victim list |
| CISA KEV | JSON API | Known Exploited Vulnerabilities (14 days) |
| DDoSia | JSON snapshots | Historical target lists from witha.name |
| Cloudflare Radar | REST API | DDoS top target/source countries |

**Concurrency:** `FetchAllDetailed()` uses a semaphore (max 10 goroutines). HTTP client: 100 idle connections, 2 per host, 90s timeout.

**Normalization:** 15+ date formats, HTML stripping, ~50 country ISO→Swedish mappings.

---

### `scorer` — LLM Scoring Pipeline

**File:** `internal/scorer/scorer.go`

Two-stage pipeline using the Anthropic API.

**`CurrentScoreVersion = 6`** — bumped when prompt logic changes, triggers automatic rescore.

#### Stage 1: Triage

- **Model:** Haiku (fast, cheap)
- **Batch:** 50 articles, 3 concurrent batches
- **Input:** title + description + source + recent feedback
- **Output:** `severity` (1–10), `verified` (bool), `scope` (1–5), `novelty` (1–3), `activity_type`, `summary`
- **DDoS rules:** Unconfirmed Telegram claims = max 3, confirmed downtime = 5–6, critical infra = 7+

#### Score Formula

```
score = clamp(1, 10, severity×0.65 + verified×0.5 + scope×0.25 + novelty×0.35)
```

#### Stage 2: Enrich

- **Model:** Configurable (can be Opus for quality)
- **Filter:** Only articles with `severity ≥ 5`
- **Batch:** 30 articles, 3 concurrent batches
- **Output:** `detail`, `threat_actor`, `threat_actor_aliases`, `actor_type`, `origin`, `country`, `region`, `impact`, `sector`, `TTPs`

#### Stage 3: Profile Boost

| Match | Boost |
|-------|-------|
| Region (generic) | +0.75 |
| Region (Norden) | +1.5 |
| Country (direct) | +2.0 |
| Sector | +0.5 |

Final score clamped to [1, 10].

#### Normalization

All enum values are normalized to canonical forms:

- **ActivityType:** 10 values — Ransomware, Phishing, Malware, Sårbarhet, Dataläcka, DDoS, Supply chain, Intrång, Spionage, Defacement
- **ActorType:** 4 values — Statlig, Kriminell, Hacktivist, Forskare
- **Region:** 10 values — Norden, Europa, Östeuropa, Nordamerika, Sydamerika, Asien, Mellanöstern, Afrika, Oceanien, Globalt
- **Sector:** 18 NIS2 sectors (Energi, Transporter, Bankverksamhet, …)
- **ThreatActor:** ~150 canonical names mapped from aliases (MITRE/Mandiant standard)

#### Retry Logic

`retryAPICall`: max 3 attempts, exponential backoff (2s, 4s). Retries on HTTP 429, 529, 5xx only.

---

### `store` — Persistent Storage

**Files:** `internal/store/db.go`, `internal/store/store.go`

SQLite database in `~/.newsdigest/newsdigest.db` (WAL mode). Auto-migrates from legacy JSON files on first run.

**Tables:**

| Table | Content |
|-------|---------|
| `articles` | Scored articles with all triage/enrich fields |
| `seen` | Dedup registry (content hash → timestamp) |
| `feedback` | User up/down votes |
| `feed_status` | Last sync result per feed |
| `actor_descriptions` | LLM-generated actor descriptions |

**Dedup strategies:**
1. **Content hash:** `ContentHash(title, link)` checked against `seen` table
2. **Source consolidation:** Merges `Sources` when duplicate detected

**Rescore detection** (`NeedsRescore`): triggers if `ScoreVersion` < current, or if severity/summary/activity_type/region/country are missing.

**RecalcScores:** SQL-based score recalculation when formula changes (no API calls). Must mirror `computeScore()` exactly.

---

### `sync` — Sync Engine

**File:** `internal/sync/sync.go`

Orchestrates the full pipeline. The `Run()` method executes these phases:

1. **Fetch** — all configured sources (concurrent)
2. **Dedup** — filter against `seen` table (content hash)
3. **Score** — triage → enrich → profileBoost
4. **Cache** — upsert into SQLite, mark seen
5. **Prune** — remove old/unlisted articles
6. **Rescore** — re-score incomplete articles (unless `--no-rescore`)
7. **Telegram discovery** — scan for new channels mentioned in articles

**Progress tracking:** Thread-safe `SyncProgress` struct with phases: `fetching → triage → enrich → rescoring → done`. Polled by the web UI via `/api/sync/progress`.

---

### `web` — HTTP Server

**File:** `internal/web/web.go`

Serves the UI and REST API using Go's `net/http`.

#### HTML Routes

| Path | Template | Description |
|------|----------|-------------|
| `/` | `digest.html` | Main article feed with filtering and sorting |
| `/stats` | `stats.html` | Threat actor cards, scatter plot, world heat map |
| `/actor` | `actor.html` | Threat actor profile pages |
| `/feeds` | `feeds.html` | Feed management and sync status |
| `/settings` | `settings.html` | Score threshold, model, sync interval |

#### REST API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/feeds` | List configured feeds |
| PUT | `/api/feeds` | Update feed list, save to config |
| POST | `/api/sync` | Trigger manual sync |
| GET | `/api/sync/progress` | Current sync progress (polling) |
| GET | `/api/settings` | Get settings |
| PUT | `/api/settings` | Update settings |
| POST | `/feedback` | Save up/down vote |
| POST | `/api/actor-description` | Get or generate actor description |

#### Templates

All templates are embedded via `go:embed`. Template hierarchy:

```
base.css.html          {{ define "basecss" }}    Shared glassmorphism styles
worldmap.svg.html      {{ define "worldmap" }}   SVG map (179 countries, ISO alpha-2 IDs)

digest.html            {{ template "basecss" }}
stats.html             {{ template "basecss" }}  {{ template "worldmap" }}
actor.html             {{ template "basecss" }}
feeds.html             {{ template "basecss" }}
settings.html          {{ template "basecss" }}
```

No build pipeline — JS and CSS are inlined in each template.

#### UI Features

- **Filtering:** date range, activity type, sector, country, region, actor type, threat actor
- **Sorting:** latest (date), score (severity×0.6 + relevance×0.4), source
- **Score pill:** red (≥8), orange (5–7), gray (<5)
- **Verified indicator:** green ✓ (confirmed) or gray ? (unverified claim)
- **i18n:** Swedish (default) / English toggle via `localStorage`
- **Filter presets:** saved/loaded from `localStorage`
- **Auto-sync:** background goroutine with configurable interval

---

## Threat Actor Naming

Three naming conventions are supported, switchable via settings:

| MITRE (default) | Microsoft | CrowdStrike |
|-----------------|-----------|-------------|
| APT28 | Forest Blizzard | Fancy Bear |
| APT29 | Midnight Blizzard | Cozy Bear |
| APT41 | Brass Typhoon | Wicked Panda |
| Lazarus Group | Diamond Sleet | Labyrinth Chollima |
| Sandworm | Seashell Blizzard | Voodoo Bear |
| Kimsuky | Emerald Sleet | Velvet Chollima |

Ransomware and DDoS groups use their own names regardless of convention.

---

## Design Patterns

| Pattern | Where | Why |
|---------|-------|-----|
| SQLite WAL mode | `store` | Concurrent read/write without locking |
| Batch API (≥10 articles) | `scorer` | 50% cost reduction via Anthropic Message Batches |
| Semaphore concurrency | `feed`, `scorer` | Bounded parallelism for HTTP/API calls |
| Version-driven rescore | `scorer` → `store` → `sync` | Prompt changes automatically propagate |
| Fuzzy title dedup | `store` | Cross-feed syndication creates near-duplicates |
| Feedback calibration | `scorer` | Recent user votes influence triage severity |
| Progress polling | `sync` → `web` | Real-time sync status in the UI |
| Profile-based boosting | `scorer` | Personalized relevance without retraining |

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `-config <path>` | Config file (default: `config.yaml`) |
| `-fetch-only` | Fetch and score, print to stdout, no server |
| `-no-rescore` | Skip rescoring incomplete articles during sync |
| `-rescore` | Re-score articles with missing fields, then exit |
| `-rescore-all` | Full rescore of all articles, then exit |
| `-dev` | Dev mode: reload templates from disk on every request |
| `-telegram-auth <phone>` | Authenticate Telegram MTProto session |
