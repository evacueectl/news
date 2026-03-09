# News Digest — Cybersäkerhets-TI-aggregator

## Vad projektet är

Personligt verktyg som aggregerar cybersäkerhetsnyheter från ~76 RSS-feeds, Telegram-kanaler, DDoSia-data och Cloudflare Radar. Artiklar scoras med Claude (Haiku för triage, konfigurerbar modell för enrichment) och presenteras i ett glassmorphism-webbgränssnitt på svenska.

## Kommandon

```bash
go build ./...          # Bygg
go test ./...           # Tester
go run main.go          # Starta server (port 8080)
go run main.go -dev     # Dev mode (template hot-reload)
go run main.go -fetch-only   # Hämta + scora, skriv till stdout
go run main.go -rescore-all  # Omscora alla artiklar
```

## Arkitektur

```
main.go                     CLI-entrypoint, flags, startar server + sync-loop
internal/
  config/                   YAML-konfiguration (config.yaml)
  feed/                     RSS/Atom-parsning, Telegram MTProto, DDoSia, Cloudflare
  scorer/                   LLM-scoring: triage → enrich → profileBoost
  store/                    SQLite-databas (~/.newsdigest/newsdigest.db)
  sync/                     Sync-motor: fetch → dedup → score → cache → prune → rescore
  web/                      HTTP-server, templates, API-endpoints
    templates/              HTML-templates (digest, stats, actor, feeds, settings)
```

### Scoring-pipeline

1. **Triage** (Haiku, batch 50, 3 concurrent): severity, verified, scope, novelty, activity_type, summary
2. **Enrich** (konfigurerbar modell, batch 15, 3 concurrent): detail, threat_actor, country, sector, TTPs
3. **computeScore**: `severity×0.65 + verified×0.5 + scope×0.25 + novelty×0.35` (clamp 1–10). Severity dominerar, verified ger moderat boost (ej bimodalt gap). Vid formeländring recalcas alla scores via SQL (ingen LLM-anrop behövs).

### ScoreVersion

`CurrentScoreVersion` (i scorer.go) bumpas när promptlogik ändras. Artiklar med gammal version rescoras automatiskt vid nästa sync.

### Data

SQLite-databas i `~/.newsdigest/newsdigest.db` (WAL mode). Tabeller: `articles`, `seen`, `feedback`, `feed_status`, `actor_descriptions`. Auto-migrering från äldre JSON-filer vid uppstart.

## Konventioner

- **Språk**: UI och LLM-prompter på svenska. Kod och kommentarer på engelska.
- **Normalisering**: Alla enum-värden (activity_type, actor_type, region, sector) normaliseras i scorer.go. Hotaktörsnamn mappas till MITRE/Mandiant-standard.
- **Templates**: HTML med inlined JS/CSS. `base.css.html` inkluderas som shared partial. Ingen byggpipeline.
- **Ingen ORM**: Direkt SQLite via `database/sql` med WAL mode. Inga ORMs.
- **Retry**: API-anrop till Anthropic wrappas i retryAPICall (max 3 försök, exponentiell backoff, bara på 429/529/5xx).

## Regler vid ändringar

- Kör `go build ./...` efter varje ändring.
- Ändra inte scoring-formeln utan att uppdatera `CurrentScoreVersion`.
- Promptändringar i `buildTriagePrompt`/`buildEnrichPrompt` kräver också versionsbump.
- Lägg aldrig API-nycklar eller secrets i kod — de hör hemma i config.yaml.
- Templates använder `esc()` för alla dynamiska värden i HTML-attribut.
