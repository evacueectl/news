package scorer

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	mitreSTIXURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
	mitreCacheTTL = 24 * time.Hour
)

// MITREData holds parsed ATT&CK data for actor and technique lookups.
type MITREData struct {
	// ActorAliases maps lowercased alias → canonical actor name
	ActorAliases map[string]string
	// Techniques maps technique ID (e.g. "T1566") → technique name
	Techniques map[string]string
	// ActorTechniques maps canonical actor name → list of technique IDs
	ActorTechniques map[string][]string
	LoadedAt        time.Time
}

// stixBundle is the top-level STIX 2.1 bundle.
type stixBundle struct {
	Objects []json.RawMessage `json:"objects"`
}

// stixObject has the fields we care about from STIX objects.
type stixObject struct {
	Type               string           `json:"type"`
	ID                 string           `json:"id"`
	Name               string           `json:"name"`
	Aliases            []string         `json:"aliases"`
	ExternalReferences []stixExternalRef `json:"external_references"`
	SourceRef          string           `json:"source_ref"`
	TargetRef          string           `json:"target_ref"`
	RelationshipType   string           `json:"relationship_type"`
	Revoked            bool             `json:"revoked"`
	Deprecated         bool             `json:"x_mitre_deprecated"`
}

type stixExternalRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

var (
	mitreData     *MITREData
	mitreMu       sync.RWMutex
	mitreInitOnce sync.Once
)

// GetMITREData returns the current MITRE ATT&CK data, loading if needed.
func GetMITREData() *MITREData {
	mitreMu.RLock()
	d := mitreData
	mitreMu.RUnlock()
	if d != nil {
		return d
	}
	return nil
}

// LoadMITREData loads ATT&CK data from cache or downloads fresh.
// cacheDir is typically ~/.newsdigest/
func LoadMITREData(cacheDir string) (*MITREData, error) {
	cachePath := filepath.Join(cacheDir, "mitre-attack.json")

	// Check cache freshness
	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < mitreCacheTTL {
			data, err := loadMITREFromFile(cachePath)
			if err == nil {
				mitreMu.Lock()
				mitreData = data
				mitreMu.Unlock()
				return data, nil
			}
			log.Printf("warning: cached MITRE data corrupted, re-downloading: %v", err)
		}
	}

	// Download fresh
	data, err := downloadAndParseMITRE(cachePath)
	if err != nil {
		// Try stale cache as fallback
		if stale, err2 := loadMITREFromFile(cachePath); err2 == nil {
			log.Printf("warning: MITRE download failed, using stale cache: %v", err)
			mitreMu.Lock()
			mitreData = stale
			mitreMu.Unlock()
			return stale, nil
		}
		return nil, fmt.Errorf("load MITRE data: %w", err)
	}

	mitreMu.Lock()
	mitreData = data
	mitreMu.Unlock()
	return data, nil
}

func downloadAndParseMITRE(cachePath string) (*MITREData, error) {
	log.Printf("downloading MITRE ATT&CK STIX data...")
	resp, err := http.Get(mitreSTIXURL)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Read to temp file first, then parse
	tmpPath := cachePath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("write temp: %w", err)
	}
	f.Close()

	// Parse
	data, err := loadMITREFromFile(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return nil, err
	}

	// Rename to final
	if err := os.Rename(tmpPath, cachePath); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("rename cache: %w", err)
	}

	log.Printf("loaded MITRE ATT&CK: %d actor aliases, %d techniques",
		len(data.ActorAliases), len(data.Techniques))
	return data, nil
}

func loadMITREFromFile(path string) (*MITREData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return parseMITRESTIX(f)
}

// parseMITRESTIX parses a STIX 2.1 bundle and extracts actor aliases and techniques.
func parseMITRESTIX(r io.Reader) (*MITREData, error) {
	dec := json.NewDecoder(r)

	// Read opening brace
	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("read start: %w", err)
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("expected {, got %v", t)
	}

	data := &MITREData{
		ActorAliases:    make(map[string]string),
		Techniques:      make(map[string]string),
		ActorTechniques: make(map[string][]string),
		LoadedAt:        time.Now(),
	}

	// Maps for relationship resolution
	idToActorName := make(map[string]string)    // STIX ID → canonical name
	idToTechniqueID := make(map[string]string)   // STIX ID → technique external ID
	type rel struct{ actorID, techID string }
	var relationships []rel

	// Stream through top-level keys
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		keyStr, ok := key.(string)
		if !ok {
			continue
		}

		if keyStr != "objects" {
			// Skip non-objects fields
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, err
			}
			continue
		}

		// Read objects array
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if delim, ok := t.(json.Delim); !ok || delim != '[' {
			return nil, fmt.Errorf("expected [, got %v", t)
		}

		for dec.More() {
			var obj stixObject
			if err := dec.Decode(&obj); err != nil {
				continue
			}
			if obj.Revoked || obj.Deprecated {
				continue
			}

			switch obj.Type {
			case "intrusion-set":
				processIntrusionSet(data, &obj, idToActorName)
			case "attack-pattern":
				processAttackPattern(data, &obj, idToTechniqueID)
			case "relationship":
				if obj.RelationshipType == "uses" &&
					strings.HasPrefix(obj.SourceRef, "intrusion-set--") &&
					strings.HasPrefix(obj.TargetRef, "attack-pattern--") {
					relationships = append(relationships, rel{obj.SourceRef, obj.TargetRef})
				}
			}
		}
	}

	// Resolve relationships
	for _, r := range relationships {
		actorName := idToActorName[r.actorID]
		techID := idToTechniqueID[r.techID]
		if actorName != "" && techID != "" {
			data.ActorTechniques[actorName] = append(data.ActorTechniques[actorName], techID)
		}
	}

	return data, nil
}

func processIntrusionSet(data *MITREData, obj *stixObject, idMap map[string]string) {
	name := obj.Name
	if name == "" {
		return
	}

	idMap[obj.ID] = name

	// Map all aliases to canonical name
	data.ActorAliases[strings.ToLower(name)] = name
	for _, alias := range obj.Aliases {
		alias = strings.TrimSpace(alias)
		if alias != "" {
			data.ActorAliases[strings.ToLower(alias)] = name
		}
	}

	// Also map external IDs (e.g. "G0007") as aliases
	for _, ref := range obj.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			data.ActorAliases[strings.ToLower(ref.ExternalID)] = name
		}
	}
}

func processAttackPattern(data *MITREData, obj *stixObject, idMap map[string]string) {
	for _, ref := range obj.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			data.Techniques[ref.ExternalID] = obj.Name
			idMap[obj.ID] = ref.ExternalID
			break
		}
	}
}

// LookupActorAlias checks MITRE ATT&CK data for an actor alias.
// Returns canonical name and true if found, empty and false otherwise.
func LookupActorAlias(name string) (string, bool) {
	mitreMu.RLock()
	d := mitreData
	mitreMu.RUnlock()
	if d == nil {
		return "", false
	}
	canonical, ok := d.ActorAliases[strings.ToLower(strings.TrimSpace(name))]
	return canonical, ok
}

// LookupTechnique returns the technique name for a MITRE ATT&CK ID.
func LookupTechnique(id string) string {
	mitreMu.RLock()
	d := mitreData
	mitreMu.RUnlock()
	if d == nil {
		return ""
	}
	return d.Techniques[id]
}

// ActorTechniques returns known MITRE ATT&CK technique IDs for an actor.
func ActorTechniques(actor string) []string {
	mitreMu.RLock()
	d := mitreData
	mitreMu.RUnlock()
	if d == nil {
		return nil
	}
	return d.ActorTechniques[actor]
}
