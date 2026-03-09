package scorer

import (
	"strings"
	"testing"
)

// testSTIXBundle is a minimal STIX 2.1 bundle for testing.
const testSTIXBundle = `{
	"type": "bundle",
	"id": "bundle--test",
	"objects": [
		{
			"type": "intrusion-set",
			"id": "intrusion-set--001",
			"name": "APT28",
			"aliases": ["Fancy Bear", "Sofacy", "Pawn Storm", "Forest Blizzard"],
			"external_references": [
				{"source_name": "mitre-attack", "external_id": "G0007"}
			]
		},
		{
			"type": "intrusion-set",
			"id": "intrusion-set--002",
			"name": "Lazarus Group",
			"aliases": ["Hidden Cobra", "ZINC", "Diamond Sleet"],
			"external_references": [
				{"source_name": "mitre-attack", "external_id": "G0032"}
			]
		},
		{
			"type": "intrusion-set",
			"id": "intrusion-set--revoked",
			"name": "OldGroup",
			"revoked": true
		},
		{
			"type": "attack-pattern",
			"id": "attack-pattern--001",
			"name": "Phishing",
			"external_references": [
				{"source_name": "mitre-attack", "external_id": "T1566"}
			]
		},
		{
			"type": "attack-pattern",
			"id": "attack-pattern--002",
			"name": "Spearphishing Attachment",
			"external_references": [
				{"source_name": "mitre-attack", "external_id": "T1566.001"}
			]
		},
		{
			"type": "attack-pattern",
			"id": "attack-pattern--003",
			"name": "Valid Accounts",
			"external_references": [
				{"source_name": "mitre-attack", "external_id": "T1078"}
			]
		},
		{
			"type": "relationship",
			"id": "relationship--001",
			"relationship_type": "uses",
			"source_ref": "intrusion-set--001",
			"target_ref": "attack-pattern--001"
		},
		{
			"type": "relationship",
			"id": "relationship--002",
			"relationship_type": "uses",
			"source_ref": "intrusion-set--001",
			"target_ref": "attack-pattern--002"
		},
		{
			"type": "relationship",
			"id": "relationship--003",
			"relationship_type": "uses",
			"source_ref": "intrusion-set--002",
			"target_ref": "attack-pattern--003"
		}
	]
}`

func TestParseMITRESTIX(t *testing.T) {
	data, err := parseMITRESTIX(strings.NewReader(testSTIXBundle))
	if err != nil {
		t.Fatalf("parseMITRESTIX: %v", err)
	}

	// Actor aliases
	tests := []struct {
		alias string
		want  string
	}{
		{"apt28", "APT28"},
		{"fancy bear", "APT28"},
		{"sofacy", "APT28"},
		{"pawn storm", "APT28"},
		{"forest blizzard", "APT28"},
		{"g0007", "APT28"},
		{"lazarus group", "Lazarus Group"},
		{"hidden cobra", "Lazarus Group"},
		{"zinc", "Lazarus Group"},
		{"diamond sleet", "Lazarus Group"},
		{"g0032", "Lazarus Group"},
	}

	for _, tt := range tests {
		got, ok := data.ActorAliases[tt.alias]
		if !ok {
			t.Errorf("alias %q not found", tt.alias)
			continue
		}
		if got != tt.want {
			t.Errorf("alias %q = %q, want %q", tt.alias, got, tt.want)
		}
	}

	// Revoked group should not appear
	if _, ok := data.ActorAliases["oldgroup"]; ok {
		t.Error("revoked intrusion-set should not be in aliases")
	}
}

func TestParseMITRETechniques(t *testing.T) {
	data, err := parseMITRESTIX(strings.NewReader(testSTIXBundle))
	if err != nil {
		t.Fatalf("parseMITRESTIX: %v", err)
	}

	if data.Techniques["T1566"] != "Phishing" {
		t.Errorf("T1566 = %q, want Phishing", data.Techniques["T1566"])
	}
	if data.Techniques["T1566.001"] != "Spearphishing Attachment" {
		t.Errorf("T1566.001 = %q", data.Techniques["T1566.001"])
	}
	if data.Techniques["T1078"] != "Valid Accounts" {
		t.Errorf("T1078 = %q", data.Techniques["T1078"])
	}
}

func TestParseMITREActorTechniques(t *testing.T) {
	data, err := parseMITRESTIX(strings.NewReader(testSTIXBundle))
	if err != nil {
		t.Fatalf("parseMITRESTIX: %v", err)
	}

	apt28TTPs := data.ActorTechniques["APT28"]
	if len(apt28TTPs) != 2 {
		t.Fatalf("APT28 techniques = %d, want 2: %v", len(apt28TTPs), apt28TTPs)
	}

	lazTTPs := data.ActorTechniques["Lazarus Group"]
	if len(lazTTPs) != 1 || lazTTPs[0] != "T1078" {
		t.Errorf("Lazarus Group techniques = %v, want [T1078]", lazTTPs)
	}
}

func TestParseMITREEmptyBundle(t *testing.T) {
	data, err := parseMITRESTIX(strings.NewReader(`{"type":"bundle","objects":[]}`))
	if err != nil {
		t.Fatalf("parseMITRESTIX: %v", err)
	}
	if len(data.ActorAliases) != 0 {
		t.Errorf("expected empty aliases, got %d", len(data.ActorAliases))
	}
}
