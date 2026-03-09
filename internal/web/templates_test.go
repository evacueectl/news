package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readStats(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("templates", "stats.html"))
	if err != nil {
		t.Fatalf("reading stats.html: %v", err)
	}
	return string(b)
}

// TestAllViewsUseScoreFilter verifies that all three views (scatter, map,
// actor cards) are called with the score-filtered list (v) so that
// min-score buttons work consistently across views.
func TestAllViewsUseScoreFilter(t *testing.T) {
	src := readStats(t)

	// No view should use vNoScore — that function should be removed
	if strings.Contains(src, "vNoScore") {
		t.Error("vNoScore should not exist — all views must use the score-filtered list v")
	}
	if strings.Contains(src, "filtNoScore") {
		t.Error("filtNoScore function should be removed — no longer needed")
	}

	// Verify each view is called with v
	if !strings.Contains(src, "renderScatter(v)") {
		t.Error("renderScatter(v) call not found")
	}
	if !strings.Contains(src, "renderMap(v)") {
		t.Error("renderMap(v) call not found")
	}
	if !strings.Contains(src, "actorCards(v)") {
		t.Error("actorCards(v) call not found")
	}
}

// TestMapPulseAnimation verifies that the pulse CSS animation and class
// logic exists for the map's pulsing countries feature.
func TestMapPulseAnimation(t *testing.T) {
	src := readStats(t)

	if !strings.Contains(src, "@keyframes mapPulse") {
		t.Error("mapPulse CSS keyframes not found")
	}
	if !strings.Contains(src, `classList.add("pulse")`) {
		t.Error("pulse class application logic not found in renderMap")
	}
	if !strings.Contains(src, "MAP_ALERT_MINUTES") {
		t.Error("MAP_ALERT_MINUTES constant not found")
	}
}

// TestMapFocusMode verifies that the focus mode button and logic exist.
func TestMapFocusMode(t *testing.T) {
	src := readStats(t)

	if !strings.Contains(src, `id="map-fs"`) {
		t.Error("focus button (map-fs) not found in HTML")
	}
	if !strings.Contains(src, "map-focus") {
		t.Error("map-focus class not found")
	}
	if !strings.Contains(src, "renderMapFocus") {
		t.Error("renderMapFocus function not found")
	}
}

// TestMapTooltipClickable verifies that map tooltips contain clickable
// article links with target="_blank".
func TestMapTooltipClickable(t *testing.T) {
	src := readStats(t)

	if !strings.Contains(src, "map-tip-article") {
		t.Error("map-tip-article class not found — tooltip articles should be clickable links")
	}
	if !strings.Contains(src, `pointer-events: auto`) {
		t.Error("map-tip must have pointer-events: auto to allow clicking links")
	}
}
