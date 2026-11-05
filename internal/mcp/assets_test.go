package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// set_field assets takes a JSON list of {host, url, port, note}; read_finding
// returns the list and its base.
func TestMCPSetAssets(t *testing.T) {
	f := newFx(t)
	args := func(value, base string) map[string]any {
		return map[string]any{"engagement": "acme", "finding": "F-001", "field": "assets", "value": value, "base": base}
	}
	read := func() (rd struct {
		Assets     []map[string]string `json:"assets"`
		AssetsBase string              `json:"assets_base"`
	}) {
		json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
		return rd
	}
	base := read().AssetsBase
	f.ok(alice, "set_field", args(`[{"host":"app.example","port":"443"},{"url":"https://app.example/x","note":"q"}]`, base))
	if !strings.Contains(f.lastCommit(), "edit assets") {
		t.Fatalf("commit %q", f.lastCommit())
	}
	rd := read()
	if len(rd.Assets) != 2 || rd.Assets[0]["host"] != "app.example" || rd.Assets[1]["note"] != "q" {
		t.Fatalf("assets %+v", rd.Assets)
	}
	if text, isErr := f.call(alice, "set_field", args(`[]`, base)); !isErr || !strings.Contains(text, "changed") {
		t.Fatalf("stale base: %s", text)
	}
	if text, isErr := f.call(alice, "set_field", args(`not json`, "")); !isErr || !strings.Contains(text, "JSON") {
		t.Fatalf("bad json: %s", text)
	}
	if text, isErr := f.call(alice, "set_field", args(`[{"note":"x"}]`, "")); !isErr || !strings.Contains(text, "host or URL") {
		t.Fatalf("invalid asset: %s", text)
	}
}
