package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"yars/internal/config"
)

// A rules file rewritten with the same size inside one tick of the file
// system's clock keeps its size and time: the engine still sees the new
// rule, and the version (Q13) changes with it (backlog, M5).
func TestEngineSeesSameSizeRewrite(t *testing.T) {
	dir := writeRules(t, nil)
	p := filepath.Join(dir, "r.yaml")
	now := time.Now().Truncate(time.Second)
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now, now); err != nil {
			t.Fatal(err)
		}
	}
	write("- id: aaa\n  regex_forbid: 'x'\n")
	e := NewEngine(dir, config.Default())
	before := e.Version()
	if r := e.Rules().Rules; len(r) != 1 || r[0].ID != "aaa" {
		t.Fatalf("rules %+v", r)
	}
	write("- id: bbb\n  regex_forbid: 'x'\n")
	if r := e.Rules().Rules; len(r) != 1 || r[0].ID != "bbb" {
		t.Fatalf("the rewrite was missed: %+v", r)
	}
	if e.Version() == before {
		t.Fatal("the version did not change")
	}
}

// A structure saved while the server runs (SetConfig) is what the engine
// checks rule targets against.
func TestEngineSetConfig(t *testing.T) {
	dir := writeRules(t, map[string]string{"u.yaml": "- id: biz\n  target: section:Business context\n  regex_forbid: 'x'\n"})
	e := NewEngine(dir, config.Default())
	if len(e.Rules().Problems) != 1 {
		t.Fatalf("problems before: %+v", e.Rules().Problems)
	}
	c := config.Default()
	c.Sections = append(c.Sections, "Business context")
	e.SetConfig(c)
	if ps := e.Rules().Problems; len(ps) != 0 {
		t.Fatalf("problems after: %+v", ps)
	}
}
