package rules

import (
	"testing"

	"yars/internal/config"
)

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
