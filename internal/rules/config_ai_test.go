package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"yars/internal/config"
)

// A new configuration (saved or pushed) brings its ai: settings to the AI
// rules too, not only the report structure.
func TestSetConfigReachesAIRunner(t *testing.T) {
	e := NewEngine(t.TempDir(), config.Default())
	c := config.Default()
	c.AI = config.AIConfig{Provider: "openai", BaseURL: "https://llm.example/v1", Model: "m2", APIKeyEnv: "YARS_TEST_KEY"}
	e.SetConfig(c)
	got, _, _ := e.Runner.(*Runner).Effective()
	if got.Provider != "openai" || got.Model != "m2" || got.BaseURL != "https://llm.example/v1" {
		t.Fatalf("runner AI settings %+v", got)
	}
}

// Q13: the rules' version changes with any rule file, a script in a
// sub-folder too, and is stable otherwise.
func TestEngineVersionChangesWithRuleFile(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		// a later mtime, as an edit a moment later has
		later := time.Now().Add(time.Duration(len(body)) * time.Second)
		os.Chtimes(p, later, later)
	}
	write("style.yaml", "- id: a\n  target: title\n  regex_forbid: 'x'\n")
	write("lib/check.sh", "#!/bin/sh\necho []\n")
	e := NewEngine(dir, config.Default())
	v1 := e.Version()
	if len(v1) != 16 {
		t.Fatalf("version %q", v1)
	}
	if v := e.Version(); v != v1 {
		t.Fatalf("unstable: %q then %q", v1, v)
	}
	write("style.yaml", "- id: a\n  target: title\n  regex_forbid: 'y'\n")
	v2 := e.Version()
	if v2 == v1 {
		t.Fatal("a rule file changed, the version did not")
	}
	write("lib/check.sh", "#!/bin/sh\necho [ ]\n")
	if v3 := e.Version(); v3 == v2 {
		t.Fatal("a script in a sub-folder changed, the version did not")
	}
}

// An empty rules folder has a version too: a run with no rules is out of
// date once rules are added ("" is left for a linter that cannot tell).
func TestEngineVersionOfNoRules(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir, config.Default())
	v0 := e.Version()
	if len(v0) != 16 {
		t.Fatalf("version of no rules %q", v0)
	}
	p := filepath.Join(dir, "style.yaml")
	if err := os.WriteFile(p, []byte("- id: a\n  target: title\n  regex_forbid: 'x'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := e.Version(); v == v0 || len(v) != 16 {
		t.Fatalf("after a rule was added: %q (before %q)", v, v0)
	}
}

// Q11: AI rules can run only with a provider and a key.
func TestAIConfigured(t *testing.T) {
	e := NewEngine(t.TempDir(), config.Default())
	rn := e.Runner.(*Runner)
	rn.Getenv = func(k string) string { return map[string]string{"YARS_TEST_KEY": "sk-1"}[k] }
	if e.AIConfigured() {
		t.Fatal("configured without a provider")
	}
	c := config.Default()
	c.AI = config.AIConfig{Provider: "openai", BaseURL: "https://llm.example/v1", Model: "m2", APIKeyEnv: "YARS_NO_SUCH_KEY"}
	e.SetConfig(c)
	if e.AIConfigured() {
		t.Fatal("configured without a key")
	}
	c.AI.APIKeyEnv = "YARS_TEST_KEY"
	e.SetConfig(c)
	if !e.AIConfigured() {
		t.Fatal("not configured with a provider and a key")
	}
}
