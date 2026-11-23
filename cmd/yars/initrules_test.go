package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/store"
)

// yars init writes no rules: a new data folder starts with none, and its
// owner adds the ones they want (Admin › Rules, or files in .yars/rules/).
// It used to write five example rules, four of them errors that block
// Submit and one an AI rule that, without a provider, flagged every finding
// "AI checks failed" after Check.
func TestInitWritesNoRules(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if set := rules.Load(rules.DirFor(dir)); len(set.Rules) != 0 || len(set.Problems) != 0 {
		t.Fatalf("rules after init: %d rules, problems %v", len(set.Rules), set.Problems)
	}
	if out, err := exec.Command("git", "-C", dir, "ls-files", ".yars/rules").Output(); err != nil || len(out) != 0 {
		t.Fatalf("rule files in the init commit: %v\n%s", err, out)
	}
	if out, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(out) != 0 {
		t.Fatalf("init left files out of its commit:\n%s", out)
	}
	// with no rules, a title the old rules refused passes
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), nil)
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "Bad title.", a); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code, err := cmdLint([]string{"--data", dir, "--fast"}, &out); err != nil || code != 0 || !strings.Contains(out.String(), "1 finding(s) checked") {
		t.Fatalf("lint with no rules: %d %v\n%s", code, err, out.String())
	}
}

// withTestRules gives the data folder dir the rules the tests check against
// (testdata/rules.yaml: the example rules yars init used to write),
// committed as an owner's own rules are.
func withTestRules(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rd := rules.DirFor(dir)
	if err := os.MkdirAll(rd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rd, "style.yaml"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit([]string{".yars/rules"}, "rules for the tests", system); err != nil {
		t.Fatal(err)
	}
}
