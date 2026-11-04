package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// Password hashes must never be cloneable: users.yaml stays untracked, and
// older repos that tracked it are migrated at serve start.
func TestUsersNotTracked(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	r, _ := gitrepo.Open(dir)
	if r.Tracked(".yars/users.yaml") {
		t.Fatal("init tracks users.yaml")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".gitignore")); !strings.Contains(string(b), ".yars/users.yaml") {
		t.Fatal(".gitignore lacks users.yaml")
	}
	// legacy repo: users.yaml committed
	old, _ := gitrepo.Init(t.TempDir())
	os.MkdirAll(filepath.Join(old.Dir, ".yars"), 0o755)
	os.WriteFile(filepath.Join(old.Dir, ".yars", "users.yaml"), []byte("[]\n"), 0o600)
	old.Commit([]string{".yars/users.yaml"}, "legacy", system)
	if err := untrackUsers(old); err != nil {
		t.Fatal(err)
	}
	if old.Tracked(".yars/users.yaml") {
		t.Fatal("still tracked after migration")
	}
	if _, err := os.Stat(filepath.Join(old.Dir, ".yars", "users.yaml")); err != nil {
		t.Fatal("users.yaml removed from disk")
	}
	if err := untrackUsers(old); err != nil {
		t.Fatalf("second run: %v", err)
	}
}

func TestLintCommand(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, ".yars", "rules", "style.yaml")); err != nil || !strings.Contains(string(b), "title-no-trailing-dot") {
		t.Fatalf("example rules not written: %v", err)
	}
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default())
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	st.CreateFinding("acme", "Bad title.", a)
	st.CreateFinding("acme", "Good title", a)

	var out bytes.Buffer
	code, err := cmdLint([]string{"--data", dir, "--fast"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 || !strings.Contains(out.String(), "acme/F-001 error title-no-trailing-dot") || strings.Contains(out.String(), "F-002 error title") {
		t.Fatalf("code %d output:\n%s", code, out.String())
	}
	out.Reset()
	code, _ = cmdLint([]string{"--data", dir, "--fast", "acme/F-002-good-title"}, &out)
	if code != 0 || strings.Contains(out.String(), "F-001") {
		t.Fatalf("scoped lint code %d:\n%s", code, out.String())
	}
}
