package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"yars/internal/config"
)

// Stamp moves on a change undone (the same bytes written again), which the
// version does not: a check run uses it to tell rules that changed while it
// ran.
func TestEngineStampMovesOnChangeUndone(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	os.WriteFile(p, []byte("- id: a\n  regex_forbid: zzz\n"), 0o644)
	e := NewEngine(dir, config.Default())
	ver, stamp := e.Version(), e.Stamp()
	os.WriteFile(p, []byte("- id: a\n  regex_forbid: yyy\n"), 0o644)
	os.WriteFile(p, []byte("- id: a\n  regex_forbid: zzz\n"), 0o644)
	if e.Version() != ver || e.Stamp() == stamp {
		t.Fatalf("version %s→%s, stamp %s→%s", ver, e.Version(), stamp, e.Stamp())
	}
}

// Review of 02ae98e: a script changed and changed back while it runs (here
// the changed script puts the old one back itself, as a push and its revert
// would) leaves the folder at the old version, but what ran was the change:
// its result is not kept, so the old script runs next time.
func TestScriptResultNotKeptAcrossChangeUndone(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(t.TempDir(), "runs")
	v1 := "cat >/dev/null\necho one >> " + log + "\necho '[]'\n"
	v1src := filepath.Join(t.TempDir(), "v1.sh") // as script writes it
	if err := os.WriteFile(v1src, []byte("#!/bin/sh\n"+v1), 0o755); err != nil {
		t.Fatal(err)
	}
	cs := filepath.Join(dir, "c.sh")
	v2 := "cat >/dev/null\necho two >> " + log + "\ncp " + v1src + " " + cs + ".new && mv " + cs + ".new " + cs + "\necho '[{\"message\":\"v2 says bad\"}]'\n"
	os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("- id: first\n  script: first.sh\n- id: s\n  script: c.sh\n"), 0o644)
	script(t, dir, "first.sh", "cat >/dev/null\necho '[]'\n")
	script(t, dir, "c.sh", v1)
	before := dirVersion(dir)
	store := newMemResults()
	e := NewEngine(dir, config.Default())
	e.Runner.(*Runner).Results = store
	e.CheckDoc(context.Background(), doc(), func(done, total int) {
		if done == 1 { // after the first rule, c.sh is changed; it changes itself back
			script(t, dir, "c.sh", v2)
		}
	})
	if got := dirVersion(dir); got != before {
		t.Fatalf("the folder is not back at its version: %s, want %s", got, before)
	}
	later := NewEngine(dir, config.Default())
	later.Runner.(*Runner).Results = store
	if vs := later.CheckDoc(context.Background(), doc(), nil); len(vs) != 0 {
		b, _ := os.ReadFile(log)
		t.Fatalf("v1 of c.sh prints [] but the check gives %+v; runs: %q", vs, b)
	}
}
