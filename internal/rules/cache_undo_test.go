package rules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
)

// Stamp moves on a change undone (the same bytes written again), which the
// version does not: a check run uses it to tell rules that changed while it
// ran.
func TestEngineStampMovesOnChangeUndone(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.yaml")
	os.WriteFile(p, []byte("- id: a\n  regex_forbid: zzz\n"), 0o644)
	t0 := time.Now().Add(-10 * time.Second) // file times set, not left to the clock's tick
	os.Chtimes(p, t0, t0)
	e := NewEngine(dir, config.Default())
	ver, stamp := e.Loaded()
	os.WriteFile(p, []byte("- id: a\n  regex_forbid: yyy\n"), 0o644)
	os.WriteFile(p, []byte("- id: a\n  regex_forbid: zzz\n"), 0o644)
	t1 := t0.Add(5 * time.Second)
	os.Chtimes(p, t1, t1)
	ver2, _ := e.Loaded()
	if ver2 != ver || e.Holds(stamp) {
		t.Fatalf("version %s→%s, the stamp still holds", ver, ver2)
	}
}

// Reviews of 421b1c9 and 42df0a1: a file's content hash is in the signature
// only while the file is fresh (written within freshFor). Its dropping out
// is no change; but a rewrite of the same size in the same time tick, seen
// only after the file stopped being fresh, is one (the content is hashed
// again then).
func TestSignatureHoldsAcrossFreshness(t *testing.T) {
	fresh := time.Now().Add(-freshFor + time.Second) // fresh for one more second
	stamped := func(body string) (string, string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "r.yaml")
		os.WriteFile(p, []byte(body), 0o644)
		os.Chtimes(p, fresh, fresh)
		return dir, dirSignature(dir)
	}
	same, sameAt := stamped("- id: a\n  regex_forbid: zzz\n")
	rewritten, rewrittenAt := stamped("- id: a\n  regex_forbid: zzz\n")
	p := filepath.Join(rewritten, "r.yaml")
	os.WriteFile(p, []byte("- id: a\n  regex_forbid: yyy\n"), 0o644) // same size
	os.Chtimes(p, fresh, fresh)                                      // same tick
	resized, resizedAt := stamped("- id: a\n  regex_forbid: zzz\n")
	os.WriteFile(filepath.Join(resized, "r.yaml"), []byte("- id: a\n  regex_forbid: zzzz\n"), 0o644)
	os.Chtimes(filepath.Join(resized, "r.yaml"), fresh, fresh)
	time.Sleep(1200 * time.Millisecond) // no longer fresh: the hashes drop out
	if dirSignature(same) == sameAt {
		t.Fatalf("the test needs the hash to drop out: %q", sameAt)
	}
	if !signatureHolds(same, sameAt) {
		t.Error("a hash dropping out counts as a change")
	}
	if signatureHolds(rewritten, rewrittenAt) {
		t.Error("a same-size rewrite in the same tick counts as none")
	}
	if signatureHolds(resized, resizedAt) {
		t.Error("a size change counts as none")
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
