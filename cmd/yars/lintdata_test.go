package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/secret"
	"github.com/abno525/yars/internal/store"
)

// lintData is a data folder (with its database) that has one engagement,
// acme, with the finding F-001 "Bad title.", and the rules in ruleYAML.
func lintData(t *testing.T, ruleYAML string) string {
	t.Helper()
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	rd := rules.DirFor(dir)
	os.MkdirAll(rd, 0o755)
	if err := os.WriteFile(filepath.Join(rd, "style.yaml"), []byte(ruleYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), nil)
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "Bad title.", a); err != nil {
		t.Fatal(err)
	}
	return dir
}

// yars lint on the data folder leaves out what was dismissed on the finding
// page: a dismissed error is not printed and does not make the exit code 1.
func TestLintHonoursDismissals(t *testing.T) {
	dir := lintData(t, "- id: no-dot\n  target: title\n  regex_forbid: '\\.$'\n  message: No dot\n- id: no-bad\n  level: warning\n  target: title\n  regex_forbid: 'Bad'\n")
	var out bytes.Buffer
	if code, err := cmdLint([]string{"--data", dir}, &out); code != 1 || err != nil || !strings.Contains(out.String(), "acme/F-001 error no-dot: No dot") {
		t.Fatalf("before: code %d err %v:\n%s", code, err, out.String())
	}
	d := openDB(t, dir)
	err := d.TxFor("acme", func(tx *db.Tx) error {
		return tx.Dismiss(db.Dismissal{Eng: "acme", Fid: "F-001", Rule: "no-dot", QuoteHash: db.ViolationHash("title", "."), Level: "error", By: "bob", Reason: "the client's name ends so"})
	})
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	code, err := cmdLint([]string{"--data", dir}, &out)
	if code != 0 || err != nil || strings.Contains(out.String(), "no-dot") || !strings.Contains(out.String(), "acme/F-001 warning no-bad") || !strings.Contains(out.String(), "1 finding(s) checked") {
		t.Fatalf("after the dismissal: code %d err %v:\n%s", code, err, out.String())
	}
}

// aiCounter is a fake OpenAI-compatible provider: it counts its requests,
// keeps the last key it was sent and answers with no violations.
type aiCounter struct {
	*httptest.Server
	hits atomic.Int32
	auth atomic.Value
}

func newAICounter(t *testing.T) *aiCounter {
	c := &aiCounter{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		c.auth.Store(r.Header.Get("Authorization"))
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"choices":[{"message":{"content":"{\"violations\":[]}"}}]}`)
	}))
	t.Cleanup(c.Close)
	return c
}

// yars lint --all on the data folder uses the AI settings saved on Admin ›
// AI, as the server does: Off there sends nothing, and an address and a key
// saved there are the ones asked. A folder without a key file gets none.
func TestLintAllUsesStoredAISettings(t *testing.T) {
	conf, saved := newAICounter(t), newAICounter(t)
	dir := lintData(t, "- id: acr\n  level: warning\n  target: title\n  ai: Expand acronyms.\n")
	t.Setenv("YARS_TEST_LINT_KEY", "env-key")
	if err := os.WriteFile(config.ConfigPath(dir), []byte("ai:\n  provider: openai\n  base_url: "+conf.URL+"\n  model: m1\n  api_key_env: YARS_TEST_LINT_KEY\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lint := func() string {
		t.Helper()
		var out bytes.Buffer
		if code, err := cmdLint([]string{"--data", dir, "--all"}, &out); code != 0 || err != nil {
			t.Fatalf("code %d err %v:\n%s", code, err, out.String())
		}
		return out.String()
	}
	// nothing saved: config.yaml's provider with the environment's key
	lint()
	if conf.hits.Load() != 1 || conf.auth.Load() != "Bearer env-key" {
		t.Fatalf("config.yaml alone: %d requests, key %v", conf.hits.Load(), conf.auth.Load())
	}
	d := openDB(t, dir)
	// Off on the admin page: no request, and the rule says it did not run
	if err := d.SetSetting(db.AIProviderKey, rules.ProviderOff); err != nil {
		t.Fatal(err)
	}
	if out := lint(); conf.hits.Load() != 1 || !strings.Contains(out, "AI rules skipped: no AI provider configured") {
		t.Fatalf("Off: %d requests:\n%s", conf.hits.Load(), out)
	}
	// an address and a key saved there: that address is asked, with that key
	box, err := secret.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := box.Encrypt("saved-key")
	for k, v := range map[string]string{db.AIProviderKey: "openai", db.AIBaseKey: saved.URL, db.AIModelKey: "m2", db.AIKeyKey: enc} {
		if err := d.SetSetting(k, v); err != nil {
			t.Fatal(err)
		}
	}
	lint()
	if conf.hits.Load() != 1 || saved.hits.Load() != 1 || saved.auth.Load() != "Bearer saved-key" {
		t.Fatalf("saved settings: %d and %d requests, key %v", conf.hits.Load(), saved.hits.Load(), saved.auth.Load())
	}
	// without the folder's key file the saved key is not read, and the
	// command makes no key file
	if err := os.Remove(secret.KeyPath(dir)); err != nil {
		t.Fatal(err)
	}
	if out := lint(); saved.hits.Load() != 1 || !strings.Contains(out, "AI rules skipped") {
		t.Fatalf("no key file: %d requests:\n%s", saved.hits.Load(), out)
	}
	if _, err := os.Stat(secret.KeyPath(dir)); err == nil {
		t.Fatal("yars lint made a key file")
	}
}
