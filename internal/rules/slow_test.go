package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"yars/internal/config"
)

func script(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestScriptViolations(t *testing.T) {
	dir := t.TempDir()
	script(t, dir, "check.sh", `id=$(cat | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
echo "[{\"message\":\"bad $id\",\"quote\":\"q\",\"target\":\"title\"}]"
`)
	r := NewRunner(dir, config.AIConfig{})
	vs := r.Script(context.Background(), Rule{ID: "s", Level: "warning", Script: "check.sh"}, doc())
	if len(vs) != 1 || vs[0].Message != "bad F-001" || vs[0].Quote != "q" || vs[0].Level != "warning" || vs[0].Target != "title" || vs[0].Rule != "s" {
		t.Fatalf("got %+v", vs)
	}
	script(t, dir, "ok.sh", "echo '[]'\n")
	if vs := r.Script(context.Background(), Rule{ID: "ok", Level: "error", Script: "ok.sh"}, doc()); len(vs) != 0 {
		t.Fatalf("clean script: %+v", vs)
	}
}

func TestScriptTimeoutAndEscape(t *testing.T) {
	dir := t.TempDir()
	script(t, dir, "slow.sh", "sleep 5\necho '[]'\n")
	script(t, dir, "junk.sh", "echo not json\n")
	script(t, dir, "fail.sh", "echo boom >&2\nexit 3\n")
	os.WriteFile(filepath.Join(dir, "noexec.sh"), []byte("#!/bin/sh\necho '[]'\n"), 0o644)
	r := NewRunner(dir, config.AIConfig{})
	r.ScriptTimeout = 300 * time.Millisecond
	cases := map[string]string{"slow.sh": "timed out", "junk.sh": "invalid output", "fail.sh": "boom",
		"noexec.sh": "rule failed", "../x.sh": "outside", "/bin/true": "outside"}
	for path, want := range cases {
		start := time.Now()
		vs := r.Script(context.Background(), Rule{ID: "s", Level: "error", Script: path}, doc())
		if len(vs) != 1 || !strings.Contains(vs[0].Message, want) || vs[0].Level != "error" {
			t.Errorf("%s: %+v", path, vs)
		}
		if time.Since(start) > 3*time.Second {
			t.Errorf("%s took %s", path, time.Since(start))
		}
	}
}

type fakeAI struct {
	hits   atomic.Int32
	status int
	body   func(req map[string]any) string
	check  func(r *http.Request)
}

func (f *fakeAI) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.check != nil {
			f.check(r)
		}
		var req map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &req)
		if f.status != 0 {
			w.WriteHeader(f.status)
		}
		io.WriteString(w, f.body(req))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func aiRunner(t *testing.T, provider, url string) *Runner {
	r := NewRunner(t.TempDir(), config.AIConfig{Provider: provider, BaseURL: url, Model: "m1", APIKeyEnv: "TEST_KEY"})
	r.Getenv = func(k string) string {
		if k == "TEST_KEY" {
			return "secret"
		}
		return ""
	}
	return r
}

var acr = Rule{ID: "acr", Level: "warning", AI: "Expand acronyms on first use."}

func TestAIOpenAI(t *testing.T) {
	f := &fakeAI{body: func(req map[string]any) string {
		msgs := req["messages"].([]any)
		user := msgs[1].(map[string]any)["content"].(string)
		if req["model"] != "m1" || !strings.Contains(user, "Expand acronyms") || !strings.Contains(user, "XSS here") {
			return `{"error":"bad request"}`
		}
		return `{"choices":[{"message":{"content":"{\"violations\":[{\"quote\":\"XSS\",\"message\":\"Expand XSS\"}]}"}}]}`
	}}
	f.check = func(r *http.Request) {
		if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("path %s auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
	}
	srv := f.server(t)
	vs := aiRunner(t, "openai", srv.URL).AI(context.Background(), acr, "section:Description", "XSS here")
	if len(vs) != 1 || vs[0].Quote != "XSS" || vs[0].Message != "Expand XSS" || vs[0].Level != "warning" || vs[0].Target != "section:Description" {
		t.Fatalf("got %+v", vs)
	}
}

func TestAIAnthropic(t *testing.T) {
	f := &fakeAI{body: func(req map[string]any) string {
		return `{"content":[{"type":"text","text":"Here you go:\n{\"violations\":[{\"quote\":\"SSRF\",\"message\":\"Expand SSRF\"}]}"}]}`
	}}
	f.check = func(r *http.Request) {
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "secret" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("path %s headers %v", r.URL.Path, r.Header)
		}
	}
	srv := f.server(t)
	vs := aiRunner(t, "anthropic", srv.URL).AI(context.Background(), acr, "title", "SSRF in export")
	if len(vs) != 1 || vs[0].Quote != "SSRF" {
		t.Fatalf("got %+v", vs)
	}
}

func TestAICache(t *testing.T) {
	f := &fakeAI{body: func(map[string]any) string {
		return `{"choices":[{"message":{"content":"{\"violations\":[]}"}}]}`
	}}
	srv := f.server(t)
	r := aiRunner(t, "openai", srv.URL)
	r.AI(context.Background(), acr, "title", "same text")
	r.AI(context.Background(), acr, "title", "same text")
	if f.hits.Load() != 1 {
		t.Fatalf("hits %d", f.hits.Load())
	}
}

// The AI cache keeps at most AICacheSize results: the oldest are asked again.
func TestAICacheBounded(t *testing.T) {
	f := &fakeAI{body: func(map[string]any) string {
		return `{"choices":[{"message":{"content":"{\"violations\":[]}"}}]}`
	}}
	srv := f.server(t)
	r := aiRunner(t, "openai", srv.URL)
	for i := 0; i <= AICacheSize; i++ {
		r.AI(context.Background(), acr, "title", fmt.Sprint("text ", i))
	}
	if n := r.aiCache().Len(); n != AICacheSize {
		t.Fatalf("cache holds %d", n)
	}
	before := f.hits.Load()
	r.AI(context.Background(), acr, "title", "text 0") // evicted
	r.AI(context.Background(), acr, "title", fmt.Sprint("text ", AICacheSize))
	if got := f.hits.Load() - before; got != 1 {
		t.Fatalf("hits after eviction %d", got)
	}
}

func TestAIErrorIsWarning(t *testing.T) {
	for _, f := range []*fakeAI{
		{status: 500, body: func(map[string]any) string { return "oops" }},
		{body: func(map[string]any) string { return `{"choices":[{"message":{"content":"not json at all"}}]}` }},
	} {
		srv := f.server(t)
		r := aiRunner(t, "openai", srv.URL)
		errRule := acr
		errRule.Level = "error"
		vs := r.AI(context.Background(), errRule, "title", "x")
		if len(vs) != 1 || vs[0].Level != "warning" || !strings.Contains(vs[0].Message, "AI check failed") {
			t.Fatalf("got %+v", vs)
		}
		// failures are not cached
		r.AI(context.Background(), errRule, "title", "x")
		if f.hits.Load() != 2 {
			t.Fatalf("failure cached")
		}
	}
}

func TestScriptOutputCapped(t *testing.T) {
	dir := t.TempDir()
	script(t, dir, "loud.sh", "head -c 5000000 /dev/zero | tr '\\0' 'x'\n")
	r := NewRunner(dir, config.AIConfig{})
	vs := r.Script(context.Background(), Rule{ID: "loud", Level: "error", Script: "loud.sh"}, doc())
	if len(vs) != 1 || !strings.Contains(vs[0].Message, "output too large") {
		t.Fatalf("got %d violations: %.200v", len(vs), vs)
	}
}

func TestAIFailureSkipsRemainingParts(t *testing.T) {
	f := &fakeAI{status: 500, body: func(map[string]any) string { return "down" }}
	srv := f.server(t)
	r := aiRunner(t, "openai", srv.URL)
	s := &Set{Rules: []Rule{{ID: "acr", Level: "warning", AI: "x", Target: "text"}}}
	d := doc()
	d.Sections = []Section{{"A", "one"}, {"B", "two"}, {"C", "three"}}
	vs := s.Run(context.Background(), d, config.Default(), All, r)
	if f.hits.Load() != 1 || len(vs) != 1 {
		t.Fatalf("hits %d, violations %d", f.hits.Load(), len(vs))
	}
}

func TestEngineBudget(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("- id: slow\n  script: slow.sh\n"), 0o644)
	script(t, dir, "slow.sh", "sleep 5\necho '[]'\n")
	e := NewEngine(dir, config.Default())
	e.Budget = 300 * time.Millisecond
	start := time.Now()
	vs := e.LintDoc(context.Background(), doc(), All)
	if time.Since(start) > 3*time.Second || len(vs) != 1 || !strings.Contains(vs[0].Message, "rule failed") {
		t.Fatalf("took %s: %+v", time.Since(start), vs)
	}
}

func TestAINotConfigured(t *testing.T) {
	r := NewRunner(t.TempDir(), config.AIConfig{})
	vs := r.AI(context.Background(), acr, "title", "x")
	if len(vs) != 1 || vs[0].Level != "warning" || !strings.Contains(vs[0].Message, "no AI provider configured") {
		t.Fatalf("got %+v", vs)
	}
	// Run reports it once even with many parts
	s := &Set{Rules: []Rule{{ID: "acr", Level: "warning", AI: "x", Target: "text"}}}
	out := s.Run(context.Background(), doc(), config.Default(), All, r)
	if len(out) != 1 {
		t.Fatalf("not deduplicated: %+v", out)
	}
}
