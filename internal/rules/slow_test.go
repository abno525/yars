package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/logs"
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

// A script's (or a model's) message is kept whole up to 4,000 characters
// and cut after them, as a quote is at 80: one runaway answer cannot flood
// the page (backlog, M5; Q23).
func TestRuleMessageCapped(t *testing.T) {
	if maxMessage != 4000 {
		t.Fatalf("maxMessage %d", maxMessage)
	}
	dir := t.TempDir()
	script(t, dir, "long.sh", "printf '[{\"message\":\"%05000d\"}]' 0\n")
	script(t, dir, "full.sh", "printf '[{\"message\":\"%04000d\"}]' 0\n")
	r := NewRunner(dir, config.AIConfig{})
	vs := r.Script(context.Background(), Rule{ID: "s", Level: "warning", Script: "long.sh"}, doc())
	if len(vs) != 1 || len([]rune(vs[0].Message)) != maxMessage+1 || !strings.HasSuffix(vs[0].Message, "…") {
		t.Fatalf("got %d characters: %+v", len([]rune(vs[0].Message)), vs)
	}
	vs = r.Script(context.Background(), Rule{ID: "f", Level: "warning", Script: "full.sh"}, doc())
	if len(vs) != 1 || vs[0].Message != strings.Repeat("0", 4000) {
		t.Fatalf("got %d characters", len([]rune(vs[0].Message)))
	}
}

// A missing script whose name starts with two dots is inside the folder:
// its error is not "outside" (the exporters' same check, backlog M8).
func TestScriptDotDotName(t *testing.T) {
	r := NewRunner(t.TempDir(), config.AIConfig{})
	if _, err := r.scriptPath("..check.sh"); err == nil || strings.Contains(err.Error(), "outside") {
		t.Fatalf("err %v", err)
	}
}

// A rule cannot run a script kept beside the rules folder, as in
// .yars/exporters, which a director without the admin flag may push.
func TestScriptInSiblingFolderRefused(t *testing.T) {
	root := t.TempDir()
	dir, exp := filepath.Join(root, "rules"), filepath.Join(root, "exporters")
	os.Mkdir(dir, 0o755)
	os.Mkdir(exp, 0o755)
	script(t, exp, "x.sh", "echo '[{\"message\":\"ran\"}]'\n")
	r := NewRunner(dir, config.AIConfig{})
	for _, path := range []string{"../exporters/x.sh", "./../exporters/x.sh", "lib/../../exporters/x.sh", filepath.Join(exp, "x.sh")} {
		if vs := r.Script(context.Background(), Rule{ID: "s", Level: "error", Script: path}, doc()); len(vs) != 1 || !strings.Contains(vs[0].Message, "outside") {
			t.Errorf("%s: %+v", path, vs)
		}
	}
}

// A symlink in the rules folder that points outside it is not run, nor is
// one inside a linked folder that leaves it; a link that stays inside is
// (backlog, M5).
func TestScriptSymlinkOutsideRefused(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	script(t, outside, "evil.sh", "echo '[{\"message\":\"ran\"}]'\n")
	script(t, dir, "real.sh", "echo '[]'\n")
	for link, target := range map[string]string{"evil.sh": filepath.Join(outside, "evil.sh"), "ok.sh": "real.sh", "sub": outside} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	r := NewRunner(dir, config.AIConfig{})
	for _, path := range []string{"evil.sh", "sub/evil.sh"} {
		if vs := r.Script(context.Background(), Rule{ID: "s", Level: "error", Script: path}, doc()); len(vs) != 1 || !strings.Contains(vs[0].Message, "outside") {
			t.Errorf("%s: %+v", path, vs)
		}
	}
	if vs := r.Script(context.Background(), Rule{ID: "s", Level: "error", Script: "ok.sh"}, doc()); len(vs) != 0 {
		t.Errorf("a link inside the folder: %+v", vs)
	}
}

type fakeAI struct {
	hits   atomic.Int32
	status int
	// statusOf, when set, is the status of the n-th request (from 1); 0 is 200
	statusOf   func(n int) int
	retryAfter string // the Retry-After header of an answer that is not 200
	body       func(req map[string]any) string
	check      func(r *http.Request)
}

func (f *fakeAI) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := f.hits.Add(1)
		if f.check != nil {
			f.check(r)
		}
		var req map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &req)
		status := f.status
		if f.statusOf != nil {
			status = f.statusOf(int(n))
		}
		if status != 0 {
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
			}
			w.WriteHeader(status)
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
	// a call that is tried again does not wait in a test
	r.Backoff = 0
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

// An Anthropic base URL written with its /v1 (as OpenAI's is) still reaches
// /v1/messages, not /v1/v1/messages (backlog, M5).
func TestAIAnthropicBaseWithV1(t *testing.T) {
	for _, suffix := range []string{"/v1", "/v1/"} {
		f := &fakeAI{body: func(map[string]any) string {
			return `{"content":[{"type":"text","text":"{\"violations\":[]}"}]}`
		}}
		f.check = func(r *http.Request) {
			if r.URL.Path != "/v1/messages" {
				t.Errorf("%s: path %s", suffix, r.URL.Path)
			}
		}
		srv := f.server(t)
		if vs := aiRunner(t, "anthropic", srv.URL+suffix).AI(context.Background(), acr, "title", "x"); len(vs) != 0 {
			t.Errorf("%s: %+v", suffix, vs)
		}
	}
}

// A rule check may answer at length: Anthropic gets 4096 tokens for it, and
// a reply cut at the limit says so instead of failing as bad JSON (backlog,
// M5).
func TestAIAnthropicReplyLimit(t *testing.T) {
	var asked float64
	f := &fakeAI{body: func(req map[string]any) string {
		asked, _ = req["max_tokens"].(float64)
		return `{"content":[{"type":"text","text":"{\"violations\":[{\"quote\":\"x\",\"mess"}],"stop_reason":"max_tokens"}`
	}}
	srv := f.server(t)
	vs := aiRunner(t, "anthropic", srv.URL).AI(context.Background(), acr, "title", "x")
	if asked != 4096 {
		t.Errorf("max_tokens %v", asked)
	}
	if len(vs) != 1 || !strings.Contains(vs[0].Message, "the reply was cut off at the 4096-token limit") {
		t.Fatalf("got %+v", vs)
	}
}

// A provider's error body (which can echo the key or the account) is never
// shown: users see the status code only (backlog, M5).
func TestAIErrorShowsStatusOnly(t *testing.T) {
	f := &fakeAI{status: 401, body: func(map[string]any) string {
		return `{"error":{"message":"invalid x-api-key sk-ant-secret-1234 for org acme-billing"}}`
	}}
	srv := f.server(t)
	vs := aiRunner(t, "anthropic", srv.URL).AI(context.Background(), acr, "title", "x")
	if len(vs) != 1 || vs[0].Message != "AI check failed: HTTP 401" {
		t.Fatalf("got %+v", vs)
	}
}

// The server log gets one warn line for a call the provider refused, the
// call's own, with the status and the provider's host, and nothing of the
// error body: a provider can echo the request there (the finding's text) or
// the key. A 500 is tried again twice, and each of those tries has a warn
// line of the same kind.
func TestAIErrorLogHasNoBody(t *testing.T) {
	lg, logged := logs.NewRecorder()
	for i, provider := range []string{"anthropic", "openai"} {
		f := &fakeAI{status: 500, body: func(map[string]any) string {
			return "invalid key: secret\nfake log line\nyou sent: The admin password is hunter2"
		}}
		srv := f.server(t)
		rn := aiRunner(t, provider, srv.URL)
		rn.Logger = lg
		vs := rn.AI(context.Background(), acr, "title", "The admin password is hunter2")
		if len(vs) != 1 || vs[0].Message != "AI check failed: HTTP 500" {
			t.Fatalf("%s: got %+v", provider, vs)
		}
		recs := logged.With("ai call failed")
		if len(recs) != i+1 || recs[i].Str("status") != "500" || recs[i].Str("host") != strings.TrimPrefix(srv.URL, "http://") || recs[i].Level != slog.LevelWarn ||
			recs[i].Str("err") != "HTTP 500" || recs[i].Str("rule") != acr.ID || recs[i].Str("provider") != provider {
			t.Fatalf("%s: log:\n%s", provider, logged.Text())
		}
	}
	if out := logged.Text(); strings.Contains(out, "secret") || strings.Contains(out, "hunter2") || strings.Contains(out, "fake log line") ||
		len(logged.With("ai call failed")) != 2 || len(logged.With(retryLine)) != 2*aiRetries || len(logged.Records()) != 2+2*aiRetries {
		t.Fatalf("log:\n%s", out)
	}
}

// Every provider call writes one line when it ends: info with what it was
// for, the rule, the provider and model, who asked and on which finding, the
// tokens and the time; warn with a few words when it failed. A reply that is
// no JSON is a warning of its own. No line holds the address, the rule's
// text, the finding's text or the reply.
func TestAICallIsLogged(t *testing.T) {
	lg, logged := logs.NewRecorder()
	reply := `{"choices":[{"message":{"content":"{\"violations\":[{\"quote\":\"zqquote7f3kq\",\"message\":\"zqreply7f3kq\"}]}"}}],"usage":{"prompt_tokens":7,"completion_tokens":3}}`
	f := &fakeAI{body: func(map[string]any) string { return reply }}
	srv := f.server(t)
	rn := aiRunner(t, "openai", srv.URL)
	rn.Logger = lg
	ctx := WithCaller(context.Background(), Caller{User: "alice", Eng: "acme", Fid: "F-002"})
	if vs := rn.AI(ctx, acr, "title", "zqtext7f3kq zqquote7f3kq"); len(vs) != 1 {
		t.Fatalf("got %+v", vs)
	}
	recs := logged.With("ai call finished")
	if len(recs) != 1 || len(logged.Records()) != 1 {
		t.Fatalf("log:\n%s", logged.Text())
	}
	r := recs[0]
	if r.Level != slog.LevelInfo || r.Str("purpose") != "rule" || r.Str("rule") != acr.ID || r.Str("provider") != "openai" || r.Str("model") == "" ||
		r.Str("user") != "alice" || r.Str("eng") != "acme" || r.Str("finding") != "F-002" || r.Str("in") != "7" || r.Str("out") != "3" || !r.Has("ms") {
		t.Fatalf("line: %s", r)
	}

	// a call that gets no answer: a warning, without the address
	logged.Reset()
	srv.Close()
	down := aiRunner(t, "openai", strings.Replace(srv.URL, "http://", "http://zquser7f3kq:zqpass7f3kq@", 1)+"/zqpath7f3kq")
	down.Logger = lg
	// a folder's name in place of an ID is not logged
	ctx = WithCaller(context.Background(), Caller{User: "alice", Eng: "acme", Fid: "F-002-zqslug7f3kq"})
	if vs := down.AI(ctx, acr, "title", "zqother7f3kq"); len(vs) != 1 || vs[0].Target != "ai" {
		t.Fatalf("got %+v", vs)
	}
	failed := logged.With("ai call failed")
	if len(failed) != 1 || failed[0].Level != slog.LevelWarn || failed[0].Str("err") != "no answer" || failed[0].Str("rule") != acr.ID || failed[0].Str("finding") != "?" {
		t.Fatalf("log:\n%s", logged.Text())
	}

	// a reply that is no JSON
	f2 := &fakeAI{body: func(map[string]any) string {
		return `{"choices":[{"message":{"content":"zqprose7f3kq"}}]}`
	}}
	bad := aiRunner(t, "openai", f2.server(t).URL)
	bad.Logger = lg
	bad.AI(context.Background(), acr, "title", "zqthird7f3kq")
	if recs := logged.With("ai: a rule's reply is not read"); len(recs) != 1 || recs[0].Level != slog.LevelWarn || recs[0].Str("rule") != acr.ID {
		t.Fatalf("log:\n%s", logged.Text())
	}
	if out := logged.Text(); strings.Contains(out, "zq") || strings.Contains(out, acr.AI) {
		t.Fatalf("the log holds text:\n%s", out)
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
		{status: 401, body: func(map[string]any) string { return "oops" }},
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
	// one question, asked three times (a 500 is tried again)
	if f.hits.Load() != 1+aiRetries || len(vs) != 1 {
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
