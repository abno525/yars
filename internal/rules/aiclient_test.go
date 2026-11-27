package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/logs"
)

const retryLine = "ai call failed; it is tried again"

// hitReply is a provider's answer with one violation whose quote is "XSS".
func hitReply(provider string) string {
	return aiContent(provider, `{"violations":[{"quote":"XSS","message":"Expand XSS"}]}`)
}

// A call the provider answers with 429 or a 5xx status is tried again, twice
// at most: the check ends with the answer that came. Each try that is made
// again is one warn line with the status, the host and the try's number; the
// call has its one line and its one usage row.
func TestAIRetries(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic"} {
		f := &fakeAI{body: func(map[string]any) string { return hitReply(provider) }}
		f.statusOf = func(n int) int { return []int{429, 529, 0}[n-1] }
		srv := f.server(t)
		lg, logged := logs.NewRecorder()
		r := aiRunner(t, provider, srv.URL)
		r.Logger = lg
		var used []Usage
		r.OnUsage = func(u Usage) { used = append(used, u) }
		vs := r.AI(context.Background(), acr, "title", "XSS here")
		if len(vs) != 1 || vs[0].Quote != "XSS" {
			t.Fatalf("%s: got %+v", provider, vs)
		}
		if f.hits.Load() != 3 {
			t.Fatalf("%s: %d requests", provider, f.hits.Load())
		}
		again := logged.With(retryLine)
		if len(again) != 2 || len(logged.With("ai call finished")) != 1 || len(logged.Records()) != 3 {
			t.Fatalf("%s: log:\n%s", provider, logged.Text())
		}
		for i, want := range []string{"429", "529"} {
			l := again[i]
			if l.Level != slog.LevelWarn || l.Str("status") != want || l.Str("host") != strings.TrimPrefix(srv.URL, "http://") || l.Str("attempt") != []string{"1", "2"}[i] ||
				l.Str("rule") != acr.ID || l.Str("provider") != provider || l.Str("model") != "m1" || l.Str("purpose") != "rule" {
				t.Errorf("%s: line %d: %s", provider, i, l)
			}
		}
		if len(used) != 1 || !used[0].OK {
			t.Errorf("%s: usage %+v", provider, used)
		}
	}
}

// Three answers of that kind are the failure: a warning with the last
// status, not kept. No line holds the answer's text.
func TestAIRetriesEnd(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503, 504, 529} {
		f := &fakeAI{status: status, body: func(map[string]any) string { return "zqbody7f3kq" }}
		lg, logged := logs.NewRecorder()
		r := aiRunner(t, "openai", f.server(t).URL)
		r.Logger = lg
		for i := range 2 {
			vs := r.AI(context.Background(), acr, "title", "x")
			if len(vs) != 1 || vs[0].Target != "ai" || vs[0].Message != fmt.Sprint("AI check failed: HTTP ", status) {
				t.Fatalf("%d: got %+v", status, vs)
			}
			if got := int(f.hits.Load()); got != 3*(i+1) {
				t.Fatalf("%d: %d requests after call %d", status, got, i+1)
			}
		}
		if len(logged.With(retryLine)) != 4 || len(logged.With("ai call failed")) != 2 || strings.Contains(logged.Text(), "zq") {
			t.Fatalf("%d: log:\n%s", status, logged.Text())
		}
	}
}

// An answer that says the request itself is wrong (the key, the model, the
// address) is not tried again, and neither is a call that got no answer.
func TestAINoRetry(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 422} {
		f := &fakeAI{status: status, body: func(map[string]any) string { return "no" }}
		r := aiRunner(t, "anthropic", f.server(t).URL)
		if vs := r.AI(context.Background(), acr, "title", "x"); len(vs) != 1 || vs[0].Target != "ai" {
			t.Fatalf("%d: got %+v", status, vs)
		}
		if f.hits.Load() != 1 {
			t.Errorf("%d: %d requests", status, f.hits.Load())
		}
	}
	var waits atomic.Int32
	down := aiRunner(t, "openai", "http://127.0.0.1:1")
	down.wait = func(context.Context, time.Duration) error { waits.Add(1); return nil }
	if vs := down.AI(context.Background(), acr, "title", "x"); len(vs) != 1 || vs[0].Target != "ai" || waits.Load() != 0 {
		t.Fatalf("no answer: %+v, %d waits", vs, waits.Load())
	}
}

// The wait before a next try doubles, takes the provider's Retry-After
// (seconds) up to ten seconds, stops when the question's time is over, and
// is not begun when it would end after it.
func TestAIRetryWait(t *testing.T) {
	waited := func(r *Runner) *[]time.Duration {
		var ds []time.Duration
		r.wait = func(_ context.Context, d time.Duration) error { ds = append(ds, d); return nil }
		return &ds
	}
	for _, c := range []struct {
		backoff    time.Duration
		retryAfter string
		want       []time.Duration
	}{
		{time.Second, "", []time.Duration{time.Second, 2 * time.Second}},
		{time.Second, "7", []time.Duration{7 * time.Second, 7 * time.Second}},
		{time.Second, "3600", []time.Duration{10 * time.Second, 10 * time.Second}},
		{time.Second, "Wed, 21 Oct 2015 07:28:00 GMT", []time.Duration{time.Second, 2 * time.Second}},
		{time.Second, "-5", []time.Duration{time.Second, 2 * time.Second}},
	} {
		f := &fakeAI{status: 429, retryAfter: c.retryAfter, body: func(map[string]any) string { return "" }}
		r := aiRunner(t, "openai", f.server(t).URL)
		r.Backoff = c.backoff
		ds := waited(r)
		r.AI(context.Background(), acr, "title", "x")
		if !slices.Equal(*ds, c.want) || f.hits.Load() != 3 {
			t.Errorf("Retry-After %q: waits %v, %d requests", c.retryAfter, *ds, f.hits.Load())
		}
	}

	// the question is given up during the wait: no further request
	f := &fakeAI{status: 503, body: func(map[string]any) string { return "" }}
	r := aiRunner(t, "openai", f.server(t).URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.wait = func(ctx context.Context, _ time.Duration) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	if vs := r.AI(ctx, acr, "title", "x"); len(vs) != 1 || vs[0].Target != "ai" || f.hits.Load() != 1 {
		t.Fatalf("given up: %+v, %d requests", vs, f.hits.Load())
	}

	// a wait that would end after the question's time is not begun
	f = &fakeAI{status: 503, body: func(map[string]any) string { return "" }}
	r = aiRunner(t, "openai", f.server(t).URL)
	r.Backoff, r.AITimeout = time.Hour, time.Minute
	ds := waited(r)
	if vs := r.AI(context.Background(), acr, "title", "x"); len(vs) != 1 || vs[0].Message != "AI check failed: HTTP 503" || len(*ds) != 0 || f.hits.Load() != 1 {
		t.Fatalf("no time left: %+v, waits %v, %d requests", vs, *ds, f.hits.Load())
	}
}

// A provider that fails is waited for once in a run of the rules, not once
// per AI rule: after the first rule's tries the other AI rules ask once, so
// the run's time is left for the rules after them. The next run tries again.
func TestAIRetriesOncePerRun(t *testing.T) {
	f := &fakeAI{status: 429, retryAfter: "30", body: func(map[string]any) string { return "" }}
	r := aiRunner(t, "openai", f.server(t).URL)
	script(t, r.Dir, "ok.sh", "echo '[]'\n")
	var waits []time.Duration
	r.wait = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	var src strings.Builder
	for i := range 5 {
		fmt.Fprintf(&src, "- {id: ai%d, level: warning, target: title, ai: rule %d}\n", i, i)
	}
	src.WriteString("- {id: s, level: error, script: ok.sh}\n")
	rs, problems := Parse("r.yaml", []byte(src.String()))
	if len(rs) != 6 || len(problems) != 0 {
		t.Fatalf("rules %+v, problems %+v", rs, problems)
	}
	set := &Set{Dir: r.Dir, Rules: rs}
	for run := 1; run <= 2; run++ {
		vs := set.Run(context.Background(), doc(), config.Config{}, Slow, r)
		if len(vs) != 5 {
			t.Fatalf("run %d: got %+v", run, vs)
		}
		for _, v := range vs {
			if v.Target != "ai" || v.Message != "AI check failed: HTTP 429" {
				t.Fatalf("run %d: got %+v", run, v)
			}
		}
		// the first rule: three requests and two waits; the four after it: one
		// request each
		if len(waits) != 2*run || int(f.hits.Load()) != 7*run {
			t.Fatalf("run %d: waits %v, %d requests", run, waits, f.hits.Load())
		}
	}
	var sum time.Duration
	for _, d := range waits[:2] {
		sum += d
	}
	if sum != 2*maxRetryAfter {
		t.Fatalf("waits %v", waits)
	}

	// a rule after one that was answered is tried again as before
	f = &fakeAI{body: func(map[string]any) string { return aiContent("openai", `{"violations":[]}`) }}
	f.statusOf = func(n int) int { return []int{503, 0, 503, 0}[n-1] }
	r = aiRunner(t, "openai", f.server(t).URL)
	set = &Set{Dir: r.Dir, Rules: rs[:2]}
	if vs := set.Run(context.Background(), doc(), config.Config{}, Slow, r); len(vs) != 0 || f.hits.Load() != 4 {
		t.Fatalf("answered after a try: %+v, %d requests", vs, f.hits.Load())
	}
}

// Fix with AI and the Test button are tried again as a rule check is.
func TestAIRetriesFixAndTest(t *testing.T) {
	f := &fakeAI{body: func(map[string]any) string { return aiContent("openai", `{"violations":[]}`) }}
	f.statusOf = func(n int) int { return []int{503, 0}[n-1] }
	r := aiRunner(t, "openai", f.server(t).URL)
	if _, err := r.Ping(context.Background()); err != nil || f.hits.Load() != 2 {
		t.Fatalf("Test: %v, %d requests", err, f.hits.Load())
	}
	f = &fakeAI{body: func(map[string]any) string { return aiContent("openai", `{"body":"fixed"}`) }}
	f.statusOf = func(n int) int { return []int{429, 0}[n-1] }
	r = aiRunner(t, "openai", f.server(t).URL)
	if body, err := r.Fix(context.Background(), Violation{Rule: "acr"}, "rule", "Description", "old"); err != nil || body != "fixed" || f.hits.Load() != 2 {
		t.Fatalf("Fix: %q %v, %d requests", body, err, f.hits.Load())
	}
}

// pickyAI is an OpenAI-compatible provider that answers 400 to a request
// with any of the keys in refuses, and reply to any other. It keeps the
// keys of each request.
type pickyAI struct {
	refuses []string
	reply   string
	mu      sync.Mutex
	asked   []map[string]any
}

func (p *pickyAI) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		p.mu.Lock()
		p.asked = append(p.asked, req)
		p.mu.Unlock()
		for _, k := range p.refuses {
			if _, has := req[k]; has {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":{"message":"zqbody7f3kq: unsupported parameter `+k+`"}}`)
				return
			}
		}
		io.WriteString(w, p.reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (p *pickyAI) hits() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.asked)
}

// A model that refuses temperature or response_format (status 400) is asked
// once more without both, and the check ends with its answer. The plain form
// is remembered for that address and model: the next question is one
// request. The refused try is a warn line without the answer's text.
func TestOpenAIPlainRequestAfter400(t *testing.T) {
	for _, refuses := range [][]string{{"temperature"}, {"response_format"}, {"temperature", "response_format"}} {
		p := &pickyAI{refuses: refuses, reply: hitReply("openai")}
		srv := p.server(t)
		lg, logged := logs.NewRecorder()
		r := aiRunner(t, "openai", srv.URL)
		r.Logger = lg
		vs := r.AI(context.Background(), acr, "title", "XSS here")
		if len(vs) != 1 || vs[0].Quote != "XSS" {
			t.Fatalf("%v: got %+v", refuses, vs)
		}
		if p.hits() != 2 {
			t.Fatalf("%v: %d requests", refuses, p.hits())
		}
		first, second := p.asked[0], p.asked[1]
		if first["temperature"] == nil || first["response_format"] == nil || len(second) != 2 || second["model"] != "m1" || second["messages"] == nil {
			t.Fatalf("%v: asked %v then %v", refuses, first, second)
		}
		again := logged.With(retryLine)
		if len(again) != 1 || again[0].Str("status") != "400" || again[0].Str("attempt") != "1" || again[0].Str("host") != strings.TrimPrefix(srv.URL, "http://") ||
			len(logged.With("ai call finished")) != 1 || len(logged.Records()) != 2 || strings.Contains(logged.Text(), "zq") {
			t.Fatalf("%v: log:\n%s", refuses, logged.Text())
		}
		// the next question, the Test button and a fix are one request each
		if vs := r.AI(context.Background(), acr, "title", "XSS there"); len(vs) != 1 || p.hits() != 3 || len(p.asked[2]) != 2 {
			t.Fatalf("%v: second question: %+v, %d requests", refuses, vs, p.hits())
		}
		if _, err := r.Ping(context.Background()); err != nil || p.hits() != 4 {
			t.Fatalf("%v: Test: %v, %d requests", refuses, err, p.hits())
		}
		// another model on the same address is asked in the full form first
		r.SetAIConf(config.AIConfig{Provider: "openai", BaseURL: srv.URL, Model: "m2", APIKeyEnv: "TEST_KEY"})
		if vs := r.AI(context.Background(), acr, "title", "XSS here"); len(vs) != 1 || p.hits() != 6 || p.asked[4]["temperature"] == nil {
			t.Fatalf("%v: another model: %+v, %d requests", refuses, vs, p.hits())
		}
	}
	// the Test button and a fix fall back too
	p := &pickyAI{refuses: []string{"temperature"}, reply: aiContent("openai", `{"violations":[]}`)}
	if _, err := aiRunner(t, "openai", p.server(t).URL).Ping(context.Background()); err != nil || p.hits() != 2 {
		t.Fatalf("Test: %v, %d requests", err, p.hits())
	}
	p = &pickyAI{refuses: []string{"response_format"}, reply: aiContent("openai", `{"body":"fixed"}`)}
	if body, err := aiRunner(t, "openai", p.server(t).URL).Fix(context.Background(), Violation{Rule: "acr"}, "rule", "Description", "old"); err != nil || body != "fixed" || p.hits() != 2 {
		t.Fatalf("Fix: %q %v, %d requests", body, err, p.hits())
	}
}

// The fallback is not one of the tries of a 429: a model that refuses
// temperature and then says "too many requests" twice is asked four times,
// the full form once.
func TestOpenAIPlainRequestThenRetries(t *testing.T) {
	var n atomic.Int32
	var full atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		switch k := n.Add(1); {
		case req["temperature"] != nil:
			full.Add(1)
			w.WriteHeader(400)
		case k <= 3:
			w.WriteHeader(429)
		default:
			io.WriteString(w, hitReply("openai"))
		}
	}))
	defer srv.Close()
	r := aiRunner(t, "openai", srv.URL)
	if vs := r.AI(context.Background(), acr, "title", "XSS here"); len(vs) != 1 || vs[0].Quote != "XSS" || n.Load() != 4 || full.Load() != 1 {
		t.Fatalf("got %+v after %d requests, %d in the full form", vs, n.Load(), full.Load())
	}
}

// A provider that answers 400 to the plain form too is the failure, after
// two requests and no more; the plain form is not remembered.
func TestOpenAI400Twice(t *testing.T) {
	f := &fakeAI{status: 400, body: func(map[string]any) string { return "zqbody7f3kq" }}
	r := aiRunner(t, "openai", f.server(t).URL)
	var waits atomic.Int32
	r.wait = func(context.Context, time.Duration) error { waits.Add(1); return nil }
	for i := range 2 {
		vs := r.AI(context.Background(), acr, "title", "x")
		if len(vs) != 1 || vs[0].Message != "AI check failed: HTTP 400" || int(f.hits.Load()) != 2*(i+1) || waits.Load() != 0 {
			t.Fatalf("call %d: %+v, %d requests, %d waits", i, vs, f.hits.Load(), waits.Load())
		}
	}
}

// An OpenAI answer cut at the model's limit, or withheld by the provider's
// filter, is a failed check and is not kept, even when its start reads as a
// whole reply. An answer that names no reason, or "stop", is read.
func TestOpenAIFinishReason(t *testing.T) {
	reply := func(reason string) string {
		choice := map[string]any{"message": map[string]string{"content": `{"violations":[]} and then`}}
		if reason != "" {
			choice["finish_reason"] = reason
		}
		b, _ := json.Marshal(map[string]any{"choices": []any{choice}})
		return string(b)
	}
	for reason, want := range map[string]string{
		"length":         "AI check failed: the reply was cut off",
		"content_filter": "AI check failed: the provider's filter withheld the reply",
		"":               "",
		"stop":           "",
	} {
		f := &fakeAI{body: func(map[string]any) string { return reply(reason) }}
		r := aiRunner(t, "openai", f.server(t).URL)
		for range 2 {
			vs := r.AI(context.Background(), acr, "title", "x")
			if want == "" && len(vs) != 0 || want != "" && (len(vs) != 1 || vs[0].Target != "ai" || vs[0].Message != want) {
				t.Fatalf("%q: got %+v", reason, vs)
			}
		}
		if hits := f.hits.Load(); want == "" && hits != 1 || want != "" && hits != 2 {
			t.Errorf("%q: %d requests", reason, hits)
		}
		if _, err := r.Ping(context.Background()); (err == nil) != (want == "") {
			t.Errorf("%q: Test: %v", reason, err)
		}
	}
}

// The provider's key and the finding's text go to the configured address
// only: a redirect to another host is not followed.
func TestAIFollowsNoRedirectToAnotherHost(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic"} {
		var got atomic.Int32
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.Add(1)
			w.Write([]byte(hitReply(provider)))
		}))
		defer other.Close()
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
		}))
		defer first.Close()
		r := aiRunner(t, provider, first.URL)
		vs := r.AI(context.Background(), acr, "title", "XSS here")
		if len(vs) != 1 || vs[0].Target != "ai" || !strings.Contains(vs[0].Message, "AI check failed") {
			t.Fatalf("%s: got %+v", provider, vs)
		}
		if got.Load() != 0 {
			t.Fatalf("%s: the other host got %d requests", provider, got.Load())
		}
	}
}
