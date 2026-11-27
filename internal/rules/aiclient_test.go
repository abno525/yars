package rules

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
