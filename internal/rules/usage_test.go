package rules

import (
	"context"
	"sync"
	"testing"
)

// usageLog collects what OnUsage is told.
type usageLog struct {
	mu  sync.Mutex
	got []Usage
}

func (l *usageLog) add(u Usage) {
	l.mu.Lock()
	l.got = append(l.got, u)
	l.mu.Unlock()
}

func (l *usageLog) all() []Usage {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Usage(nil), l.got...)
}

const openAIUsage = `{"choices":[{"message":{"content":"{\"violations\":[]}"}}],"usage":{"prompt_tokens":12,"completion_tokens":3}}`

// D24: every call to the provider is one usage, with its tokens, the rule
// and who the run is for.
func TestUsageRecordedPerCall(t *testing.T) {
	srv := (&fakeAI{body: func(map[string]any) string { return openAIUsage }}).server(t)
	r := aiRunner(t, "openai", srv.URL)
	var log usageLog
	r.OnUsage = log.add
	ctx := WithCaller(context.Background(), Caller{User: "alice", Eng: "acme", Fid: "F-001"})
	r.AI(ctx, acr, "title", "XSS here")
	got := log.all()
	if len(got) != 1 {
		t.Fatalf("usage %+v", got)
	}
	u := got[0]
	if u.Purpose != "rule" || u.Rule != "acr" || u.In != 12 || u.Out != 3 || !u.OK || u.Provider != "openai" || u.Model != "m1" ||
		u.User != "alice" || u.Eng != "acme" || u.Fid != "F-001" || u.Took <= 0 {
		t.Fatalf("usage %+v", u)
	}
	// the admin's Test is a call too
	if _, err := r.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := log.all(); len(got) != 2 || got[1].Purpose != "test" || got[1].Rule != "" {
		t.Fatalf("ping usage %+v", got)
	}
}

// D24, Review focus 3: a reply served from the cache costs nothing.
func TestCachedReplyIsNotUsage(t *testing.T) {
	srv := (&fakeAI{body: func(map[string]any) string { return openAIUsage }}).server(t)
	r := aiRunner(t, "openai", srv.URL)
	var log usageLog
	r.OnUsage = log.add
	r.AI(context.Background(), acr, "title", "same text")
	r.AI(context.Background(), acr, "title", "same text")
	if got := log.all(); len(got) != 1 {
		t.Fatalf("usage %+v", got)
	}
}

// D24: a call that failed is a call (OK false).
func TestFailedCallIsUsage(t *testing.T) {
	srv := (&fakeAI{status: 500, body: func(map[string]any) string { return "oops" }}).server(t)
	r := aiRunner(t, "openai", srv.URL)
	var log usageLog
	r.OnUsage = log.add
	r.AI(context.Background(), acr, "title", "x")
	if got := log.all(); len(got) != 1 || got[0].OK || got[0].Purpose != "rule" {
		t.Fatalf("usage %+v", got)
	}
}

// D24: Anthropic reports its tokens in other fields.
func TestAnthropicUsage(t *testing.T) {
	srv := (&fakeAI{body: func(map[string]any) string {
		return `{"content":[{"type":"text","text":"{\"violations\":[]}"}],"usage":{"input_tokens":40,"output_tokens":7}}`
	}}).server(t)
	r := aiRunner(t, "anthropic", srv.URL)
	var log usageLog
	r.OnUsage = log.add
	r.AI(context.Background(), acr, "title", "SSRF in export")
	if got := log.all(); len(got) != 1 || got[0].In != 40 || got[0].Out != 7 || !got[0].OK || got[0].Provider != "anthropic" {
		t.Fatalf("usage %+v", got)
	}
}
