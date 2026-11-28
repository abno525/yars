package rules

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// With the spend limit reached no rule check and no fix calls the provider:
// an AI rule reports the notice a missing provider reports (a warning with
// target ai, so the check goes on and the gate stays open), a fix is refused
// with words. A reply kept before is still served, since it costs nothing,
// the notice itself is not kept, and the admin's Test still calls.
func TestAILimitReached(t *testing.T) {
	var calls atomic.Int32
	srv := (&fakeAI{body: func(map[string]any) string { calls.Add(1); return openAIUsage }}).server(t)
	r := aiRunner(t, "openai", srv.URL)
	var log usageLog
	r.OnUsage = log.add
	ctx := WithCaller(context.Background(), Caller{User: "alice", Eng: "acme", Fid: "F-001"})
	if vs := r.AI(ctx, acr, "title", "kept text"); len(vs) != 0 || calls.Load() != 1 {
		t.Fatalf("before the limit: %+v, %d calls", vs, calls.Load())
	}
	var over atomic.Bool
	over.Store(true)
	r.OverLimit = over.Load

	vs := r.AI(ctx, acr, "title", "new text")
	if len(vs) != 1 || vs[0].Target != "ai" || vs[0].Level != "warning" || vs[0].Fail != "" || vs[0].Message != "AI rules skipped: the AI spend limit is reached" {
		t.Fatalf("over the limit: %+v", vs)
	}
	if calls.Load() != 1 || len(log.all()) != 1 {
		t.Fatalf("the provider was called over the limit: %d calls, usage %+v", calls.Load(), log.all())
	}
	if vs := r.AI(ctx, acr, "title", "kept text"); len(vs) != 0 || calls.Load() != 1 {
		t.Fatalf("a kept reply over the limit: %+v, %d calls", vs, calls.Load())
	}
	if _, err := r.Fix(ctx, Violation{Rule: "acr", Message: "m", Quote: "q"}, "Expand acronyms", "Impact", "the body"); !errors.Is(err, ErrAILimit) || err.Error() != "the AI spend limit is reached" {
		t.Fatalf("a fix over the limit: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("a fix called the provider over the limit: %d calls", calls.Load())
	}
	// the engine says it, for the store's refusal of Fix with AI
	e := &Engine{Runner: r}
	if !e.AIOverLimit() || !e.AIConfigured() {
		t.Fatalf("engine: over %v, configured %v", e.AIOverLimit(), e.AIConfigured())
	}
	// the admin's Test is not held
	if _, err := r.Ping(ctx); err != nil || calls.Load() != 2 {
		t.Fatalf("Test over the limit: %v, %d calls", err, calls.Load())
	}
	// under the limit again: the notice was not kept, the text is asked
	over.Store(false)
	if vs := r.AI(ctx, acr, "title", "new text"); len(vs) != 0 || calls.Load() != 3 {
		t.Fatalf("under the limit again: %+v, %d calls", vs, calls.Load())
	}
	if e.AIOverLimit() {
		t.Fatal("engine: still over")
	}
}
