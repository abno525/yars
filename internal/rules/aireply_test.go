package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// aiContent is a provider's answer whose text is content.
func aiContent(provider, content string) string {
	var reply any
	if provider == "anthropic" {
		reply = map[string]any{"content": []any{map[string]string{"type": "text", "text": content}}}
	} else {
		reply = map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": content}}}}
	}
	b, _ := json.Marshal(reply)
	return string(b)
}

// A reply without the violations list is a failed check, not a pass: it is a
// warning, it is not kept, and its words quote nothing of the reply. An
// empty list is the pass, and is kept.
func TestAIReplyNeedsViolations(t *testing.T) {
	for _, provider := range []string{"openai", "anthropic"} {
		for _, content := range []string{`{}`, `{"violations":null}`, `{"answer":"zqfine7f3kq"}`, `{"error":"zqfine7f3kq"}`, `{"violations":"zqfine7f3kq"}`, `{"violations":{"quote":"x"}}`} {
			f := &fakeAI{body: func(map[string]any) string { return aiContent(provider, content) }}
			r := aiRunner(t, provider, f.server(t).URL)
			for range 2 {
				vs := r.AI(context.Background(), acr, "title", "some text")
				if len(vs) != 1 || vs[0].Target != "ai" || vs[0].Level != "warning" || vs[0].Message != "AI check failed: reply has no violations list" {
					t.Fatalf("%s %s: got %+v", provider, content, vs)
				}
			}
			if f.hits.Load() != 2 {
				t.Errorf("%s %s: %d requests, the failure was kept", provider, content, f.hits.Load())
			}
			if _, err := r.Ping(context.Background()); err == nil || strings.Contains(err.Error(), "zq") {
				t.Errorf("%s %s: Test says %v", provider, content, err)
			}
		}
		f := &fakeAI{body: func(map[string]any) string { return aiContent(provider, `{"violations":[]}`) }}
		r := aiRunner(t, provider, f.server(t).URL)
		for range 2 {
			if vs := r.AI(context.Background(), acr, "title", "some text"); len(vs) != 0 {
				t.Fatalf("%s: an empty list: %+v", provider, vs)
			}
		}
		if f.hits.Load() != 1 {
			t.Errorf("%s: an empty list is not kept: %d requests", provider, f.hits.Load())
		}
		if _, err := r.Ping(context.Background()); err != nil {
			t.Errorf("%s: Test: %v", provider, err)
		}
	}
}
