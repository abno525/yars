package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// fixedEnv has had one Fix with AI run to its end: an AI commit and an AI
// reply in the check's thread.
func fixedEnv(t *testing.T) *env {
	t.Helper()
	e, _ := fixEnv(t, true)
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 200 {
		t.Fatalf("fix %d %s", rec.Code, rec.Body.String())
	}
	e.srv.Store.WaitChecks()
	return e
}

var aiReplyRe = regexp.MustCompile(`<strong>alice</strong><span class="tag ai">AI</span>`)

func TestChatMarksAIReply(t *testing.T) {
	e := fixedEnv(t)
	b := e.do(t, "bob", "GET", fpath+"/chat?all=1", nil, hxReq).Body.String()
	if !aiReplyRe.MatchString(b) {
		t.Fatalf("no AI mark on the reply:\n%s", b)
	}
	// the check thread's own root is not marked
	if n := strings.Count(b, `class="tag ai"`); n != 1 {
		t.Fatalf("%d AI marks:\n%s", n, b)
	}
}

func TestHistoryMarksAICommit(t *testing.T) {
	e := fixedEnv(t)
	b := e.do(t, "bob", "GET", fshort+"/history", nil, nil).Body.String()
	if strings.Contains(b, "AI for alice") {
		t.Fatalf("the git name is shown:\n%s", b)
	}
	if !regexp.MustCompile(`<strong>alice</strong><span class="tag ai">AI</span> <span class="evact">edited Impact</span>`).MatchString(b) {
		t.Fatalf("no AI mark on the commit:\n%s", b)
	}
	// alice's own edit before it is not marked
	if !strings.Contains(b, `<strong>alice</strong> <span class="evact">edited Impact</span>`) {
		t.Fatalf("alice's own edit:\n%s", b)
	}
	// the selected commit's head too
	if !strings.Contains(b, `<h2>alice</h2><span class="tag ai">AI</span>`) {
		t.Fatalf("no AI mark in the commit's head:\n%s", b)
	}
}

// A save that meets the AI's commit names alice, marked AI, as History does.
func TestConflictMarksAICommit(t *testing.T) {
	e, f := fixEnv(t, true)
	ref, _ := e.srv.Store.Finding("acme", fdir)
	body, _ := ref.F.Section("Impact")
	base := store.BodyHash(body)
	e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq)
	e.srv.Store.WaitChecks()
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 1 {
		t.Fatalf("Fix called %d times", calls)
	}
	rec := e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"my line"}, "base": {base}}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code %d", rec.Code)
	}
	b := rec.Body.String()
	if strings.Contains(b, "AI for alice") || !regexp.MustCompile(`<h3 title="alice">alice<span class="tag ai">AI</span> · \d\d:\d\d</h3>`).MatchString(b) {
		t.Fatalf("conflict head:\n%s", between(b, `class="cdiff`, "</section>"))
	}
}
