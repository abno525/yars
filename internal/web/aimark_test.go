package web

import (
	"regexp"
	"strings"
	"testing"
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
}
