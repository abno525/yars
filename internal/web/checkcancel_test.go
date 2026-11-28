package web

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/rules"
)

// cancelSlot is the strip head's cancel place: the button's tag while a run
// can be stopped, else the empty slot.
func cancelSlot(t *testing.T, body string) string {
	t.Helper()
	head := between(checksPanel(t, body), "<summary", "</summary>")
	acts := head[strings.Index(head, `<div class="actions">`):]
	if strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(acts, `<div class="actions">`)), `<span class="slot w96" data-cancel-slot></span>`) {
		return "slot"
	}
	return between(acts, `<button type="button" class="btn ghost w96"`, `</button>`)
}

// A check under way is cancelled from the strip: the head's first place is
// an empty slot of the button's width while nothing runs and the Cancel
// button while a check does. The cancel kills the running script, leaves no
// run, and answers the bar and the strip.
func TestChecksCancelCheck(t *testing.T) {
	e := setupSerial(t)
	began := filepath.Join(t.TempDir(), "began")
	e.rules(t, "- id: slow\n  level: warning\n  script: slow.sh\n", map[string]string{"slow.sh": "cat >/dev/null; echo run >> " + began + "; sleep 9; echo '[]'\n"})
	if got := cancelSlot(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); got != "slot" {
		t.Fatalf("nothing runs: %q", got)
	}
	// nothing to cancel: words, as a toast for htmx
	rec := e.do(t, "alice", "POST", fpath+"/checks/cancel", nil, hxReq)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "no check or fix of this finding is running") {
		t.Fatalf("nothing to cancel: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/cancel", nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("nothing to cancel, without htmx: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks", nil, hxReq); rec.Code != 200 {
		t.Fatalf("check %d", rec.Code)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if b, _ := os.ReadFile(began); len(b) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the script did not start")
		}
	}
	// anyone who sees the finding has the button, as they have Check
	btn := cancelSlot(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String())
	for _, want := range []string{` hx-post="/e/acme/f/001/checks/cancel"`, ` hx-target="#workflow"`, ` hx-swap="outerHTML"`, ` id="checks-cancel"`, ` data-kskip`, `>Cancel`} {
		if !strings.Contains(btn, want) {
			t.Fatalf("the button lacks %s: %q", want, btn)
		}
	}
	if rec := e.do(t, "bob", "GET", fpath+"/checks/cancel", nil, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", fpath+"/checks/cancel", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST: %d", rec.Code)
	}
	if !e.srv.Store.CheckRunning("acme", "F-001") {
		t.Fatal("a request that cancels nothing ended the run")
	}
	rec = e.do(t, "bob", "POST", fpath+"/checks/cancel", nil, hxReq)
	if b := rec.Body.String(); rec.Code != 200 || !strings.Contains(b, `id="workflow"`) || !strings.Contains(b, `id="checks"`) {
		t.Fatalf("cancel: %d\n%s", rec.Code, b)
	}
	e.srv.Store.WaitChecks()
	if st, err := e.srv.Store.CheckStatus("acme", fdir); err != nil || st.HasRun || st.Running {
		t.Fatalf("after the cancel: %+v %v", st, err)
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if got := cancelSlot(t, b); got != "slot" {
		t.Fatalf("after the cancel: %q", got)
	}
	if strings.Contains(checksPanel(t, b), "rule failed") {
		t.Fatalf("the killed script's failure is shown:\n%s", checksPanel(t, b))
	}
}

// ctxFixer is webFixer whose Fix also returns when its context ends, as a
// provider call does; it then still answers a text.
type ctxFixer struct{ *webFixer }

func (f ctxFixer) Fix(ctx context.Context, _ rules.Violation, _, body string) (string, error) {
	f.mu.Lock()
	f.calls++
	block := f.block
	f.mu.Unlock()
	select {
	case <-block:
	case <-ctx.Done():
	}
	return strings.ReplaceAll(body, "foo", "bar"), nil
}

// A Fix with AI under way is cancelled by those who may edit the finding:
// they have the button, the others the empty slot and a refusal. Nothing is
// committed after the cancel and no reply is posted.
func TestChecksCancelFix(t *testing.T) {
	e, f := fixEnv(t, true)
	f.block = make(chan struct{})
	e.srv.Store.Linter = ctxFixer{f}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 200 {
		t.Fatalf("fix %d %s", rec.Code, rec.Body.String())
	}
	if btn := cancelSlot(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); !strings.Contains(btn, `id="checks-cancel"`) {
		t.Fatalf("the author while fixing: %q", btn)
	}
	// approved meanwhile: the author may no longer edit it, a director may
	e.complete(t)
	if got := cancelSlot(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); got != "slot" {
		t.Fatalf("someone who may not edit, while fixing: %q", got)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/cancel", nil, hxReq); rec.Code != http.StatusForbidden {
		t.Fatalf("a cancel of the fix by someone who may not edit: %d %s", rec.Code, rec.Body.String())
	}
	if !e.srv.Store.FixRunning("acme", "F-001") {
		t.Fatal("a refused cancel ended the fix")
	}
	if btn := cancelSlot(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); !strings.Contains(btn, `id="checks-cancel"`) {
		t.Fatalf("a director while fixing: %q", btn)
	}
	if rec := e.do(t, "dora", "POST", fpath+"/checks/cancel", nil, hxReq); rec.Code != 200 {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	e.srv.Store.WaitChecks()
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := ref.F.Section("Impact"); !strings.Contains(body, "foo") {
		t.Fatalf("committed after the cancel: %q", body)
	}
	msgs, err := e.srv.Store.Chat("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if strings.Contains(m.Text, "ixed") {
			t.Fatalf("a reply after the cancel: %+v", m)
		}
	}
	if got := cancelSlot(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); got != "slot" {
		t.Fatalf("after the cancel: %q", got)
	}
}
