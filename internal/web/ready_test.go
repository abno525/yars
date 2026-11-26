package web

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/workflow"
)

const softRule = "- id: soft\n  target: title\n  regex_forbid: 'SQL'\n  level: warning\n  message: say what SQL means\n"

// slotButton is the bar's button of an action, as drawn.
func slotButton(t *testing.T, b, act string) string {
	t.Helper()
	m := regexp.MustCompile(`<button[^>]*data-action="` + act + `"[^>]*>`).FindString(wfBar(t, b))
	if m == "" {
		t.Fatalf("no %s button:\n%s", act, wfBar(t, b))
	}
	return m
}

// D25: Sign off and Approve are disabled on the finding page while a check
// warning (not only an error) is open.
func TestOpenWarningDisablesSignOffAndApprove(t *testing.T) {
	e := setup(t)
	e.rules(t, softRule, nil)
	e.toVerification(t)
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if btn := slotButton(t, b, "clear"); !strings.Contains(btn, " disabled") {
		t.Fatalf("sign off enabled with an open warning: %s", btn)
	}
	if !strings.Contains(wfBar(t, b), ">1 warning open<") {
		t.Fatalf("state:\n%s", wfBar(t, b))
	}
	st := e.srv.Store
	if err := st.DismissWhy("acme", fdir, "soft", "", "SQL", "fine here", wBob); err != nil {
		t.Fatal(err)
	}
	e.checked(t, "acme", fdir)
	b = e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if btn := slotButton(t, b, "clear"); strings.Contains(btn, " disabled") {
		t.Fatalf("sign off disabled once dismissed: %s", btn)
	}
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String(); strings.Contains(slotButton(t, b, "approve"), " disabled") {
		t.Fatal("approve disabled on a clean finding")
	}
	if err := st.Undismiss("acme", fdir, "soft", "", "SQL", wBob); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String(); !strings.Contains(slotButton(t, b, "approve"), " disabled") {
		t.Fatal("approve enabled with an open warning")
	}
}

// D25: bulk Approve skips a finding with an open warning, with the
// warning as the reason, and approves the clean one.
func TestBulkApproveSkipsOpenChecks(t *testing.T) {
	e := setup(t)
	e.rules(t, softRule, nil)
	st := e.srv.Store
	// alice's two findings: "SQL injection" warns until dismissed, "CSRF"
	// is clean
	e.toVerification(t)
	if err := st.DismissWhy("acme", fdir, "soft", "", "SQL", "fine here", wBob); err != nil {
		t.Fatal(err)
	}
	e.checked(t, "acme", fdir)
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	clean := e.toSignedOff(t, "acme", "CSRF")
	if err := st.Undismiss("acme", fdir, "soft", "", "SQL", wBob); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"action": {"approve"}, "id": {"acme/" + fdir, "acme/" + clean}}
	b := e.do(t, "dora", "POST", "/inbox/bulk", form, nil).Body.String()
	if r := row(b, "acme/F-001"); !strings.Contains(r, `class="denied"`) || !strings.Contains(r, "say what SQL means") {
		t.Fatalf("warned row:\n%s", b)
	}
	if r := row(b, "acme/F-002"); !strings.Contains(r, `class="ok"`) {
		t.Fatalf("clean row:\n%s", b)
	}
	if e.status(t) != "verification" || e.statusOf(t, "acme", clean) != "complete" {
		t.Fatal("wrong statuses")
	}
}

// The open-checks filter of Ready to approve runs on every page a director
// loads (the nav badge): it reads each finding once, then again only after
// something changed.
func TestReadyToApproveCached(t *testing.T) {
	e := setup(t)
	e.rules(t, softRule, nil)
	e.toVerification(t)
	st := e.srv.Store
	st.DismissWhy("acme", fdir, "soft", "", "SQL", "fine here", wBob)
	e.checked(t, "acme", fdir)
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	runs := func() int {
		e.srv.openCache.mu.Lock()
		defer e.srv.openCache.mu.Unlock()
		return e.srv.openCache.runs
	}
	e.do(t, "dora", "GET", "/inbox", nil, nil)
	n := runs()
	if n == 0 {
		t.Fatal("not read")
	}
	e.do(t, "dora", "GET", "/inbox", nil, nil)
	e.do(t, "dora", "GET", "/notifications", nil, nil)
	if runs() != n {
		t.Fatalf("read again with nothing changed: %d then %d", n, runs())
	}
	st.Undismiss("acme", fdir, "soft", "", "SQL", wBob)
	if q := queue(e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(), "approve"); strings.Contains(q, "SQL injection") || runs() == n {
		t.Fatalf("a stale answer after the undismissal (%d reads):\n%s", runs(), q)
	}
}

// D25: Ready to approve leaves out a signed-off finding whose check run on
// its current content has an open warning; dismissed, it is listed again.
func TestReadyToApproveSkipsOpenChecks(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n", nil)
	e.toVerification(t)
	st := e.srv.Store
	e.checked(t, "acme", fdir)
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	approve := func() string { return queue(e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(), "approve") }
	if !strings.Contains(approve(), "SQL injection") {
		t.Fatal("clean signed-off finding not listed")
	}
	// a warning rule added after the sign-off, no run since: not listed,
	// Approve disabled on the page and refused by the store
	e.rules(t, softRule, nil)
	if q := approve(); strings.Contains(q, "SQL injection") {
		t.Fatalf("listed with a new open warning:\n%s", q)
	}
	if b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String(); !strings.Contains(slotButton(t, b, "approve"), " disabled") {
		t.Fatal("approve enabled with a new open warning")
	}
	if err := st.Transition("acme", fdir, workflow.Approve, "", wDora); err == nil || !strings.Contains(err.Error(), "say what SQL means") {
		t.Fatalf("store approve: %v", err)
	}
	e.rules(t, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n", nil)
	ref, _ := st.Finding("acme", fdir)
	id, err := st.DB().StartRun("acme", "F-001", ref.Hash, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	st.DB().TxFor("acme", func(tx *db.Tx) error {
		return tx.FinishRun(id, db.RunDone, "", []db.CheckResult{{Rule: "w", Level: "warning", QuoteHash: "1"}})
	})
	if q := approve(); strings.Contains(q, "SQL injection") {
		t.Fatalf("listed with an open warning:\n%s", q)
	}
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	if strings.Contains(b, `<span class="badge">1</span>`) {
		t.Fatalf("the nav badge still counts it")
	}
	st.DB().TxFor("acme", func(tx *db.Tx) error {
		return tx.Dismiss(db.Dismissal{Eng: "acme", Fid: "F-001", Rule: "w", QuoteHash: "1", Level: "warning", By: "bob"})
	})
	if !strings.Contains(approve(), "SQL injection") {
		t.Fatal("not listed once the warning is dismissed")
	}
}
