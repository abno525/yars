package web

import (
	"regexp"
	"strings"
	"testing"

	"yars/internal/db"
	"yars/internal/workflow"
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
	if err := st.Dismiss("acme", fdir, "soft", "SQL", wBob); err != nil {
		t.Fatal(err)
	}
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

// D25: Ready to approve leaves out a signed-off finding whose check run on
// its current content has an open warning; dismissed, it is listed again.
func TestReadyToApproveSkipsOpenChecks(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	st := e.srv.Store
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	approve := func() string { return queue(e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(), "approve") }
	if !strings.Contains(approve(), "SQL injection") {
		t.Fatal("clean signed-off finding not listed")
	}
	ref, _ := st.Finding("acme", fdir)
	id, err := st.DB().StartRun("acme", "F-001", ref.Hash, "bob")
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
