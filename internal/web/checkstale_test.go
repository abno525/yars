package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// The simple workflow has no review and no approve queue, and Require Check
// gates Complete there: Check stale counts and starts the viewer's own
// drafts whose check the rules left out of date (pre1 7.12).
func TestInboxCheckStaleSimple(t *testing.T) {
	e := setupSimple(t)
	const one = "- id: none\n  target: title\n  regex_forbid: 'zzz'\n"
	const fd = "F-001-sql-injection"
	e.rules(t, one, nil)
	st := e.srv.Store
	latest := func() int64 {
		t.Helper()
		run, _, err := st.DB().LatestRun("acme", "F-001")
		if err != nil {
			t.Fatal(err)
		}
		return run.ID
	}
	head := func(who string) string {
		t.Helper()
		b := e.do(t, who, "GET", "/inbox", nil, nil).Body.String()
		return between(b, `<div class="titlerow">`, `</form>`)
	}
	const off = `<span class="qcnt zero">0</span>` + "\n    " + `<button class="btn secondary w152" disabled>Check stale</button>`
	const on = `<span class="qcnt">1</span>` + "\n    " + `<button class="btn secondary w152">Check stale</button>`
	press := func(who string) {
		t.Helper()
		rec := e.do(t, who, "POST", "/inbox/check-stale", url.Values{}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/inbox" {
			t.Fatalf("%s: %d to %q\n%s", who, rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		st.WaitChecks()
	}
	// never checked: nothing is stale
	if h := head("anna"); !strings.Contains(h, off) {
		t.Fatalf("never checked:\n%s", h)
	}
	e.do(t, "anna", "POST", "/e/acme/f/"+fd+"/checks", url.Values{}, nil)
	st.WaitChecks()
	first := latest()
	if first == 0 {
		t.Fatal("no check ran")
	}
	if h := head("anna"); !strings.Contains(h, off) {
		t.Fatalf("checked with the rules as they are:\n%s", h)
	}
	e.rules(t, one+"- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	if g, err := st.CheckGate("acme", fd); err != nil || g != store.GateRules {
		t.Fatalf("the gate after a rule change: %q %v", g, err)
	}
	if h := head("anna"); !strings.Contains(h, on) {
		t.Fatalf("the author's inbox after a rule change:\n%s", h)
	}
	// another account's draft is not theirs to start
	if h := head("ben"); !strings.Contains(h, off) {
		t.Fatalf("another account's inbox:\n%s", h)
	}
	press("ben")
	if latest() != first {
		t.Fatal("an account that did not write the draft started its check")
	}
	press("anna")
	if latest() == first {
		t.Fatal("no check was started")
	}
	if g, err := st.CheckGate("acme", fd); err != nil || g != "" {
		t.Fatalf("the gate after the new check: %q %v", g, err)
	}
	if h := head("anna"); !strings.Contains(h, off) {
		t.Fatalf("after the check:\n%s", h)
	}
}

// After a rule changes, every checked finding waits for a new check. The
// inbox counts the findings of the viewer's review and approve queues whose
// check is out of date for that reason alone, and Check stale starts their
// checks in one press. The button's place is always drawn (pre1 7.12).
func TestInboxCheckStale(t *testing.T) {
	e := setupSerial(t)
	e.toVerification(t)
	const one = "- id: none\n  target: title\n  regex_forbid: 'zzz'\n"
	e.rules(t, one, nil)
	st := e.srv.Store
	ref, err := st.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	latest := func() int64 {
		t.Helper()
		run, _, err := st.DB().LatestRun("acme", ref.F.Meta.ID)
		if err != nil {
			t.Fatal(err)
		}
		return run.ID
	}
	head := func(who string) string {
		t.Helper()
		b := e.do(t, who, "GET", "/inbox", nil, nil).Body.String()
		return between(b, `<div class="titlerow">`, `</form>`)
	}
	const off = `<span class="qcnt zero">0</span>` + "\n    " + `<button class="btn secondary w152" disabled>Check stale</button>`
	const on = `<span class="qcnt">1</span>` + "\n    " + `<button class="btn secondary w152">Check stale</button>`
	press := func(who string) {
		t.Helper()
		rec := e.do(t, who, "POST", "/inbox/check-stale", url.Values{}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/inbox" {
			t.Fatalf("%s: %d to %q\n%s", who, rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		st.WaitChecks()
	}
	// never checked: that is not "the rules changed"; the slot is there, off
	if h := head("bob"); !strings.Contains(h, `action="/inbox/check-stale"`) || !strings.Contains(h, off) {
		t.Fatalf("nothing stale:\n%s", h)
	}
	press("bob")
	if latest() != 0 {
		t.Fatal("a finding never checked was started")
	}
	e.do(t, "bob", "POST", fpath+"/checks", url.Values{}, nil)
	st.WaitChecks()
	first := latest()
	if h := head("bob"); !strings.Contains(h, off) {
		t.Fatalf("checked with the rules as they are:\n%s", h)
	}
	// a rule changes: the reviewer's queue has one stale check
	e.rules(t, one+"- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	if h := head("bob"); !strings.Contains(h, on) {
		t.Fatalf("after a rule change:\n%s", h)
	}
	// the author has it in no queue of theirs: nothing to start
	if h := head("alice"); !strings.Contains(h, off) {
		t.Fatalf("the author's inbox:\n%s", h)
	}
	press("alice")
	if latest() != first {
		t.Fatal("an account without the finding in its queues started a check")
	}
	press("bob")
	second := latest()
	if second == first {
		t.Fatal("no check was started")
	}
	if g, err := st.CheckGate("acme", fdir); err != nil || g != "" {
		t.Fatalf("the gate after the new check: %q %v", g, err)
	}
	if h := head("bob"); !strings.Contains(h, off) {
		t.Fatalf("after the checks:\n%s", h)
	}
	// nothing stale: a second press starts none
	press("bob")
	if latest() != second {
		t.Fatal("a second press started a check again")
	}
	// the text changed too: that finding needs its author's look, not a press
	e.rules(t, one, nil)
	if err := st.UpdateSection("acme", fdir, "Impact", "Other text.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	if h := head("bob"); !strings.Contains(h, off) {
		t.Fatalf("stale by its text:\n%s", h)
	}
	press("bob")
	if latest() != second {
		t.Fatal("a finding whose text changed was started")
	}
}
