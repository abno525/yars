package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/notify"
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

// One press of Check stale ends in one check event per finding. The author
// is told of such a check only when it left an open error; a check with
// nothing to do sends no notice (pre1 7.12).
func TestInboxCheckStaleNotices(t *testing.T) {
	e := setupSerial(t)
	e.toVerification(t)
	const one = "- id: none\n  target: title\n  regex_forbid: 'zzz'\n"
	e.rules(t, one, nil)
	st := e.srv.Store
	d := st.DB()
	if err := d.SetNotify("alice", notify.Check, "app", true); err != nil {
		t.Fatal(err)
	}
	notices := func() []string {
		t.Helper()
		st.WaitChecks()
		e.srv.Notifier.Wait()
		l, err := d.Notifications("alice", 50)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for i := len(l) - 1; i >= 0; i-- { // oldest first
			if l[i].Event == notify.Check {
				out = append(out, l[i].Actor+": "+l[i].Text)
			}
		}
		return out
	}
	press := func() {
		t.Helper()
		if rec := e.do(t, "bob", "POST", "/inbox/check-stale", url.Values{}, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("press: %d\n%s", rec.Code, rec.Body.String())
		}
	}
	// a check the reviewer starts on the finding tells its author, as before
	e.do(t, "bob", "POST", fpath+"/checks", url.Values{}, nil)
	if got := notices(); !slices.Equal(got, []string{"bob: 0 errors · 0 warnings"}) {
		t.Fatalf("after bob's own check: %q", got)
	}
	// a rule changes and finds nothing: the press starts the check, no notice
	e.rules(t, one+"- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	first, _, _ := d.LatestRun("acme", "F-001")
	press()
	if got := notices(); len(got) != 1 {
		t.Fatalf("a check with nothing to do told the author: %q", got)
	}
	if run, _, _ := d.LatestRun("acme", "F-001"); run.ID == first.ID {
		t.Fatal("the press started no check")
	}
	// a rule that leaves an error: the author is told
	e.rules(t, one+"- id: any\n  target: title\n  regex_forbid: '^.'\n", nil)
	press()
	if got := notices(); len(got) != 2 || got[1] != "bob: 1 error · 0 warnings" {
		t.Fatalf("a check that left an error: %q", got)
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
