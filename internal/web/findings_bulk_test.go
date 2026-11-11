package web

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"yars/internal/workflow"
)

var hxReq = map[string]string{"HX-Request": "true"}

// frow is the findings-list row of a finding folder ("" when missing).
func frow(b, dir string) string { return between(b, `data-fid="`+dir+`"`, "</tr>") }

// toolbarOf is the bulk toolbar above the findings table.
func toolbarOf(b string) string { return between(b, `class="fbulk"`, "<table") }

var actRe = regexp.MustCompile(`data-act="([a-z_]+)"`)

func menuActs(bar string) []string {
	var out []string
	for _, m := range actRe.FindAllStringSubmatch(bar, -1) {
		out = append(out, m[1])
	}
	return out
}

// The bulk bar is always above the findings table; Set state lists the
// role's targets, Assign reviewers is for reviewers and directors.
func TestFindingsBulkBar(t *testing.T) {
	e := setup(t)
	d2 := e.second(t, "bob")
	cases := map[string][]string{
		"alice": {"submit", "take_back", "report", "withdraw"},
		"bob":   {"clear", "return"},
		"dora":  {"take_back", "submit", "approve", "report", "withdraw"},
	}
	pages := map[string]string{}
	for u, want := range cases {
		b := e.do(t, u, "GET", "/e/acme", nil, nil).Body.String()
		pages[u] = b
		bar := toolbarOf(b)
		if bar == "" {
			t.Fatalf("%s: no bulk bar:\n%s", u, b)
		}
		if got := menuActs(bar); !slices.Equal(got, want) {
			t.Errorf("%s menu %v, want %v", u, got, want)
		}
		if !strings.Contains(bar, ">0 selected<") || !strings.Contains(bar, `data-bulk-menu aria-haspopup="menu" aria-expanded="false" disabled`) {
			t.Errorf("%s: empty selection not shown or Set state enabled:\n%s", u, bar)
		}
		if assign := strings.Contains(bar, "Assign reviewers"); assign != (u != "alice") {
			t.Errorf("%s: Assign reviewers shown %v", u, assign)
		}
		if u == "alice" && !strings.Contains(bar, `<span class="slot w152"></span>`) {
			t.Errorf("pentester: no empty slot for Assign reviewers:\n%s", bar)
		}
		if !strings.Contains(bar, `class="bsum" role="status"></span>`) || !strings.Contains(bar, "data-bulk-clear") {
			t.Errorf("%s: summary slot or Clear missing:\n%s", u, bar)
		}
		// every table has a header row: the pick column has select-all
		if !strings.Contains(b, `<th class="col-pick"><input type="checkbox" data-pick-all aria-label="Select all"></th>`) {
			t.Errorf("%s: no select-all header", u)
		}
		if strings.Contains(b, "<th>Result</th>") {
			t.Errorf("%s: a Result column", u)
		}
	}
	// a pentester picks own findings only; reviewers and directors any
	a := pages["alice"]
	if !strings.Contains(frow(a, fdir), `name="id" value="`+fdir+`"`) || strings.Contains(frow(a, d2), `name="id"`) {
		t.Fatalf("alice's picks:\n%s\n%s", frow(a, fdir), frow(a, d2))
	}
	for _, u := range []string{"bob", "dora"} {
		if !strings.Contains(frow(pages[u], fdir), `name="id"`) || !strings.Contains(frow(pages[u], d2), `name="id"`) {
			t.Fatalf("%s cannot pick every row", u)
		}
	}
	// each row says which of the menu's targets it can reach
	if r := frow(a, fdir); !strings.Contains(r, `data-acts="submit withdraw"`) {
		t.Fatalf("alice F-001 acts: %s", r)
	}
	if r := frow(pages["bob"], fdir); !strings.Contains(r, `data-acts=""`) {
		t.Fatalf("bob F-001 acts: %s", r)
	}
	// Return and Withdraw ask for one reason in a panel over the table
	for _, u := range []string{"alice", "bob", "dora"} {
		dlg := between(pages[u], `class="bdlg"`, "</section>")
		if !strings.Contains(dlg, `<textarea name="reason"`) || !strings.Contains(dlg, `class="btn danger w112"`) || !strings.Contains(dlg, `class="btn secondary w96" data-bulk-cancel`) {
			t.Fatalf("%s reason panel:\n%s", u, dlg)
		}
	}
}

// Q12: the board offers bulk Approve only where it would work, as Ready to
// approve does: not for a finding without a finished check on its content
// while Require Check is on.
func TestBoardBulkApproveHidesGated(t *testing.T) {
	e := setup(t)
	e.rules(t, noneRule, nil)
	e.toVerification(t)
	st := e.srv.Store
	// signed off while Require Check was off; on again, with no check run
	if err := st.SetRequireCheck(false, "dora"); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRequireCheck(true, "dora"); err != nil {
		t.Fatal(err)
	}
	acts := func() string {
		r := frow(e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String(), fdir)
		_, rest, ok := strings.Cut(r, `data-acts="`)
		if !ok {
			t.Fatalf("no row:\n%s", r)
		}
		acts, _, _ := strings.Cut(rest, `"`)
		return acts
	}
	if a := acts(); strings.Contains(a, "approve") {
		t.Fatalf("approve offered without a check run: %q", a)
	}
	e.checked(t, "acme", fdir)
	if a := acts(); !strings.Contains(a, "approve") {
		t.Fatalf("approve not offered after a clean check: %q", a)
	}
}

// Running a bulk change re-renders the list: the summary says how many
// moved and how many were skipped, moved rows show their new status and
// skipped rows are tinted.
func TestFindingsBulkRun(t *testing.T) {
	e := setup(t)
	d2 := e.second(t, "bob")
	st := e.srv.Store
	if err := st.SetReviewers("acme", fdir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	post := func(user string, form url.Values) (int, string) {
		t.Helper()
		rec := e.do(t, user, "POST", "/e/acme/bulk", form, hxReq)
		return rec.Code, rec.Body.String()
	}
	code, b := post("alice", url.Values{"action": {"submit"}, "id": {fdir, d2}})
	if code != 200 || !strings.Contains(b, `id="findings"`) || strings.Contains(b, `id="bulk-result"`) {
		t.Fatalf("code %d:\n%s", code, b)
	}
	if !strings.Contains(toolbarOf(b), `<span class="mv">1 moved</span> <span class="sk">· 1 skipped</span>`) {
		t.Fatalf("summary:\n%s", toolbarOf(b))
	}
	if r := frow(b, fdir); !strings.Contains(r, "status-verification") || !strings.Contains(r, "checked") || strings.Contains(r, "skip") {
		t.Fatalf("moved row: %s", r)
	}
	if r := frow(b, d2); !strings.Contains(r, `class="skip"`) {
		t.Fatalf("skipped row: %s", r)
	}
	// the kept selection is counted
	if !strings.Contains(toolbarOf(b), ">1 selected<") {
		t.Fatalf("selection count:\n%s", toolbarOf(b))
	}
	if e.status(t) != "verification" || e.statusOf(t, "acme", d2) != "draft" {
		t.Fatal("statuses after submit")
	}

	// the author takes it back, without a reason
	if _, b = post("alice", url.Values{"action": {"take_back"}, "id": {fdir}}); e.status(t) != "draft" || !strings.Contains(toolbarOf(b), "1 moved") {
		t.Fatalf("take back: %s\n%s", e.status(t), toolbarOf(b))
	}
	if !strings.Contains(e.events(t), "alice:take_back") {
		t.Fatalf("events %q", e.events(t))
	}
	post("alice", url.Values{"action": {"submit"}, "id": {fdir}})

	// a reviewer signs off and returns, with one reason for all
	if _, b = post("bob", url.Values{"action": {"clear"}, "id": {fdir}}); !strings.Contains(frow(b, fdir), "status-signed-off") {
		t.Fatalf("after sign off: %s", frow(b, fdir))
	}
	if rec := e.do(t, "bob", "POST", "/e/acme/bulk", url.Values{"action": {"return"}, "id": {fdir}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("return without reason code %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", "/e/acme/bulk", url.Values{"action": {"submit"}, "id": {fdir}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reviewer submit code %d", rec.Code)
	}
	post("bob", url.Values{"action": {"return"}, "id": {fdir}, "reason": {"add proof"}})
	ref, _ := st.Finding("acme", fdir)
	if m := ref.F.Meta; m.Status != "draft" || m.Returned == nil || m.Returned.Reason != "add proof" || m.Returned.By != "bob" {
		t.Fatalf("after return: %s %+v", m.Status, m.Returned)
	}

	// the director approves; the author marks it reported
	post("alice", url.Values{"action": {"submit"}, "id": {fdir}})
	post("bob", url.Values{"action": {"clear"}, "id": {fdir}})
	if post("dora", url.Values{"action": {"approve"}, "id": {fdir}}); e.status(t) != "complete" {
		t.Fatalf("after approve: %s", e.status(t))
	}
	if post("alice", url.Values{"action": {"report"}, "id": {fdir}}); e.status(t) != "reported" {
		t.Fatalf("after report: %s", e.status(t))
	}
}

// Withdraw needs a reason, given once for all selected rows.
func TestFindingsBulkWithdraw(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "POST", "/e/acme/bulk", url.Values{"action": {"withdraw"}, "id": {fdir}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("withdraw without reason code %d", rec.Code)
	}
	e.do(t, "alice", "POST", "/e/acme/bulk", url.Values{"action": {"withdraw"}, "id": {fdir}, "reason": {"duplicate"}}, hxReq)
	if e.status(t) != "withdrawn" {
		t.Fatalf("status %s", e.status(t))
	}
}

// The bar posts with the list's filter and sort, so the list comes back the
// same; an archived engagement has no bulk bar.
func TestFindingsBulkKeepsQuery(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/e/acme?sort=title", nil, nil).Body.String()
	if !strings.Contains(b, `hx-post="/e/acme/bulk?sort=title"`) {
		t.Fatalf("bulk form URL:\n%s", toolbarOf(b))
	}
	b = e.do(t, "dora", "POST", "/e/acme/bulk?sort=title", url.Values{"action": {"submit"}, "id": {fdir}}, hxReq).Body.String()
	if !strings.Contains(b, "Title ↑") {
		t.Fatalf("sort lost:\n%s", b)
	}
	if err := e.srv.Store.Archive("acme", wDora); err != nil {
		t.Fatal(err)
	}
	b = e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	if strings.Contains(b, `class="fbulk"`) || strings.Contains(b, `name="id"`) {
		t.Fatal("archived engagement has a bulk bar")
	}
}
