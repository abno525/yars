package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"yars/internal/store"
	"yars/internal/workflow"
)

// bulkPost posts the engagement's bulk form as htmx does.
func (e *env) bulkPost(t *testing.T, user string, form url.Values) (int, string) {
	t.Helper()
	rec := e.do(t, user, "POST", "/e/acme/bulk", form, hxReq)
	return rec.Code, rec.Body.String()
}

// summaryOf is the bar's "N moved · M skipped" text.
func summaryOf(b string) string {
	return between(toolbarOf(b), `class="bsum" role="status">`, "</span></span>")
}

// Every refusal of a bulk run, per row: a skipped row with its reason, never
// a 500; a refusal of the whole request: 4xx with nothing changed.
func TestBulkDenyRows(t *testing.T) {
	e := setup(t)
	e.toVerification(t) // F-001: alice's, bob reviews
	d2 := e.second(t, "alice")
	e.pen2(t)

	// a pentester on someone else's finding: no checkbox, and by hand a skip
	b := e.do(t, "pen2", "GET", "/e/acme", nil, nil).Body.String()
	if strings.Contains(frow(b, fdir), `name="id"`) {
		t.Fatal("pen2 can pick alice's finding")
	}
	code, b := e.bulkPost(t, "pen2", url.Values{"action": {"take_back"}, "id": {fdir}})
	if code != 200 || !strings.Contains(summaryOf(b), "0 moved") || !strings.Contains(frow(b, fdir), "only the author") || e.status(t) != "verification" {
		t.Fatalf("pen2 take back of alice's: %d %s\n%s", code, e.status(t), frow(b, fdir))
	}

	// a reviewer not assigned: Clear and Return skipped, row still pickable
	b = e.do(t, "carol", "GET", "/e/acme", nil, nil).Body.String()
	if r := frow(b, fdir); !strings.Contains(r, `name="id"`) || !strings.Contains(r, `data-acts=""`) {
		t.Fatalf("carol's row: %s", r)
	}
	for _, f := range []url.Values{{"action": {"clear"}, "id": {fdir}}, {"action": {"return"}, "id": {fdir}, "reason": {"x"}}} {
		if _, b := e.bulkPost(t, "carol", f); !strings.Contains(frow(b, fdir), `class="skip"`) || e.status(t) != "verification" {
			t.Fatalf("carol %s: %s", f.Get("action"), frow(b, fdir))
		}
	}

	// a director approves only after another reviewer's sign-off
	if _, b := e.bulkPost(t, "dora", url.Values{"action": {"approve"}, "id": {fdir}}); !strings.Contains(frow(b, fdir), "other than you") {
		t.Fatalf("dora approve unreviewed: %s", frow(b, fdir))
	}

	// a gate failure (no reviewer) is a skip with its reason
	code, b = e.bulkPost(t, "alice", url.Values{"action": {"submit"}, "id": {d2}})
	if code != 200 || !strings.Contains(frow(b, d2), "assign at least one reviewer") || e.statusOf(t, "acme", d2) != "draft" {
		t.Fatalf("gated submit: %d %s", code, frow(b, d2))
	}

	// a pentester's bulk withdraw takes drafts only
	if _, b := e.bulkPost(t, "alice", url.Values{"action": {"withdraw"}, "id": {fdir, d2}, "reason": {"dup"}}); !strings.Contains(summaryOf(b), "1 moved") ||
		e.status(t) != "verification" || e.statusOf(t, "acme", d2) != workflow.Withdrawn {
		t.Fatalf("pentester withdraw: %s %s", e.status(t), summaryOf(b))
	}

	// a repeated id counts once
	if _, b := e.bulkPost(t, "bob", url.Values{"action": {"clear"}, "id": {fdir, fdir, "001"}}); !strings.Contains(summaryOf(b), "1 moved") || !strings.Contains(summaryOf(b), "0 skipped") {
		t.Fatalf("duplicates: %s", summaryOf(b))
	}
}

// Refusals of the whole request, before any row moves.
func TestBulkDenyRequest(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	cases := []struct {
		user string
		form url.Values
		code int
	}{
		// actions off the role's menu
		{"alice", url.Values{"action": {"clear"}, "id": {fdir}}, http.StatusForbidden},
		{"alice", url.Values{"action": {"approve"}, "id": {fdir}}, http.StatusForbidden},
		{"bob", url.Values{"action": {"take_back"}, "id": {fdir}}, http.StatusForbidden},
		{"dora", url.Values{"action": {"clear"}, "id": {fdir}}, http.StatusForbidden},
		// unknown action, no ids, no reason, a reason too long
		{"dora", url.Values{"action": {"bogus"}, "id": {fdir}}, http.StatusUnprocessableEntity},
		{"dora", url.Values{"action": {"approve"}}, http.StatusUnprocessableEntity},
		{"bob", url.Values{"action": {"return"}, "id": {fdir}}, http.StatusUnprocessableEntity},
		{"bob", url.Values{"action": {"return"}, "id": {fdir}, "reason": {strings.Repeat("x", maxBulkReason+1)}}, http.StatusUnprocessableEntity},
	}
	for i, c := range cases {
		if code, _ := e.bulkPost(t, c.user, c.form); code != c.code {
			t.Errorf("case %d: %s %s: code %d, want %d", i, c.user, c.form.Get("action"), code, c.code)
		}
	}
	// too many ids
	many := url.Values{"action": {"approve"}}
	for i := 0; i <= maxBulkIDs; i++ {
		many.Add("id", strconv.Itoa(i+1))
	}
	if code, _ := e.bulkPost(t, "dora", many); code != http.StatusUnprocessableEntity {
		t.Errorf("too many ids: code %d", code)
	}
	if e.status(t) != "verification" {
		t.Fatalf("a refused request moved F-001: %s", e.status(t))
	}
	// an archived engagement refuses the whole run
	if err := e.srv.Store.Archive("acme", wDora); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.bulkPost(t, "dora", url.Values{"action": {"take_back"}, "id": {fdir}}); code != http.StatusForbidden || e.status(t) != "verification" {
		t.Fatalf("archived: code %d status %s", code, e.status(t))
	}
}

// Ids reach only findings the user's teams can see: from the inbox an id of
// another team's engagement is "unknown finding", its title not shown.
func TestBulkOtherTeam(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if err := st.CreateEngagement(store.Engagement{ID: "gamma", Name: "Gamma"}, e.authorOf(wDora)); err != nil {
		t.Fatal(err)
	}
	ref, err := st.CreateFinding("gamma", "Secret title", e.authorOf(wAlice))
	if err != nil {
		t.Fatal(err)
	}
	if st.CanSee(wAlice, "gamma") {
		t.Skip("alice is on gamma's team")
	}
	b := e.do(t, "alice", "POST", "/inbox/bulk", url.Values{"action": {"submit"}, "id": {"gamma/" + ref.Dir, "gamma/001"}}, nil).Body.String()
	if strings.Contains(b, "Secret title") || !strings.Contains(b, "unknown finding") {
		t.Fatalf("other team's finding:\n%s", b)
	}
	if code := e.do(t, "alice", "POST", "/e/gamma/bulk", url.Values{"action": {"submit"}, "id": {ref.Dir}}, hxReq).Code; code == 200 {
		t.Fatal("alice ran a bulk change on another team's engagement")
	}
	if e.statusOf(t, "gamma", ref.Dir) != "draft" {
		t.Fatal("moved")
	}
}

// Sign off on a finding with two reviewers when one signs: the row moved
// (the sign-off is recorded) and still shows Verification.
func TestBulkPartialSignOff(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if err := st.SetReviewers("acme", fdir, []string{"bob", "carol"}, wAlice); err != nil {
		t.Fatal(err)
	}
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	st.Transition("acme", fdir, workflow.Submit, "", wAlice)
	_, b := e.bulkPost(t, "bob", url.Values{"action": {"clear"}, "id": {fdir}})
	if !strings.Contains(summaryOf(b), "1 moved") || !strings.Contains(frow(b, fdir), "status-verification") {
		t.Fatalf("partial sign-off: %s\n%s", summaryOf(b), frow(b, fdir))
	}
}

// A status-filtered list keeps the rows a run moved, in their new status,
// and they stay ticked and counted.
func TestBulkKeepsMovedRows(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.SetReviewers("acme", fdir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	rec := e.do(t, "alice", "POST", "/e/acme/bulk?status=draft", url.Values{"action": {"submit"}, "id": {fdir}}, hxReq)
	b := rec.Body.String()
	if r := frow(b, fdir); !strings.Contains(r, "status-verification") || !strings.Contains(r, "checked") {
		t.Fatalf("moved row left the draft list: %q", r)
	}
	if !strings.Contains(toolbarOf(b), ">1 selected<") {
		t.Fatalf("selection: %s", toolbarOf(b))
	}
	// reloading the list (no run) applies the filter again
	if b := e.do(t, "alice", "GET", "/e/acme?status=draft", nil, hxReq).Body.String(); frow(b, fdir) != "" {
		t.Fatal("filter not applied on reload")
	}
}

// Load more rows carry the pick column like the first page.
func TestBulkLoadMoreRows(t *testing.T) {
	e := setup(t)
	d2 := e.second(t, "alice")
	e.srv.pageSize = 1
	b := e.do(t, "alice", "GET", "/e/acme?offset=1", nil, hxReq).Body.String()
	if r := frow(b, d2); !strings.Contains(r, `<td class="c-pick"><input type="checkbox" name="id" value="`+d2+`"`) || !strings.Contains(r, `data-acts="submit withdraw"`) {
		t.Fatalf("load more row: %q", r)
	}
}

// A reviewer adds reviewers in bulk, but the author is never one (that row
// is skipped) and the bulk form never removes anyone.
func TestBulkAssignOnlyAdds(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	if err := e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	d2 := e.second(t, "carol")
	_, b := e.bulkPost(t, "bob", url.Values{"action": {"reviewers"}, "id": {fdir, d2}, "reviewer": {"carol"}})
	if !strings.Contains(summaryOf(b), "1 moved") || !strings.Contains(frow(b, d2), `class="skip"`) {
		t.Fatalf("assign: %s\n%s", summaryOf(b), frow(b, d2))
	}
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if got := strings.Join(ref.F.Meta.Reviewers, ","); got != "bob,carol" || strings.Join(ref.F.Meta.ClearedBy, ",") != "bob" {
		t.Fatalf("reviewers %q cleared %v", got, ref.F.Meta.ClearedBy)
	}
	// on the finding page a reviewer cannot drop the one who signed off
	if rec := e.do(t, "carol", "POST", fshort+"/reviewers", url.Values{"reviewer": {"carol"}}, nil); rec.Code == http.StatusSeeOther {
		t.Fatal("carol removed bob")
	}
	if ref, _ := e.srv.Store.Finding("acme", fdir); strings.Join(ref.F.Meta.Reviewers, ",") != "bob,carol" {
		t.Fatalf("reviewers %v", ref.F.Meta.Reviewers)
	}
}

// The author's new finding-page powers keep the bar's fixed slots: Take
// back has no button there (bulk only), Mark reported uses its slot.
func TestAuthorBarSlots(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	alice := actionsOf(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if strings.Contains(alice, "take_back") || strings.Contains(alice, "Take back") {
		t.Fatalf("take back on the finding page:\n%s", alice)
	}
}
