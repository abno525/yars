package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

var (
	sAnna = config.User{Username: "anna", Role: "director", IsAdmin: true}
	sBen  = config.User{Username: "ben", Role: "director"}
)

// completeAs gives a draft of acme a severity and completes it as u.
func (e *env) completeAs(t *testing.T, dir string, u config.User) {
	t.Helper()
	st := e.srv.Store
	if err := st.UpdateSeverity("acme", dir, "high", "", u); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", dir, workflow.Complete, "", u); err != nil {
		t.Fatal(err)
	}
}

var filterRe = regexp.MustCompile(`id="flt-([a-z-]+)" aria-keyshortcuts="(\d)" href="[^"]*" hx-get="[^"]*" hx-target="#findings" hx-swap="outerHTML" hx-push-url="true">([^<]+)</a>`)

// filtersOf lists the findings list's status filters as "key digit label".
func filtersOf(b string) []string {
	var out []string
	for _, m := range filterRe.FindAllStringSubmatch(between(b, `aria-label="Status"`, "</nav>"), -1) {
		out = append(out, m[1]+" "+m[2]+" "+m[3])
	}
	return out
}

// The simple workflow's findings list filters by its own states: All, Draft,
// Complete, Reported and Withdrawn on keys 1 to 5, with neither verification
// nor signed off.
func TestSimpleStatusFilters(t *testing.T) {
	e := setupSimple(t)
	d2 := e.second(t, "ben")
	e.completeAs(t, d2, sBen)
	b := e.do(t, "anna", "GET", "/e/acme", nil, nil).Body.String()
	want := []string{"all 1 All · 2", "draft 2 Draft · 1", "complete 3 Complete · 1", "reported 4 Reported · 0", "withdrawn 5 Withdrawn · 0"}
	if got := filtersOf(b); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("filters %q, want %q", got, want)
	}
	for _, gone := range []string{"flt-verification", "flt-signed-off", "Verification ·", "Signed off ·"} {
		if strings.Contains(b, gone) {
			t.Errorf("list has %q", gone)
		}
	}
	// a filter lists its findings and is the one marked on
	f := e.do(t, "anna", "GET", "/e/acme?status=complete", nil, nil).Body.String()
	if !strings.Contains(f, `class="on" id="flt-complete"`) || frow(f, d2) == "" || frow(f, fdir) != "" {
		t.Fatalf("complete filter:\n%s", between(f, `id="findings"`, "</table>"))
	}
	// the standard list keeps its seven
	std := setup(t)
	if got := filtersOf(std.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()); len(got) != 7 || got[2] != "verification 3 Verification · 0" || got[3] != "signed-off 4 Signed off · 0" {
		t.Fatalf("standard filters %q", got)
	}
}

// The simple workflow has no reviewers: the findings list has no Reviewers
// column, its header or its cells, and the empty row and Load more span the
// columns left.
func TestSimpleNoReviewersColumn(t *testing.T) {
	e := setupSimple(t)
	e.srv.pageSize = 1
	e.second(t, "ben")
	b := e.do(t, "anna", "GET", "/e/acme", nil, nil).Body.String()
	tbl := between(b, `<table class="table findings"`, "</table>")
	for _, gone := range []string{"col-reviewers", "sort-reviewers", ">Reviewers", `class="revs"`, `class="rvs"`} {
		if strings.Contains(tbl, gone) {
			t.Errorf("findings table has %q:\n%s", gone, tbl)
		}
	}
	// pick, ID, Title, Severity, CVSS, Status, Chat, Author
	if n := strings.Count(between(tbl, "<thead>", "</thead>"), "<th "); n != 8 {
		t.Errorf("%d header cells:\n%s", n, tbl)
	}
	if !strings.Contains(tbl, `<tr class="more" id="findings-more"><td colspan="8">`) {
		t.Errorf("Load more colspan:\n%s", tbl)
	}
	if r := frow(b, fdir); strings.Count(r, "<td") != 8 {
		t.Errorf("row cells: %s", r)
	}
	empty := e.do(t, "anna", "GET", "/e/acme?status=reported", nil, nil).Body.String()
	if !strings.Contains(empty, `<tr class="emptyrow"><td colspan="8">—</td></tr>`) {
		t.Fatalf("empty row:\n%s", between(empty, `<table class="table findings"`, "</table>"))
	}
	// the standard list keeps the column
	std := setup(t)
	sb := std.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(sb, `<th class="col-reviewers">`) || !strings.Contains(frow(sb, fdir), `class="revs"`) {
		t.Fatal("standard list lost its Reviewers column")
	}
	// a retest's list: its Result column, still no Reviewers. Only a complete
	// finding is retested (Q11): here Complete makes it so.
	if err := e.srv.Store.UpdateSeverity("acme", fdir, "high", "", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.Transition("acme", fdir, workflow.Complete, "", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "acme-rt", Name: "ACME retest"}, "acme", []string{fdir}, "", sAnna); err != nil {
		t.Fatal(err)
	}
	rt := between(e.do(t, "anna", "GET", "/e/acme-rt", nil, nil).Body.String(), "<thead>", "</thead>")
	if !strings.Contains(rt, `<th class="col-result">`) || strings.Contains(rt, "col-reviewers") || strings.Count(rt, "<th ") != 9 {
		t.Fatalf("retest header:\n%s", rt)
	}
}

var legendRe = regexp.MustCompile(`<span class="sw seg-([a-z-]+)"></span><span class="lgname">([^<]+)</span><span class="n">(\d+)</span>`)

// legendOf lists a legend's entries as "key label count".
func legendOf(b string) []string {
	var out []string
	for _, m := range legendRe.FindAllStringSubmatch(b, -1) {
		out = append(out, m[1]+" "+m[2]+" "+m[3])
	}
	return out
}

// keysOf lists a bar's legend keys.
func keysOf(v barView) []string {
	var out []string
	for _, s := range v.Legend {
		out = append(out, s.Key)
	}
	return out
}

// The progress bars and their legends follow the simple workflow: draft,
// complete and reported on the findings page, the home table and the
// Overview, never verification or signed off.
func TestSimpleProgressBars(t *testing.T) {
	e := setupSimple(t)
	st := e.srv.Store
	d2 := e.second(t, "ben")
	e.completeAs(t, d2, sBen)
	if err := st.Transition("acme", d2, workflow.Report, "", sBen); err != nil {
		t.Fatal(err)
	}
	e.completeAs(t, e.second(t, "anna"), sAnna)
	gone := []string{"seg-verification", "seg-signed-off", "Verification", "Signed off", "signed off"}

	b := e.do(t, "anna", "GET", "/e/acme", nil, nil).Body.String()
	bars := between(b, `id="engbars"`, "</section>")
	if got := legendOf(between(bars, ">Progress<", ">By severity<")); strings.Join(got, ",") != "draft Draft 1,complete Complete 1,reported Reported 1" {
		t.Fatalf("findings page legend %q:\n%s", got, bars)
	}
	if !strings.Contains(bars, ">1 of 3 reported<") {
		t.Fatalf("findings page count:\n%s", bars)
	}
	for _, g := range gone {
		if strings.Contains(bars, g) {
			t.Errorf("findings page bars have %q", g)
		}
	}

	// the home table counts the reported ones; its row's bars are the same
	home := e.do(t, "anna", "GET", "/", nil, nil).Body.String()
	if r := between(home, `data-eng="acme"`, "</tr>"); !strings.Contains(r, ">1 of 3<") {
		t.Fatalf("home row:\n%s", r)
	}
	rows, err := e.srv.engRows([]store.Engagement{{ID: "acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(rows[0].Bars.Progress); strings.Join(got, ",") != "draft,complete,reported" {
		t.Fatalf("home bar keys %q", got)
	}

	// the Overview: one segment per state with findings, none other
	ov := between(e.do(t, "anna", "GET", "/e/acme/overview", nil, nil).Body.String(), `aria-label="Engagement progress"`, "</section>")
	for _, k := range []string{"draft", "complete", "reported"} {
		if !strings.Contains(ov, `<rect class="seg-`+k+`"`) {
			t.Errorf("Overview has no %s segment:\n%s", k, ov)
		}
	}
	for _, g := range gone {
		if strings.Contains(ov, g) {
			t.Errorf("Overview bars have %q", g)
		}
	}
	sum, err := e.srv.Index.Summary("acme")
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(overviewBars(sum).Progress); strings.Join(got, ",") != "draft,complete,reported" {
		t.Fatalf("Overview bar keys %q", got)
	}
}

var menuLabelRe = regexp.MustCompile(`role="menuitem" data-act="[a-z_]+"[^>]*>([^<]+?) ?(?:<span class="v">|</button>)`)

// rowActs is the data-acts of a findings-list row: the menu entries it can
// take.
func rowActs(t *testing.T, b, dir string) string {
	t.Helper()
	_, rest, ok := strings.Cut(frow(b, dir), `data-acts="`)
	if !ok {
		t.Fatalf("no row %s:\n%s", dir, b)
	}
	acts, _, _ := strings.Cut(rest, `"`)
	return acts
}

// The simple workflow's Set state menu is the same for every account:
// Complete on Shift+A, Reported, Draft and Back to complete (the reverts)
// and Withdrawn, no two alike; no Assign reviewers and no Return. Everyone
// ticks every row, and each row names the entries it can take.
func TestSimpleBulkMenu(t *testing.T) {
	e := setupSimple(t)
	d2 := e.second(t, "ben")
	e.completeAs(t, d2, sBen)
	for _, u := range []string{"anna", "ben"} {
		b := e.do(t, u, "GET", "/e/acme", nil, nil).Body.String()
		bar := toolbarOf(b)
		if got := menuActs(bar); strings.Join(got, " ") != "complete report reopen unreport withdraw" {
			t.Errorf("%s menu %v", u, got)
		}
		for _, want := range []string{
			// no verb: "Complete · complete" said the word twice
			`name="action" value="complete" role="menuitem" data-act="complete" aria-keyshortcuts="Shift&#43;A" disabled>Complete</button>`,
			`name="action" value="report" role="menuitem" data-act="report" aria-keyshortcuts="Shift&#43;P" disabled>Reported <span class="v">· mark reported</span>`,
			`data-bulk-reason="Draft" role="menuitem" data-act="reopen" disabled>Draft <span class="v">· revert</span>`,
			`data-bulk-reason="Back to complete" role="menuitem" data-act="unreport" disabled>Back to complete <span class="v">· revert</span>`,
			`data-bulk-reason="Withdrawn" role="menuitem" data-act="withdraw" disabled>Withdrawn</button>`,
			// Assign reviewers' place is kept, empty, so nothing after it moves
			`<span class="slot w152"></span>`,
			// the reason panel, before an entry names its verb
			`data-bulk-head>Withdraw 0 findings</h2>`, `<button class="btn danger w112" name="action" value="withdraw" data-bulk-go aria-keyshortcuts="Control+Enter">Withdraw</button>`,
		} {
			if !strings.Contains(bar, want) {
				t.Errorf("%s bar lacks %s:\n%s", u, want, bar)
			}
		}
		var labels []string
		for _, m := range menuLabelRe.FindAllStringSubmatch(bar, -1) {
			labels = append(labels, m[1])
		}
		if got := strings.Join(labels, ","); got != "Complete,Reported,Draft,Back to complete,Withdrawn" {
			t.Errorf("%s labels %s", u, got)
		}
		for _, gone := range []string{"Assign reviewers", `value="reviewers"`, `name="reviewer"`, `value="return"`, "Return"} {
			if strings.Contains(bar, gone) {
				t.Errorf("%s bar has %q", u, gone)
			}
		}
		for _, d := range []string{fdir, d2} {
			if !strings.Contains(frow(b, d), `name="id" value="`+d+`"`) {
				t.Errorf("%s cannot tick %s", u, d)
			}
		}
		if a := rowActs(t, b, fdir); a != "complete withdraw" {
			t.Errorf("%s: draft acts %q", u, a)
		}
		if a := rowActs(t, b, d2); a != "report reopen withdraw" {
			t.Errorf("%s: complete acts %q", u, a)
		}
	}
}

// Bulk Complete takes each row through the store as the finding page's
// Complete does (the gate first); Mark reported and the reverts follow, one
// reason for every row.
func TestSimpleBulkComplete(t *testing.T) {
	e := setupSimple(t)
	st := e.srv.Store
	d2 := e.second(t, "anna") // no severity: the gate holds it
	if err := st.UpdateSeverity("acme", fdir, "high", "", sBen); err != nil {
		t.Fatal(err)
	}
	code, b := e.bulkPost(t, "ben", url.Values{"action": {"complete"}, "id": {fdir, d2}})
	if code != 200 || !strings.Contains(summaryOf(b), "1 moved") || !strings.Contains(summaryOf(b), "1 skipped") {
		t.Fatalf("code %d: %s", code, summaryOf(b))
	}
	if r := frow(b, fdir); !strings.Contains(r, "status-complete") || !strings.Contains(r, " checked") || strings.Contains(r, "skip") {
		t.Fatalf("moved row: %s", r)
	}
	if r := frow(b, d2); !strings.Contains(r, `class="skip"`) || !strings.Contains(r, "set a CVSS vector or a severity") {
		t.Fatalf("skipped row: %s", r)
	}
	if e.status(t) != "complete" || e.statusOf(t, "acme", d2) != "draft" || !strings.Contains(e.events(t), "ben:complete") {
		t.Fatalf("after complete: %s %s %q", e.status(t), e.statusOf(t, "acme", d2), e.events(t))
	}
	// the approval is set: an edit keeps it complete
	if err := st.UpdateSection("acme", fdir, "Impact", "More.", "", sAnna); err != nil {
		t.Fatal(err)
	}
	if e.status(t) != "complete" {
		t.Fatalf("after an edit: %s", e.status(t))
	}
	if _, b := e.bulkPost(t, "anna", url.Values{"action": {"report"}, "id": {fdir}}); e.status(t) != "reported" || !strings.Contains(frow(b, fdir), "status-reported") {
		t.Fatalf("after report: %s", e.status(t))
	}
	if code, b := e.bulkPost(t, "anna", url.Values{"action": {"unreport"}, "id": {fdir}}); code != http.StatusUnprocessableEntity || !strings.Contains(b, "give a reason") {
		t.Fatalf("revert without a reason %d: %s", code, b)
	}
	for _, step := range []struct{ act, want string }{{"unreport", "complete"}, {"reopen", "draft"}, {"withdraw", workflow.Withdrawn}} {
		e.bulkPost(t, "anna", url.Values{"action": {step.act}, "id": {fdir}, "reason": {"sent too early"}})
		if got := e.status(t); got != step.want {
			t.Fatalf("after %s: %s", step.act, got)
		}
	}
}

// The bar offers Complete only where the store would take it, as Approve in
// the standard workflow: not on a draft with an open check, nor, with
// Require Check on and a rule on, on one with no finished check run.
func TestSimpleBulkCompleteHidesGated(t *testing.T) {
	e := setupSimple(t)
	st := e.srv.Store
	d2 := e.second(t, "ben")
	e.rules(t, softRule, nil) // a warning on F-001's title
	if err := st.SetRequireCheck(false, "anna"); err != nil {
		t.Fatal(err)
	}
	list := func() string { return e.do(t, "anna", "GET", "/e/acme", nil, nil).Body.String() }
	b := list()
	if a := rowActs(t, b, fdir); a != "withdraw" {
		t.Fatalf("draft with an open warning: %q", a)
	}
	if a := rowActs(t, b, d2); a != "complete withdraw" {
		t.Fatalf("clean draft: %q", a)
	}
	// posted anyway: skipped with the check's message
	if err := st.UpdateSeverity("acme", fdir, "high", "", sAnna); err != nil {
		t.Fatal(err)
	}
	if _, b := e.bulkPost(t, "anna", url.Values{"action": {"complete"}, "id": {fdir}}); !strings.Contains(frow(b, fdir), "say what SQL means (warning)") || e.status(t) != "draft" {
		t.Fatalf("posted complete: %s", frow(b, fdir))
	}
	if err := st.SetRequireCheck(true, "anna"); err != nil {
		t.Fatal(err)
	}
	if a := rowActs(t, list(), d2); a != "withdraw" {
		t.Fatalf("Require Check, no run: %q", a)
	}
	if _, err := st.StartCheck("acme", d2, sAnna); err != nil {
		t.Fatal(err)
	}
	st.WaitChecks()
	if a := rowActs(t, list(), d2); a != "complete withdraw" {
		t.Fatalf("after a clean run: %q", a)
	}
}

// The standard workflow's bulk actions are refused as a whole, with the
// simple wording, and so is assigning reviewers; Restore is no bulk action.
// Nothing changes.
func TestSimpleBulkSubmitRefused(t *testing.T) {
	e := setupSimple(t)
	if err := e.srv.Store.UpdateSeverity("acme", fdir, "high", "", sAnna); err != nil {
		t.Fatal(err)
	}
	refused := func(path string, form url.Values, want string) {
		t.Helper()
		rec := e.do(t, "anna", "POST", path, form, hxReq)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s %s: %d %s", path, form.Get("action"), rec.Code, rec.Body.String())
		}
	}
	for _, a := range []string{"submit", "take_back", "clear", "sign_off", "return", "approve"} {
		refused("/e/acme/bulk", url.Values{"action": {a}, "id": {fdir}, "reason": {"x"}}, "is not part of the simple workflow (draft → complete → reported)")
	}
	refused("/inbox/bulk", url.Values{"action": {"submit"}, "id": {"acme/" + fdir}}, "Submit for verification is not part of the simple workflow")
	refused("/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {fdir}, "reviewer": {"ben"}}, "the simple workflow has no reviewers")
	refused("/e/acme/bulk", url.Values{"action": {"revise"}, "id": {fdir}}, "Restore is not a bulk action")
	if code, b := e.bulkPost(t, "anna", url.Values{"action": {"publish"}, "id": {fdir}}); code != http.StatusUnprocessableEntity || !strings.Contains(b, "unknown bulk action") {
		t.Errorf("unknown action %d: %s", code, b)
	}
	if e.status(t) != "draft" || e.events(t) != "" {
		t.Fatalf("changed: %s %q", e.status(t), e.events(t))
	}
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if len(ref.F.Meta.Reviewers) != 0 {
		t.Fatalf("reviewers %v", ref.F.Meta.Reviewers)
	}
}

// Every account of the simple workflow has the same queues: Notifications,
// Ready to mark reported, Open threads on my findings and New on team
// board, under the one bar (everyone is a director); a thread is the
// author's.
func TestSimpleInboxQueues(t *testing.T) {
	e := setupSimple(t)
	st := e.srv.Store
	if _, err := st.PostChat("acme", fdir, chat.Message{Text: "Is the impact real?"}, sBen); err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{}
	for _, u := range []string{"anna", "ben"} {
		b := e.do(t, u, "GET", "/inbox", nil, nil).Body.String()
		pages[u] = b
		names, _ := queues(b)
		if got := strings.Join(names, ","); got != "Notifications,Ready to mark reported,Open threads on my findings,New on team board" {
			t.Errorf("%s: %s", u, got)
		}
		bar := between(b, `class="fbulk"`, `<section class="q q-`)
		if got := menuActs(bar); strings.Join(got, " ") != "complete report reopen unreport withdraw" {
			t.Errorf("%s inbox menu %v", u, got)
		}
		for _, gone := range []string{"Assign reviewers", `name="reviewer"`, "Return"} {
			if strings.Contains(bar, gone) {
				t.Errorf("%s inbox bar has %q", u, gone)
			}
		}
		if !strings.Contains(queue(b, "report"), "data-pick-all") || strings.Contains(queue(b, "threads"), "c-pick") {
			t.Errorf("%s: picks in the wrong queues", u)
		}
	}
	if q := queue(pages["anna"], "threads"); !strings.Contains(q, "<strong>ben</strong> · Is the impact real?") || !strings.Contains(q, `href="`+fshort+`#chat">Reply</a>`) {
		t.Fatalf("anna's threads:\n%s", q)
	}
	if q := queue(pages["ben"], "threads"); strings.Contains(q, "SQL injection") {
		t.Fatalf("ben sees a thread of a finding he did not write:\n%s", q)
	}
	// the nav badge counts the thread
	if !strings.Contains(pages["anna"], `Inbox <span class="badge">1</span>`) {
		t.Errorf("anna's badge:\n%s", between(pages["anna"], "Inbox", "</a>"))
	}
}

// Ready to mark reported says who completed a finding: "Completed by"
// heads the column and the row reads "ben · completed". Mark reported from
// the inbox's bar moves it in place; reverted, it is back as completed.
func TestSimpleInboxReportRow(t *testing.T) {
	e := setupSimple(t)
	e.completeAs(t, fdir, sBen)
	for _, u := range []string{"anna", "ben"} {
		q := queue(e.do(t, u, "GET", "/inbox", nil, nil).Body.String(), "report")
		for _, want := range []string{`<th class="c-what">Completed by</th>`, "<strong>ben</strong> · completed", `btn primary sm w128" href="` + fshort + `">Mark reported</a>`,
			`name="id" value="acme/` + fdir + `"`, `data-acts="report reopen withdraw"`} {
			if !strings.Contains(q, want) {
				t.Errorf("%s: report queue lacks %s:\n%s", u, want, q)
			}
		}
		if strings.Contains(q, "Approved by") || strings.Contains(q, "approved") {
			t.Errorf("%s: report queue says approved:\n%s", u, q)
		}
	}
	key := "acme/" + fdir
	b := e.do(t, "anna", "POST", "/inbox/bulk", url.Values{"action": {"report"}, "id": {key}}, hxReq).Body.String()
	if q := queue(b, "report"); !strings.Contains(b, `<span class="mv">1 moved</span>`) || !strings.Contains(q, "<strong>anna</strong> · reported") || !strings.Contains(q, ">Open</a>") {
		t.Fatalf("after Mark reported:\n%s", b)
	}
	if e.status(t) != "reported" {
		t.Fatalf("status %s", e.status(t))
	}
	b = e.do(t, "anna", "POST", "/inbox/bulk", url.Values{"action": {"unreport"}, "id": {key}, "reason": {"sent too early"}}, hxReq).Body.String()
	if q := queue(b, "report"); !strings.Contains(q, "<strong>ben</strong> · completed") || !strings.Contains(q, ">Mark reported</a>") {
		t.Fatalf("after the revert:\n%s", q)
	}

	// no complete event (a migration, a seed): the muted dash of an empty
	// value; an approve event is not the simple workflow's
	r := index.Row{EngID: "acme", Dir: fdir, ID: "F-001", Title: "SQL injection", Meta: &finding.Meta{Status: "complete"}}
	simple := workflow.Flow{Simple: true}
	r.Events = []index.Event{{Action: string(workflow.Approve), User: "dora"}}
	if ir := findingRowFor(simple, workflow.InboxReport, sAnna, r, "Acme"); ir.Who != "" || ir.What != "" || ir.Act != "Mark reported" {
		t.Fatalf("without a complete event: %+v", ir)
	}
	r.Events = append(r.Events, index.Event{Action: string(workflow.Complete), User: "ben"})
	if ir := findingRowFor(simple, workflow.InboxReport, sAnna, r, "Acme"); ir.Who != "ben" || ir.What != "completed" {
		t.Fatalf("with the event: %+v", ir)
	}
	// the standard row is the approver's, as before
	if ir := findingRow(workflow.InboxReport, wDora, r, "Acme"); ir.Who != "dora" || ir.What != "approved" {
		t.Fatalf("standard row: %+v", ir)
	}
	if inboxWhoFor(simple, workflow.InboxReport) != "Completed by" || inboxWhoFor(workflow.Flow{}, workflow.InboxReport) != "Approved by" {
		t.Fatal("who heads")
	}
}

// A finding with an open thread is in two lists of its author's inbox: Ready
// to mark reported and Open threads. Marked reported in place and reverted
// with the row still ticked, it comes back to Ready to mark reported, ticked:
// its thread row is not its queue's row, so no row leaves the page.
func TestSimpleInboxRevertWithThread(t *testing.T) {
	e := setupSimple(t)
	e.completeAs(t, fdir, sBen)
	if _, err := e.srv.Store.PostChat("acme", fdir, chat.Message{Text: "Is the impact real?"}, sBen); err != nil {
		t.Fatal(err)
	}
	key := "acme/" + fdir
	ticked := `aria-label="Select acme F-001" checked id="pick-report-acme-F-001"`
	b := e.do(t, "anna", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(queue(b, "report"), `value="`+key+`"`) || !strings.Contains(queue(b, "threads"), "<strong>ben</strong> · Is the impact real?") {
		t.Fatalf("anna's inbox before the run:\n%s", b)
	}
	b = e.do(t, "anna", "POST", "/inbox/bulk", url.Values{"action": {"report"}, "id": {key}}, hxReq).Body.String()
	if q := queue(b, "report"); !strings.Contains(q, "<strong>anna</strong> · reported") || !strings.Contains(q, ticked) {
		t.Fatalf("after Mark reported:\n%s", q)
	}
	b = e.do(t, "anna", "POST", "/inbox/bulk", url.Values{"action": {"unreport"}, "id": {key}, "reason": {"sent too early"}}, hxReq).Body.String()
	if e.status(t) != "complete" {
		t.Fatalf("status %s", e.status(t))
	}
	q := queue(b, "report")
	for _, want := range []string{"<strong>ben</strong> · completed", ">Mark reported</a>", ticked} {
		if !strings.Contains(q, want) {
			t.Errorf("after the revert, the report queue lacks %s:\n%s", want, q)
		}
	}
	if !strings.Contains(b, `<span class="mv">1 moved</span>`) || !strings.Contains(b, `<span class="nsel" data-nsel>1 selected</span>`) {
		t.Errorf("after the revert, the bar:\n%s", between(b, `class="fbulk"`, `<section class="q q-`))
	}
	if !strings.Contains(queue(b, "threads"), "<strong>ben</strong> · Is the impact real?") {
		t.Errorf("after the revert, the thread:\n%s", queue(b, "threads"))
	}
}
