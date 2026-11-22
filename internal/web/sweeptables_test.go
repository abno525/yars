package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/db"
	"yars/internal/workflow"
)

// cssWidth is the px width a one-line rule of style.css gives (selector as
// written, alone or in the rule's selector list; several such rules may
// share a line).
func cssWidth(t *testing.T, css, selector string) int {
	t.Helper()
	n, ok := cssWidthOK(css, selector)
	if !ok {
		t.Fatalf("style.css has no %s width", selector)
	}
	return n
}

func cssWidthOK(css, selector string) (int, bool) {
	m := regexp.MustCompile(`(?m)(?:^|\} )(?:[^{}\n]*, )?` + regexp.QuoteMeta(selector) + `(?:, [^{}\n]*)? \{ width: (\d+)px; \}`).FindStringSubmatch(css)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return n, true
}

// The inbox's action column holds its longest label: Mark reported is 83px
// of 13px Plex Sans 600 (measured at 1440 x 900), so its sm button (12px
// padding and a 1px border each side) needs 109px; a w104 button let it run
// into the padding to the border. Every row's action has the one width (no
// queue's column differs), and the column is that width plus its 8px and
// 20px padding.
func TestInboxActionFitsMarkReported(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	st := e.srv.Store
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", fdir, workflow.Approve, "", wDora); err != nil {
		t.Fatal(err)
	}
	st.DB().AddNotification(db.Notification{User: "dora", Event: "mentioned", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "bob", Text: "@dora a look?"})
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	acts := regexp.MustCompile(`<td class="c-go"><(?:a|button) class="btn (?:primary|secondary) sm (w\d+)"[^>]*>([^<]+)<`).FindAllStringSubmatch(b, -1)
	labels := map[string]bool{}
	for _, a := range acts {
		labels[a[2]] = true
		if a[1] != acts[0][1] {
			t.Errorf("%s is %s, %s is %s", a[2], a[1], acts[0][2], acts[0][1])
		}
	}
	if !labels["Mark reported"] || !labels["Open"] {
		t.Fatalf("actions %v:\n%s", labels, b)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	w := cssWidth(t, css, "."+acts[0][1])
	if w < 83+2*12+2*1 {
		t.Errorf("Mark reported (83px) in a %dpx sm button", w)
	}
	if col := cssWidth(t, css, ".table.inboxt .c-go"); col != w+8+20 {
		t.Errorf("action column %dpx for a %dpx button", col, w)
	}
}

// A token's Last used is a date and minute, as Activity's Time and
// Sessions' Last seen: 16 characters of 13px Plex Mono (125px), 157px with
// the cell's 16px padding. Its column is as wide as theirs (c-time) on
// Admin › Tokens and in Settings; a date column (128px) cut it to "…".
func TestTokenLastUsedFits(t *testing.T) {
	e := setup(t)
	_, info, err := auth.NewTokens(e.srv.Store.DB()).Create("dora", "dora", db.TokenSpec{Name: "laptop", Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.DB().TokenUsed(info.ID); err != nil {
		t.Fatal(err)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	for _, path := range []string{"/admin/tokens", "/settings"} {
		b := e.do(t, "dora", "GET", path, nil, nil).Body.String()
		if !regexp.MustCompile(`<td class="mono">\d{4}-\d\d-\d\d \d\d:\d\d</td>`).MatchString(b) {
			t.Errorf("%s: no last used time", path)
		}
		m := regexp.MustCompile(`<th class="([a-z0-9-]+)">Last used</th>`).FindStringSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no Last used column", path)
		}
		if w := cssWidth(t, css, ".table th."+m[1]); w < 157 {
			t.Errorf("%s: Last used (157px) in a %dpx column (%s)", path, w, m[1])
		}
	}
}

// auditTable is the Activity table's width at 1440 x 900: the page less its
// stable scrollbar gutter (15px), main's 32px sides and the panel's border.
const auditTable = 1440 - 15 - 2*32 - 2

// Activity's Object and Detail share what the fixed columns leave: Object
// holds an attachment's path ("acme-retest/F-003/session-token.png" and
// longer: 360px is 46 characters of 15px Plex Sans), Detail a prune's
// counts ("audit 0 · check runs 0 · sessions 0 · rule results 1", about as
// long). Object was 200px and cut the path while Detail stood mostly empty.
func TestActivityObjectRoom(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String()
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	head := between(b, `<table class="table stable audittable">`, "</thead>")
	ths := regexp.MustCompile(`<th(?: class="([a-z0-9-]+)")?>([^<]+)</th>`).FindAllStringSubmatch(head, -1)
	if len(ths) != 5 {
		t.Fatalf("columns %v", ths)
	}
	fixed, auto := 0, 0
	widths := map[string]int{}
	for _, th := range ths {
		if th[1] == "" {
			auto++
			continue
		}
		w, ok := cssWidthOK(css, ".table.audittable th."+th[1])
		if !ok {
			w = cssWidth(t, css, ".table th."+th[1])
		}
		widths[th[2]] = w
		fixed += w
	}
	rest := 0
	if auto > 0 {
		rest = (auditTable - fixed) / auto
	}
	for _, col := range []string{"Object", "Detail"} {
		w, ok := widths[col]
		if !ok {
			w = rest
		}
		if w < 360 {
			t.Errorf("%s is %dpx of %dpx (fixed %v)", col, w, auditTable, widths)
		}
	}
}

// An Activity row with no object or no detail (a sign-in has neither)
// shows the muted "—" in each empty cell, as every empty value does.
func TestActivityEmptyCellsDash(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String()
	want := `<td class="mono clip">login</td><td class="clip" title=""><span class="muted">—</span></td><td class="clip" title=""><span class="muted">—</span></td>`
	if !strings.Contains(b, want) {
		t.Fatalf("a sign-in row lacks %s:\n%s", want, between(b, `<tbody>`, `</tbody>`))
	}
}

// Activity's footer holds Previous and Next in their places on every page:
// one that leads nowhere is there, disabled, so the footer is never an
// empty strip (all on one page: both disabled).
func TestActivityPagerFilled(t *testing.T) {
	e := setup(t)
	foot := func(path string) string {
		return between(e.do(t, "dora", "GET", path, nil, nil).Body.String(), `<div class="pfoot flush">`, "</div>")
	}
	prevOff := `<button type="button" class="btn secondary sm w112" disabled>Previous</button>`
	nextOff := `<button type="button" class="btn secondary sm w112" disabled>Next</button>`
	if f := foot("/admin/activity"); !strings.Contains(f, prevOff) || !strings.Contains(f, nextOff) || strings.Contains(f, "slot") {
		t.Errorf("one page:\n%s", f)
	}
	d := e.srv.Store.DB()
	for range auditPage + 10 {
		d.Audit("dora", "user.role", "bob", "reviewer")
	}
	if f := foot("/admin/activity"); !strings.Contains(f, prevOff) || !strings.Contains(f, `<a class="btn secondary sm w112" href="/admin/activity?offset=50">Next</a>`) {
		t.Errorf("first page:\n%s", f)
	}
	if f := foot("/admin/activity?offset=50"); !strings.Contains(f, `<a class="btn secondary sm w112" href="/admin/activity">Previous</a>`) || !strings.Contains(f, nextOff) {
		t.Errorf("last page:\n%s", f)
	}
}

// Activity's details read as the rest of the app's copy: a list of people
// is separated by a comma and a space ("dora, alice, bob", not
// "dora,alice,bob"), and one earlier version is "1 earlier version".
func TestActivityDetailCopy(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "dora", "POST", "/engagements/new", url.Values{"id": {"beta"}, "name": {"Beta"}, "member": {"alice", "bob"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("new engagement %d:\n%s", rec.Code, rec.Body)
	}
	redacted(t, e)
	if rec := e.do(t, "dora", "POST", fpath+"/attachments/shot.png/purge", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("purge %d:\n%s", rec.Code, rec.Body)
	}
	b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String()
	for _, want := range []string{
		`<td class="mono clip">eng.create</td><td class="clip" title="beta">beta</td><td class="clip" title="dora, alice, bob">dora, alice, bob</td>`,
		`<td class="mono clip">eng.member.add</td><td class="clip" title="beta">beta</td><td class="clip" title="dora, alice, bob">dora, alice, bob</td>`,
		`<td class="mono clip">attachment.purge</td><td class="clip" title="acme/F-001/shot.png">acme/F-001/shot.png</td><td class="clip" title="1 earlier version">1 earlier version</td>`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("Activity lacks %s:\n%s", want, between(b, `<tbody>`, `</tbody>`))
		}
	}
}

// An inbox row's who · what has its dot only between the two: a notice
// without text (Approved) shows who did it, not "dora · ".
func TestInboxWhoWithoutWhat(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	d.AddNotification(db.Notification{User: "alice", Event: "approved", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "dora"})
	d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "bob", Text: "a look?"})
	sec := notesSection(t, e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String())
	for _, want := range []string{`<td class="c-what" title="dora"><strong>dora</strong></td>`,
		`<td class="c-what" title="bob · a look?"><strong>bob</strong> · a look?</td>`} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %s:\n%s", want, sec)
		}
	}
}
