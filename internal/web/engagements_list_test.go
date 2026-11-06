package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/store"
)

// englistRow is the list row of engagement id.
func englistRow(b, id string) string {
	return between(between(b, `class="table englist`, "</table>"), `data-eng="`+id+`"`, "</tr>")
}

// The engagements list: All / Active / Archived with counts, Name with
// client and ID under it, type and state tags, and for directors one fixed
// 112px slot at the row end: Archive or Reopen.
func TestEngagementsListFilterAndArchive(t *testing.T) {
	e := setup(t)
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta", Client: "B Corp", Type: "retest"}, e.authorOf(dora)); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.AddMembers("beta", []string{"alice"}, dora)
	b := e.do(t, "dora", "GET", "/engagements", nil, nil).Body.String()
	for _, want := range []string{`<a class="on" href="/engagements">All · 2</a>`, `<a href="/engagements?show=active">Active · 2</a>`, `<a href="/engagements?show=archived">Archived · 0</a>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("filter lacks %q:\n%s", want, between(b, `aria-label="Show"`, "</nav>"))
		}
	}
	head := between(b, `class="table englist`, "</thead>")
	for _, bad := range []string{">Team<", ">Client<", ">Progress<"} {
		if strings.Contains(head, bad) {
			t.Errorf("list head has %s", bad)
		}
	}
	for _, want := range []string{">Name<", ">Type<", ">State<", ">Dates<", ">Findings<", ">Reported<", `<span class="sr">Actions</span>`} {
		if !strings.Contains(head, want) {
			t.Errorf("list head lacks %s", want)
		}
	}
	r := englistRow(b, "beta")
	for _, want := range []string{`href="/e/beta"`, ">Beta<", "B Corp", `<span class="mono">beta</span>`, `<span class="tag etype-retest">Retest</span>`,
		`<span class="tag eng-active">Active</span>`, `action="/e/beta/archive"`, `class="btn secondary sm w112">Archive<`} {
		if !strings.Contains(r, want) {
			t.Fatalf("beta row lacks %q:\n%s", want, r)
		}
	}
	if r := englistRow(b, "acme"); !strings.Contains(r, `<span class="tag etype-pentest">Pentest</span>`) || !strings.Contains(r, "1 of 1") && !strings.Contains(r, "0 of 1") {
		t.Fatalf("acme row:\n%s", r)
	}
	// a pentester (and an admin who is not a director) keeps the slot, empty
	e.addUser(t, config.User{Username: "ann", Role: "pentester", IsAdmin: true})
	for _, u := range []string{"alice", "ann"} {
		r := englistRow(e.do(t, u, "GET", "/engagements", nil, nil).Body.String(), "acme")
		if strings.Contains(r, "/archive") || !strings.Contains(r, `<span class="slot w112"></span>`) {
			t.Fatalf("%s row:\n%s", u, r)
		}
		if rec := e.do(t, u, "POST", "/e/acme/archive", url.Values{}, nil); rec.Code != http.StatusForbidden || e.srv.Store.Archived("acme") {
			t.Fatalf("archive by %s: %d", u, rec.Code)
		}
	}
	// archive from the list: back to the list with its filter
	rec := e.do(t, "dora", "POST", "/e/acme/archive", url.Values{"show": {"active"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/engagements?show=active" || !e.srv.Store.Archived("acme") {
		t.Fatalf("archive %d %q", rec.Code, rec.Header().Get("Location"))
	}
	b = e.do(t, "dora", "GET", "/engagements?show=archived", nil, nil).Body.String()
	if !strings.Contains(b, `<a class="on" href="/engagements?show=archived">Archived · 1</a>`) || englistRow(b, "beta") != "" {
		t.Fatalf("archived filter:\n%s", b)
	}
	r = englistRow(b, "acme")
	for _, want := range []string{`<tr class="off" data-eng="acme"`, `<span class="tag eng-archived">Archived</span>`, `action="/e/acme/reopen"`, `name="show" value="archived"`, ">Reopen<"} {
		if !strings.Contains(b, want) {
			t.Fatalf("archived row lacks %q:\n%s", want, r)
		}
	}
	// no "date · by" under the tag
	if strings.Contains(r, " · dora") {
		t.Fatalf("archived row shows who archived:\n%s", r)
	}
	if englistRow(e.do(t, "dora", "GET", "/engagements?show=active", nil, nil).Body.String(), "acme") != "" {
		t.Fatal("archived engagement under Active")
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/reopen", url.Values{"show": {"archived"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reopen by pentester %d", rec.Code)
	}
	rec = e.do(t, "dora", "POST", "/e/acme/reopen", url.Values{"show": {"archived"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/engagements?show=archived" || e.srv.Store.Archived("acme") {
		t.Fatalf("reopen %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// from the board (no show field): back to the engagement
	if rec := e.do(t, "dora", "POST", "/e/acme/archive", url.Values{}, nil); rec.Header().Get("Location") != "/e/acme" {
		t.Fatalf("archive from the board goes to %q", rec.Header().Get("Location"))
	}
	if rec := e.do(t, "dora", "POST", "/e/nope/archive", url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown %d", rec.Code)
	}
}

// /engagements/new: Cancel and Create in the title row, one panel, the
// creator always ticked, errors under their field.
func TestNewEngagementPage(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/engagements/new", nil, nil).Body.String()
	head := between(b, `class="titlerow"`, "</div>\n</div>")
	for _, want := range []string{`<a class="btn secondary w128" href="/engagements">Cancel</a>`, `<button class="btn primary w128" form="new-engagement">Create</button>`} {
		if !strings.Contains(head, want) {
			t.Fatalf("title row lacks %q:\n%s", want, head)
		}
	}
	form := between(b, `<form id="new-engagement"`, "</form>")
	for _, want := range []string{`class="panel neweng"`, `name="id"`, `name="name"`, `name="client"`, `name="start"`, `name="end"`, `data-check-all="member"`,
		`<input type="checkbox" checked disabled aria-label="dora">`, `name="member" value="alice"`} {
		if !strings.Contains(form, want) {
			t.Fatalf("form lacks %q:\n%s", want, form)
		}
	}
	if strings.Contains(form, `name="member" value="dora"`) {
		t.Fatal("the creator can be unticked")
	}
	// errors: under the field, the values kept
	rec := e.do(t, "dora", "POST", "/engagements/new", url.Values{"id": {"acme"}, "name": {"Again"}, "member": {"bob"}}, nil)
	b = rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(b, `<span class="ferr" id="id-err">ID already used</span>`) || !strings.Contains(b, `value="Again"`) ||
		!strings.Contains(b, `name="member" value="bob" checked`) || !strings.Contains(b, `name="id" value="acme" aria-invalid="true"`) {
		t.Fatalf("taken id %d:\n%s", rec.Code, b)
	}
	b = e.do(t, "dora", "POST", "/engagements/new", url.Values{"id": {"new-one"}}, nil).Body.String()
	if !strings.Contains(b, `<span class="ferr" id="name-err">Required</span>`) || !strings.Contains(b, `<span class="ferr" id="id-err"></span>`) {
		t.Fatalf("no name:\n%s", b)
	}
	b = e.do(t, "dora", "POST", "/engagements/new", url.Values{"id": {"a b"}, "name": {"X"}}, nil).Body.String()
	if !strings.Contains(b, `<span class="ferr" id="id-err">Letters, digits, dot, dash, underscore</span>`) {
		t.Fatalf("bad id:\n%s", b)
	}
}

func TestDateRange(t *testing.T) {
	for _, c := range []struct{ start, end, want string }{
		{"2026-11-04", "2026-11-07", "04–07 Nov"},
		{"2026-11-28", "2026-12-03", "28 Nov–03 Dec"},
		{"2026-12-28", "2027-01-03", "28 Dec–03 Jan"},
		{"2026-11-04", "", "04 Nov"},
		{"", "", "—"},
		{"soon", "", "soon"},
	} {
		if got := dateRange(c.start, c.end); got != c.want {
			t.Errorf("dateRange(%q, %q) = %q, want %q", c.start, c.end, got, c.want)
		}
	}
}
