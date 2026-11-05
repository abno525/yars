package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/store"
)

// tabsOf is the engagement tab bar.
func tabsOf(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `class="etabs"`)
	if i < 0 {
		t.Fatalf("no tabs:\n%s", b)
	}
	j := strings.Index(b[i:], "</nav>")
	return b[i : i+j]
}

func TestEngagementTabs(t *testing.T) {
	e := setup(t)
	for path, on := range map[string]string{"/e/acme": "Findings · 1", "/e/acme/overview": "Overview", "/e/acme/report": "Report", "/e/acme/settings": "Settings"} {
		rec := e.do(t, "alice", "GET", path, nil, nil)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		b := rec.Body.String()
		tabs := tabsOf(t, b)
		if strings.Count(tabs, `class="etab on"`) != 1 || !strings.Contains(tabs, `class="etab on" href="`+path+`" aria-current="page">`+on) {
			t.Fatalf("%s tabs:\n%s", path, tabs)
		}
		// one active top-nav item: Findings
		nav := b[strings.Index(b, `<nav class="nav">`):]
		nav = nav[:strings.Index(nav, "</nav>")]
		if strings.Count(nav, `class="on"`) != 1 || !strings.Contains(nav, `<a class="on" href="/e/acme">Findings`) {
			t.Fatalf("%s: top nav:\n%s", path, nav)
		}
		noInline(t, path, b)
	}
}

func TestOverviewTab(t *testing.T) {
	e := setup(t)
	e.toVerification(t) // F-001 high, in verification
	b := e.do(t, "alice", "GET", "/e/acme/overview", nil, nil).Body.String()
	for _, want := range []string{`class="tiles"`, `class="tag sev-high"`, `class="sevchart`, "<th", `class="bar"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q:\n%s", want, b)
		}
	}
}

func TestReportTab(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/report", nil, nil).Body.String()
	for _, n := range []string{"Executive summary", "Scope", "Methodology"} {
		if !strings.Contains(b, "<h2>"+n+"</h2>") {
			t.Fatalf("no %s panel:\n%s", n, b)
		}
	}
	if !strings.Contains(b, `hx-get="/e/acme/report/s/Scope/edit"`) || !strings.Contains(b, "Severity") {
		t.Fatalf("report page:\n%s", b)
	}
	ed := e.do(t, "alice", "GET", "/e/acme/report/s/Scope/edit", nil, nil).Body.String()
	if !strings.Contains(ed, `hx-post="/e/acme/report/s/Scope"`) || !strings.Contains(ed, `<textarea name="body"`) {
		t.Fatalf("editor:\n%s", ed)
	}
	rec := e.do(t, "alice", "POST", "/e/acme/report/s/Scope", url.Values{"body": {"Only **app.acme**."}, "base": {store.BodyHash("")}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<strong>app.acme</strong>") {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if got := e.lastCommit(t); got != "alice|report: edit Scope" {
		t.Fatalf("commit %q", got)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/report/s/Scope", url.Values{"body": {"x"}, "base": {store.BodyHash("")}}, nil); rec.Code != http.StatusConflict {
		t.Fatalf("stale %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/report/s/Nope/edit", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown section %d", rec.Code)
	}
	// archived: no Edit, saves refused
	e.srv.Store.Archive("acme", wDora)
	if b := e.do(t, "alice", "GET", "/e/acme/report", nil, nil).Body.String(); strings.Contains(b, "/report/s/Scope/edit") {
		t.Fatal("archived report editable")
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/report/s/Scope", url.Values{"body": {"y"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("archived save %d", rec.Code)
	}
}

func TestSettingsTab(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/settings", nil, nil).Body.String()
	// others see the values, not the form's Save or the team controls
	if strings.Contains(b, `action="/e/acme/settings"`) || !strings.Contains(b, "ACME Web") || strings.Contains(b, "/settings/team") {
		t.Fatalf("pentester settings:\n%s", b)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/settings", url.Values{"name": {"X"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester save %d", rec.Code)
	}
	b = e.do(t, "dora", "GET", "/e/acme/settings", nil, nil).Body.String()
	if !strings.Contains(b, `action="/e/acme/settings"`) || !strings.Contains(b, `action="/e/acme/settings/team"`) || !strings.Contains(b, "<th") {
		t.Fatalf("director settings:\n%s", b)
	}
	rec := e.do(t, "dora", "POST", "/e/acme/settings", url.Values{"name": {"ACME portal"}, "client": {"ACME Ltd"}, "start": {"2026-11-04"}, "end": {"2026-11-07"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d %s", rec.Code, rec.Body.String())
	}
	if got, _ := e.srv.Store.Engagement("acme"); got.Name != "ACME portal" || got.Client != "ACME Ltd" || got.End != "2026-11-07" {
		t.Fatalf("saved %+v", got)
	}
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, "ACME portal") {
		t.Fatal("board shows the old name")
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/settings", url.Values{"name": {""}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name %d", rec.Code)
	}
	// team
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/team/remove", url.Values{"user": {"carol"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove %d", rec.Code)
	}
	if m, _ := e.srv.Store.Members("acme"); strings.Contains(strings.Join(m, ","), "carol") {
		t.Fatalf("carol still on the team: %v", m)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/team", url.Values{"user": {"carol"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("add %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/settings/team", url.Values{"user": {"carol"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester team %d", rec.Code)
	}
}
