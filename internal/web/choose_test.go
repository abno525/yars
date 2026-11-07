package web

import (
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// K10: the engagement picker and the severity selects (CVSS panel, lead
// severity, admin role) do not act when the value changes: moving through
// the options with the keyboard would fire them. They act on an explicit
// choice (a click or Enter, app.js yarsChoose).
func TestSelectsActOnChoiceOnly(t *testing.T) {
	e := setup(t)
	page := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	pick := regexp.MustCompile(`<select name="eng"[^>]*>`).FindString(page)
	if pick == "" || strings.Contains(pick, "onchange") || !strings.Contains(pick, "data-choose") {
		t.Fatalf("engagement picker: %s", pick)
	}
	sev := regexp.MustCompile(`(?s)<form class="sevform"[^>]*>.*?<select name="severity"[^>]*>`).FindString(page)
	if sev == "" || strings.Contains(sev, `hx-trigger="change"`) || !strings.Contains(sev, `hx-trigger="yars:choose"`) || !strings.Contains(sev, "data-choose") {
		t.Fatalf("severity select: %s", sev)
	}
	users := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String()
	if role := regexp.MustCompile(`<select name="role"[^>]*>`).FindString(users); strings.Contains(role, "onchange") || !strings.Contains(role, "data-choose") {
		t.Fatalf("role select: %s", role)
	}
	tb, _ := os.ReadFile("templates/team_board.html")
	if tbsev := regexp.MustCompile(`<form class="tbsev"[^>]*>`).FindString(string(tb)); !strings.Contains(tbsev, `hx-trigger="yars:choose"`) {
		t.Fatalf("lead severity: %s", tbsev)
	}
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, want := range []string{"select[data-choose]", "e.key === 'Enter'", "data-keyed", "yars:choose"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %q", want)
		}
	}
	// the severity form still works when chosen
	if rec := e.do(t, "alice", "POST", fpath+"/severity", url.Values{"severity": {"high"}}, nil); rec.Code != 200 {
		t.Fatalf("severity save %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", "/go?eng=acme", nil, nil); rec.Code != 303 && rec.Code != 302 {
		t.Fatalf("picker target %d", rec.Code)
	}
}
