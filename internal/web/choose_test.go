package web

import (
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// R2: the retest result radios save on a click, Space or Enter only, not
// when the arrow keys move the selection (as K10's selects).
func TestRetestRadiosActOnChoiceOnly(t *testing.T) {
	b, _ := os.ReadFile("templates/retest.html")
	form := regexp.MustCompile(`<form class="seg result-seg"[^>]*>`).FindString(string(b))
	if form == "" || strings.Contains(form, `hx-trigger="change"`) || !strings.Contains(form, `hx-trigger="yars:choose"`) {
		t.Fatalf("result form: %s", form)
	}
	if !strings.Contains(string(b), `<input type="radio" data-choose name="result" value="{{.Code}}"`) {
		t.Fatal("result radios not marked data-choose")
	}
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	// P5: a keyboard save puts the focus back on the saved radio on the
	// page the save reloads (HX-Refresh)
	for _, want := range []string{"input[type=radio][data-choose]", "e.key === ' '", "defaultChecked", "ArrowDown", "yarsRadioFocus", "sessionStorage.setItem(yarsRadioFocus", "DOMContentLoaded"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %q", want)
		}
	}
	// the CVSS calculator buttons keep acting at once
	cv, _ := os.ReadFile("templates/cvss.html")
	if strings.Contains(string(cv), `type="radio" data-choose`) {
		t.Fatal("CVSS calculator radios changed")
	}
}

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
	// no select anywhere acts on change by itself (the rules bench's
	// engagement select only loads its finding list)
	ents, _ := os.ReadDir("templates")
	for _, en := range ents {
		b, _ := os.ReadFile("templates/" + en.Name())
		for _, sel := range regexp.MustCompile(`<select[^>]*>`).FindAllString(string(b), -1) {
			if strings.Contains(sel, "onchange") || (strings.Contains(sel, `hx-trigger="change"`) && !strings.Contains(sel, "/admin/rules/bench/findings")) {
				t.Errorf("%s: %s", en.Name(), sel)
			}
		}
	}
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, want := range []string{"select[data-choose]", "e.key === 'Enter'", "data-keyed", "yars:choose", "e.altKey", "defaultSelected"} {
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
