package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
)

// The editor's values can be run before they are saved: Try unsaved posts
// the editor's own fields and answers the bench's output for the chosen
// finding. Nothing is written: no rule file, no commit, no check run.
func TestRuleTryRunsUnsavedValues(t *testing.T) {
	e := setupSerial(t)
	ran := filepath.Join(t.TempDir(), "ran")
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo run >> " + ran + "; echo '[]'\n"})
	runs := func() int {
		b, _ := os.ReadFile(ran)
		return strings.Count(string(b), "run")
	}
	head := func() string {
		out, err := exec.Command("git", "-C", e.dir, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	at, style := head(), e.ruleFile(t, "style.yaml")
	hx := map[string]string{"HX-Request": "true"}

	// a new rule, typed and never saved, without an ID yet
	form := url.Values{"id": {""}, "kind": {"pattern"}, "level": {"warning"}, "target": {"title"}, "mode": {"forbid"},
		"pattern": {"sql"}, "icase": {"1"}, "message": {"No SQL in a title"}, "eng": {"acme"}, "fid": {fdir}}
	rec := e.do(t, "dora", "POST", "/admin/rules/try", form, hx)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `id="bench-out"`) || !strings.Contains(b, "No SQL in a title") || !strings.Contains(b, "<code>SQL</code>") || !strings.Contains(b, `<span class="badge">1</span>`) {
		t.Fatalf("a new rule: %d\n%s", rec.Code, b)
	}
	// a saved rule runs with the form's pattern, not the saved one
	form = url.Values{"old": {"title-word"}, "id": {"title-word"}, "kind": {"pattern"}, "level": {"error"}, "target": {"title"}, "mode": {"forbid"},
		"pattern": {"SQL"}, "message": {"edited"}, "eng": {"acme"}, "fid": {fdir}}
	rec = e.do(t, "dora", "POST", "/admin/rules/try", form, hx)
	b = rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, "<code>SQL</code>") || strings.Contains(b, "<code>injection</code>") || !strings.Contains(b, "edited") {
		t.Fatalf("an edited rule: %d\n%s", rec.Code, b)
	}
	// an ID another rule has is no error for a Try
	form.Set("id", "scripted")
	if rec := e.do(t, "dora", "POST", "/admin/rules/try", form, hx); rec.Code != 200 {
		t.Fatalf("a taken ID: %d\n%s", rec.Code, rec.Body.String())
	}
	// nothing was written
	if head() != at || e.ruleFile(t, "style.yaml") != style {
		t.Fatal("a Try changed the rules")
	}
	if _, err := os.Stat(filepath.Join(e.dir, ".yars", "rules", "try.yaml")); err == nil {
		t.Fatal("a Try wrote a rule file")
	}
	if r, _ := e.srv.Rules.Rule("title-word"); r.RegexForbid != "injection" {
		t.Fatalf("the saved rule changed: %+v", r)
	}
	if st, err := e.srv.Store.CheckStatus("acme", fdir); err != nil || st.HasRun {
		t.Fatalf("stored a run: %+v %v", st, err)
	}

	// a bad pattern: words, not a page, for htmx as 422
	form = url.Values{"id": {"x"}, "kind": {"pattern"}, "level": {"error"}, "target": {"title"}, "mode": {"forbid"}, "pattern": {"(["}, "eng": {"acme"}, "fid": {fdir}}
	rec = e.do(t, "dora", "POST", "/admin/rules/try", form, hx)
	if b := rec.Body.String(); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(b, "missing closing ]") || strings.Contains(b, "<") {
		t.Fatalf("a bad pattern: %d\n%s", rec.Code, b)
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/try", form, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("a bad pattern without htmx: %d", rec.Code)
	}

	// the page: the button beside Save, in the editor of a rule and of a new one
	for _, p := range []string{"/admin/rules", "/admin/rules?edit=scripted", "/admin/rules?edit=title-word"} {
		page := e.do(t, "dora", "GET", p, nil, nil).Body.String()
		foot := between(page, `<form class="panel compact ruleform"`, `</form>`)
		btn := between(foot, `<button class="btn secondary sm w128" type="button"`, `</button>`)
		for _, want := range []string{` hx-post="/admin/rules/try"`, ` hx-encoding="multipart/form-data"`, ` hx-target="#bench-out"`, ` hx-swap="outerHTML"`, ` hx-include="`, `>Try unsaved`} {
			if !strings.Contains(btn, want) {
				t.Errorf("%s: the button lacks %s: %s", p, want, btn)
			}
		}
		if !strings.Contains(foot, `Try unsaved</button>`+"\n    "+`<button class="btn primary sm w128">Save</button>`) {
			t.Errorf("%s: Try unsaved is not right before Save", p)
		}
	}
	if n := runs(); n != 0 {
		t.Fatalf("the script ran %d times", n)
	}
}

// A Try runs scripts and AI rules, so it is guarded as the bench: a link, a
// form on another site, values in the address and an account that is no
// admin run nothing. A fresh upload cannot be tried (the runner runs the
// saved file); a saved script rule runs its saved script, with the write
// deadline of a lint run.
func TestRuleTryScriptsAndGuards(t *testing.T) {
	e := setupSerial(t)
	ran := filepath.Join(t.TempDir(), "ran")
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo run >> " + ran + "; echo '[]'\n"})
	runs := func() int {
		b, _ := os.ReadFile(ran)
		return strings.Count(string(b), "run")
	}
	form := url.Values{"old": {"scripted"}, "id": {"scripted"}, "kind": {"script"}, "level": {"warning"}, "target": {""}, "eng": {"acme"}, "fid": {fdir}}
	query := "?" + form.Encode()
	if rec := e.do(t, "dora", "GET", "/admin/rules/try"+query, nil, nil); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("GET: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/try", form, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/try"+query, url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("a POST with its values in the address: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/admin/rules/try", form, nil); rec.Code != http.StatusForbidden {
		t.Errorf("alice: %d", rec.Code)
	}
	// an upload is refused with words, and the saved script does not run in
	// its place
	fields := map[string]string{"old": "scripted", "id": "scripted", "kind": "script", "level": "warning", "eng": "acme", "fid": fdir}
	rec := e.upload(t, "dora", "/admin/rules/try", fields, "check.sh", "cat >/dev/null; echo '[{\"message\":\"new\"}]'\n")
	if b := rec.Body.String(); rec.Code != http.StatusBadRequest || !strings.Contains(b, "save the rule to try an uploaded script") {
		t.Fatalf("an upload: %d\n%s", rec.Code, b)
	}
	// a script rule that has no saved script
	rec = e.upload(t, "dora", "/admin/rules/try", map[string]string{"id": "fresh", "kind": "script", "level": "warning", "eng": "acme", "fid": fdir}, "", "")
	if b := rec.Body.String(); rec.Code != http.StatusBadRequest || !strings.Contains(b, "upload a script") {
		t.Fatalf("no script: %d\n%s", rec.Code, b)
	}
	if n := runs(); n != 0 {
		t.Fatalf("the script ran %d times for requests that run nothing", n)
	}
	if b, err := os.ReadFile(filepath.Join(e.dir, ".yars", "rules", "check.sh")); err != nil || strings.Contains(string(b), "new") {
		t.Fatalf("the saved script changed: %s %v", b, err)
	}

	// the saved script runs, with the long write deadline; and as multipart,
	// which is what the editor sends
	req := httptest.NewRequest("POST", "/admin/rules/try", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["dora"]})
	drec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.h.ServeHTTP(drec, req)
	if drec.Code != 200 || !strings.Contains(drec.Body.String(), `<span class="badge0">0</span>`) || runs() != 1 {
		t.Fatalf("a saved script: %d, %d runs\n%s", drec.Code, runs(), drec.Body.String())
	}
	if len(drec.deadlines) != 1 || time.Until(drec.deadlines[0]) < 100*time.Second {
		t.Errorf("write deadlines %v", drec.deadlines)
	}
	if rec := e.upload(t, "dora", "/admin/rules/try", fields, "", ""); rec.Code != 200 {
		t.Fatalf("multipart without a file: %d\n%s", rec.Code, rec.Body.String())
	}
}
