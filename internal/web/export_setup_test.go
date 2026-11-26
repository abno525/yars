package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/export"
)

// A destination whose pandoc format is not one of the editor's (written by
// hand, such as docx+styles) opens with that format selected, so a save
// keeps it.
func TestDestKeepsUnlistedFormat(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	os.WriteFile(filepath.Join(e.srv.Export.Dir, "styled.yaml"), []byte("name: Styled\ntype: pandoc\nformat: docx+styles\n"), 0o644)
	b := e.do(t, "dora", "GET", "/e/acme/export/setup?edit=styled", nil, nil).Body.String()
	if !strings.Contains(b, "<option selected>docx&#43;styles</option>") {
		_, sel, _ := strings.Cut(b, `name="format"`)
		sel, _, _ = strings.Cut(sel, "</select>")
		t.Fatalf("styled listed %v, format select: %s", strings.Contains(b, "styled.yaml"), sel)
	}
	if strings.Contains(e.do(t, "dora", "GET", "/e/acme/export/setup?edit=docx", nil, nil).Body.String(), "<option>docx&#43;styles") {
		t.Fatal("another destination offers docx+styles")
	}
}

// Only an admin sets where a service destination sends its keys: a
// director who is not an admin can't change its address or key variables
// or create one, but can edit the rest.
func TestDestAddressAdminOnly(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	e.addUser(t, config.User{Username: "dir2", Role: "director"})
	base := "http://" + j.host()
	form := func(mod func(url.Values)) url.Values {
		f := url.Values{"id": {"jira"}, "name": {"Jira PEN"}, "type": {"jira"}, "base_url": {base}, "project": {"PEN"},
			"user_env": {"JIRA_USER"}, "token_env": {"JIRA_TOKEN"}, "status": {"complete"}, "mark_reported": {"1"}}
		if mod != nil {
			mod(f)
		}
		return f
	}
	hostNow := func() string {
		es, _ := export.Load(e.srv.Export.Dir)
		ex, _ := findExporter(es, "jira")
		return ex.Host() + " " + ex.Jira.TokenEnv
	}
	b := e.do(t, "dir2", "GET", "/e/acme/export/setup?edit=jira", nil, nil).Body.String()
	if !strings.Contains(b, `name="base_url" value="`+base+`" readonly`) || !strings.Contains(b, `name="token_env" value="JIRA_TOKEN" readonly`) {
		t.Fatalf("editor:\n%s", b)
	}
	for name, f := range map[string]url.Values{
		"address":   form(func(f url.Values) { f.Set("base_url", "https://attacker.example") }),
		"token env": form(func(f url.Values) { f.Set("token_env", "JIRA_OTHER") }),
		"new":       form(func(f url.Values) { f.Set("new", "1"); f.Set("id", "jira2") }),
	} {
		if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", f, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, rec.Code)
		}
	}
	if h := hostNow(); h != j.host()+" JIRA_TOKEN" {
		t.Fatalf("changed to %s", h)
	}
	if _, err := os.Stat(filepath.Join(e.srv.Export.Dir, "jira2.yaml")); err == nil {
		t.Fatal("new service destination saved")
	}
	// the rest is the director's: the name, the statuses, mark_reported
	if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", form(func(f url.Values) {
		f.Set("name", "Jira PEN 2")
		f["status"] = []string{"complete", "reported"}
		f.Del("mark_reported")
	}), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("director edit %d:\n%s", rec.Code, between(rec.Body.String(), `class="pstate error"`, "</span>"))
	}
	es, _ := export.Load(e.srv.Export.Dir)
	if ex, _ := findExporter(es, "jira"); ex.Name != "Jira PEN 2" || ex.Marks() || len(ex.Statuses) != 2 || ex.Jira.Project != "PEN" {
		t.Fatalf("director's edit saved as %+v %+v", ex, ex.Jira)
	}
	// an admin may move it
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", form(func(f url.Values) { f.Set("base_url", "https://jira.acme.com") }), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("admin edit %d:\n%s", rec.Code, rec.Body.String())
	}
	if h := hostNow(); h != "jira.acme.com JIRA_TOKEN" {
		t.Fatalf("admin change: %s", h)
	}
	if b := e.do(t, "dora", "GET", "/e/acme/export/setup?edit=jira", nil, nil).Body.String(); !strings.Contains(b, `name="base_url" value="https://jira.acme.com">`) {
		t.Fatal("admin editor read only")
	}
}

// A director without the admin flag does not retarget a service destination:
// where it publishes (project, issue type, space, parent page) is an admin's
// to set, as the address is. The director still edits the name and
// mark_reported of each, and all of a script or pandoc destination: its
// script, its template and its arguments. An admin changes all of it.
func TestDestTargetAdminOnly(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	e.jira(t, true)
	e.addUser(t, config.User{Username: "dir2", Role: "director"})
	dir := e.srv.Export.Dir
	files := map[string]string{
		"jira.yaml":   "name: Jira\ntype: jira\njira: {base_url: https://jira.firm.example, project: PEN, issue_type: Bug, user_env: JIRA_USER, token_env: JIRA_TOKEN}\n",
		"wiki.yaml":   "name: Wiki\ntype: confluence\nconfluence: {base_url: https://wiki.firm.example, space: PEN, parent_id: \"100\", user_env: CONFLUENCE_USER, token_env: CONFLUENCE_TOKEN}\n",
		"csv.yaml":    "name: CSV\ntype: script\nscript: csv.sh\nextension: csv\n",
		"styled.yaml": "name: Styled\ntype: pandoc\nformat: docx\ntemplate: firm.docx\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	forms := map[string]url.Values{
		"jira": {"id": {"jira"}, "name": {"Jira"}, "type": {"jira"}, "base_url": {"https://jira.firm.example"}, "project": {"PEN"}, "issue_type": {"Bug"},
			"user_env": {"JIRA_USER"}, "token_env": {"JIRA_TOKEN"}, "status": {"complete"}, "mark_reported": {"1"}},
		"wiki": {"id": {"wiki"}, "name": {"Wiki"}, "type": {"confluence"}, "base_url": {"https://wiki.firm.example"}, "space": {"PEN"}, "parent_id": {"100"},
			"user_env": {"CONFLUENCE_USER"}, "token_env": {"CONFLUENCE_TOKEN"}, "status": {"complete"}, "mark_reported": {"1"}},
		"csv":    {"id": {"csv"}, "name": {"CSV"}, "type": {"script"}, "script": {"csv.sh"}, "extension": {"csv"}, "status": {"complete"}, "mark_reported": {"1"}},
		"styled": {"id": {"styled"}, "name": {"Styled"}, "type": {"pandoc"}, "format": {"docx"}, "template": {"firm.docx"}, "status": {"complete"}, "mark_reported": {"1"}},
		"docx":   {"id": {"docx"}, "name": {"Client report (DOCX)"}, "type": {"pandoc"}, "format": {"docx"}, "status": {"complete"}, "mark_reported": {"1"}},
	}
	with := func(id string, kv ...string) url.Values {
		f := url.Values{}
		for k, v := range forms[id] {
			f[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			f.Set(kv[i], kv[i+1])
		}
		return f
	}
	file := func(id string) string {
		b, err := os.ReadFile(filepath.Join(dir, id+".yaml"))
		if err != nil {
			return ""
		}
		return string(b)
	}
	// the editor shows a director what is an admin's read-only; the script
	// and the template are the director's to write
	b := e.do(t, "dir2", "GET", "/e/acme/export/setup?edit=jira", nil, nil).Body.String()
	for _, want := range []string{`name="project" value="PEN" readonly`, `name="issue_type" value="Bug" readonly`, `name="space" value="" readonly`,
		`name="parent_id" value="" readonly`, `name="script" value="">`, `name="template" value="">`} {
		if !strings.Contains(b, want) {
			t.Errorf("a director's editor lacks %s", want)
		}
	}
	if b := e.do(t, "dora", "GET", "/e/acme/export/setup?edit=jira", nil, nil).Body.String(); !strings.Contains(b, `name="project" value="PEN">`) || !strings.Contains(b, `name="script" value="">`) || !strings.Contains(b, `name="template" value="">`) {
		t.Error("an admin's editor has read-only fields")
	}
	type edit struct {
		name, id string
		form     url.Values
	}
	refused := []edit{
		{"jira project", "jira", with("jira", "project", "PUBLIC")},
		{"jira issue type", "jira", with("jira", "issue_type", "Epic")},
		{"confluence space", "wiki", with("wiki", "space", "PUBLIC")},
		{"confluence parent page", "wiki", with("wiki", "parent_id", "1")},
	}
	for _, c := range refused {
		before := file(c.id)
		rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", c.form, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), export.AdminOnly) {
			t.Errorf("%s by a director without the admin flag: %d", c.name, rec.Code)
		}
		if file(c.id) != before {
			t.Errorf("%s: the file changed:\n%s", c.name, file(c.id))
		}
	}
	// a director's own: name and mark_reported of each, a new pandoc one
	for _, id := range []string{"jira", "wiki", "csv", "styled", "docx"} {
		f := with(id, "name", "Renamed "+id)
		f.Del("mark_reported")
		if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", f, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("a director's edit of %s: %d\n%s", id, rec.Code, between(rec.Body.String(), `class="pstate error"`, "</span>"))
		}
		es, _ := export.Load(dir)
		if ex, ok := findExporter(es, id); !ok || ex.Name != "Renamed "+id || ex.Marks() {
			t.Errorf("a director's edit of %s saved as %+v", id, ex)
		}
	}
	if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", with("docx", "new", "1", "id", "odt", "format", "odt"), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("a director's new pandoc destination: %d", rec.Code)
	}
	// a director's too: scripts, templates and pandoc arguments
	for _, c := range []edit{
		{"another script", "csv", with("csv", "script", "other.sh")},
		{"a new script destination", "run", with("csv", "new", "1", "id", "run")},
		{"pandoc turned into a script", "odt", with("docx", "id", "odt", "type", "script", "script", "csv.sh", "extension", "odt")},
		{"a template", "docx", with("docx", "template", "firm.docx")},
		{"another template", "styled", with("styled", "template", "other.docx")},
		{"a new pandoc destination with a template", "tpl", with("styled", "new", "1", "id", "tpl")},
	} {
		if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", c.form, nil); rec.Code != http.StatusSeeOther {
			t.Errorf("%s by a director without the admin flag: %d\n%s", c.name, rec.Code, between(rec.Body.String(), `class="pstate error"`, "</span>"))
		}
	}
	es, _ := export.Load(dir)
	if ex, _ := findExporter(es, "csv"); ex.Script != "other.sh" {
		t.Errorf("the director's script: %+v", ex)
	}
	if ex, _ := findExporter(es, "run"); ex.Type != "script" || ex.Script != "csv.sh" {
		t.Errorf("the director's script destination: %+v", ex)
	}
	if ex, _ := findExporter(es, "odt"); ex.Type != "script" || ex.Script != "csv.sh" {
		t.Errorf("the director's pandoc turned into a script: %+v", ex)
	}
	if ex, _ := findExporter(es, "styled"); ex.Template != "other.docx" {
		t.Errorf("the director's template: %+v", ex)
	}
	if ex, _ := findExporter(es, "tpl"); ex.Type != "pandoc" || ex.Template != "firm.docx" {
		t.Errorf("the director's pandoc destination with a template: %+v", ex)
	}
	// an admin sets all of it
	for _, c := range refused {
		if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", c.form, nil); rec.Code != http.StatusSeeOther {
			t.Errorf("%s by an admin: %d\n%s", c.name, rec.Code, between(rec.Body.String(), `class="pstate error"`, "</span>"))
		}
	}
	es, _ = export.Load(dir)
	if ex, _ := findExporter(es, "jira"); ex.Jira == nil || ex.Jira.IssueType != "Epic" {
		t.Fatalf("the admin's jira: %+v", ex.Jira)
	}
}
