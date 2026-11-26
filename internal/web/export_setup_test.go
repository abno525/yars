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
	// the rest is the director's
	if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", form(func(f url.Values) { f.Set("project", "SEC") }), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("director edit %d:\n%s", rec.Code, rec.Body.String())
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
