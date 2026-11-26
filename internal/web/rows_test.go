package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// formOf reads the named fields and values of a form fragment (inputs and
// textareas), as a browser would post them.
func formOf(b string) url.Values {
	out := url.Values{}
	for _, m := range regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`).FindAllStringSubmatch(b, -1) {
		out.Add(m[1], m[2])
	}
	for _, m := range regexp.MustCompile(`(?s)<textarea name="([^"]+)"[^>]*>(.*?)</textarea>`).FindAllStringSubmatch(b, -1) {
		out.Add(m[1], strings.TrimPrefix(m[2], "\n"))
	}
	return out
}

// D14 on the web: the Details editor writes only the rows the user
// changed, each checked on its own; a row changed meanwhile (MCP) keeps
// its new value; the same row changed is a conflict that blames nobody.
func TestDetailsEditorPerRow(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	editor := e.do(t, "alice", "GET", fpath+"/details/edit", nil, nil).Body.String()
	form := formOf(editor)
	if form.Get("base:Location") == "" || !form.Has("row:Cause") {
		t.Fatalf("editor form %v", form)
	}
	// MCP sets Cause meanwhile
	if err := st.UpdateDetails("acme", fdir, map[string]string{"Cause": "by MCP"}, "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	form.Set("row:Location", "POST /login")
	if rec := e.do(t, "alice", "POST", fpath+"/details", form, nil); rec.Code != http.StatusOK {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	ref, _ := st.Finding("acme", fdir)
	if d := ref.F.Meta.Details; d["Location"] != "POST /login" || d["Cause"] != "by MCP" {
		t.Fatalf("details %v", d)
	}
	// the same row, stale: conflict, the typed value kept, the other rows
	// as they are now
	form.Set("row:Location", "GET /")
	rec := e.do(t, "alice", "POST", fpath+"/details", form, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "The finding changed since you read it") {
		t.Fatalf("stale row %d:\n%s", rec.Code, rec.Body.String())
	}
	again := formOf(rec.Body.String())
	if again.Get("row:Location") != "GET /" || again.Get("row:Cause") != "by MCP" || again.Get("base:Location") != store.RowHash("POST /login") {
		t.Fatalf("conflict editor %v", again)
	}
	// saving the conflict editor goes through (Keep mine)
	if rec := e.do(t, "alice", "POST", fpath+"/details", again, nil); rec.Code != http.StatusOK {
		t.Fatalf("keep mine %d", rec.Code)
	}
}

// D14: the CVSS editor writes the vector only if the user changed it, and
// reasons one by one: a reason set meanwhile stays.
func TestCVSSEditorPerRow(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	vec := "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
	if err := st.UpdateCVSS("acme", fdir, vec, nil, "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	editor := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()
	form := formOf(editor)
	if form.Get("base:cvss") == "" || form.Get("base:AC") == "" {
		t.Fatalf("editor bases %v", form)
	}
	// MCP changes the vector meanwhile
	vec2 := "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
	if err := st.UpdateCVSS("acme", fdir, vec2, nil, "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	// the web saves only an AC reason (the radios as they were: AV:N)
	for k, v := range map[string]string{"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"} {
		form.Set(k, v)
	}
	form.Set("reason_AC", "needs a race")
	// the vector in the form is the one the user read, so it is not theirs
	// to write: no conflict, and the newer vector stays
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", form, nil); rec.Code != http.StatusOK {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	ref, _ := st.Finding("acme", fdir)
	if ref.F.Meta.CVSS != vec2 || ref.F.Meta.CVSSReasons["AC"] != "needs a race" {
		t.Fatalf("cvss %q reasons %v", ref.F.Meta.CVSS, ref.F.Meta.CVSSReasons)
	}
}

// No editor blames someone else for a conflict.
func TestNoSomeoneElse(t *testing.T) {
	for _, dir := range []string{".", "templates"} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, en := range ents {
			name := en.Name()
			if en.IsDir() || strings.HasSuffix(name, "_test.go") || !(strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".html")) {
				continue
			}
			b, _ := os.ReadFile(filepath.Join(dir, name))
			if strings.Contains(string(b), `changed by someone else`) || strings.Contains(string(b), `Changed by someone else`) {
				t.Errorf("%s blames someone else", name)
			}
		}
	}
}
