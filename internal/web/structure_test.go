package web

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// structForm is the structure form as the page fills it from cfg.
func (e *env) structForm() url.Values {
	c := e.srv.conf()
	v := url.Values{"section": c.Sections, "detail": c.DetailsRows, "severity": c.Severities, "report": c.ReportSections, "version": {c.CVSS.Version}}
	for _, k := range []string{"section", "detail", "severity", "report"} {
		v["was_"+k] = slices.Clone(v[k]) // each row's original name
	}
	for k, x := range c.CVSS.Standard {
		v.Set("std_"+k, x)
	}
	raw, _ := os.ReadFile(filepath.Join(e.dir, ".yars", "config.yaml"))
	v.Set("base", store.BodyHash(string(raw)))
	return v
}

// The page shows config.yaml as it is on disk (a push included) and a
// save from a page older than the file is a conflict, not an overwrite.
func TestStructureSaveConflict(t *testing.T) {
	e := setup(t)
	v := e.structForm()
	b := e.do(t, "dora", "GET", "/admin/structure", nil, nil).Body.String()
	if !strings.Contains(b, `name="base" value="`+v.Get("base")+`"`) {
		t.Fatalf("no base:\n%s", b)
	}
	// someone pushes a config.yaml
	os.MkdirAll(filepath.Join(e.dir, ".yars"), 0o755)
	pushed := "sections: [Summary, Fix]\n"
	os.WriteFile(filepath.Join(e.dir, ".yars", "config.yaml"), []byte(pushed), 0o644)
	if b := e.do(t, "dora", "GET", "/admin/structure", nil, nil).Body.String(); !strings.Contains(b, `name="section" value="Summary"`) || !strings.Contains(b, `name="base" value="`+store.BodyHash(pushed)+`"`) {
		t.Fatalf("page not from disk:\n%s", b)
	}
	// a move keeps the page's base; the save from the old page is refused
	v.Set("op", "up:section:1")
	if b := e.do(t, "dora", "POST", "/admin/structure", v, nil).Body.String(); !strings.Contains(b, `name="base" value="`+v.Get("base")+`"`) {
		t.Fatalf("op changed the base:\n%s", b)
	}
	v.Set("op", "save")
	rec := e.do(t, "dora", "POST", "/admin/structure", v, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "The structure changed since you read it") {
		t.Fatalf("stale save %d:\n%s", rec.Code, rec.Body.String())
	}
	if got, _ := os.ReadFile(filepath.Join(e.dir, ".yars", "config.yaml")); string(got) != pushed {
		t.Fatalf("overwritten:\n%s", got)
	}
	// the conflict page carries the file's base: saving again is deliberate
	if !strings.Contains(rec.Body.String(), `name="base" value="`+store.BodyHash(pushed)+`"`) {
		t.Fatalf("conflict base:\n%s", rec.Body.String())
	}
}

func TestStructurePage(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "GET", "/admin/structure", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/admin/structure", nil, nil).Body.String()
	for _, want := range []string{`class="atab on" href="/admin/structure"`, `name="section" value="Description"`, `name="detail" value="Location"`, `name="severity" value="critical"`, `name="report" value="Scope"`, `name="std_AV" value="N" checked`, "<th", `class="btn save w128"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q:\n%s", want, b)
		}
	}
	noInline(t, "structure", b)
	// rating severities can't be renamed or removed
	if !strings.Contains(b, `name="severity" value="critical" readonly`) {
		t.Fatalf("critical editable:\n%s", b)
	}
}

func TestStructureEditOps(t *testing.T) {
	e := setup(t)
	v := e.structForm()
	v.Set("op", "up:section:1") // Impact above Description
	rec := e.do(t, "dora", "POST", "/admin/structure", v, nil)
	b := rec.Body.String()
	if rec.Code != 200 || strings.Index(b, `value="Impact"`) > strings.Index(b, `value="Description"`) || !strings.Contains(b, "1 change") {
		t.Fatalf("up %d:\n%s", rec.Code, b)
	}
	v = e.structForm()
	v.Set("op", "add:detail")
	v.Set("new_detail", "Affected users")
	if b := e.do(t, "dora", "POST", "/admin/structure", v, nil).Body.String(); !strings.Contains(b, `name="detail" value="Affected users"`) {
		t.Fatalf("add:\n%s", b)
	}
	v = e.structForm()
	v.Set("op", "del:section:4")
	if b := e.do(t, "dora", "POST", "/admin/structure", v, nil).Body.String(); strings.Contains(b, `name="section" value="References"`) {
		t.Fatalf("del:\n%s", b)
	}
	// nothing was written by the edits
	if _, err := os.Stat(filepath.Join(e.dir, ".yars", "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("config written before Save")
	}
}

func TestStructureSave(t *testing.T) {
	e := setup(t)
	v := e.structForm()
	v["section"] = []string{"Description", "Impact", "Steps to reproduce", "Remediation"}
	v["severity"] = append(v["severity"], "note")
	v.Set("std_PR", "L")
	v.Set("std_A", "-")
	v.Set("op", "save")
	rec := e.do(t, "dora", "POST", "/admin/structure", v, nil)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/admin/structure?saved=") {
		t.Fatalf("save %d %q:\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	out, _ := exec.Command("git", "-C", e.dir, "log", "-1", "--format=%an|%s").Output()
	if strings.TrimSpace(string(out)) != "dora|config: report structure" {
		t.Fatalf("commit %q", out)
	}
	c := e.srv.conf()
	if !slices.Contains(c.Sections, "Steps to reproduce") || !slices.Contains(c.Severities, "note") || c.CVSS.Standard["PR"] != "L" {
		t.Fatalf("not applied: %+v", c)
	}
	if _, ok := c.CVSS.Standard["A"]; ok {
		t.Fatalf("A still has a standard: %v", c.CVSS.Standard)
	}
	if !slices.Equal(e.srv.Store.Config().Sections, c.Sections) {
		t.Fatal("store config not applied")
	}
	// the saved state shows the commit
	b := e.do(t, "dora", "GET", rec.Header().Get("Location"), nil, nil).Body.String()
	if !strings.Contains(b, "Saved") || !strings.Contains(b, ".yars/config.yaml") {
		t.Fatalf("saved state:\n%s", b)
	}
	// new findings get the new sections
	e.srv.Store.CreateFinding("acme", "XSS", e.authorOf(wAlice))
	if b := e.do(t, "alice", "GET", "/e/acme/f/002", nil, nil).Body.String(); !strings.Contains(b, "<h2>Steps to reproduce</h2>") {
		t.Fatal("new section not on new finding")
	}
}

// replaced is list with old swapped for new, in place.
func replaced(list []string, old, new string) []string {
	out := slices.Clone(list)
	if i := slices.Index(out, old); i >= 0 {
		out[i] = new
	}
	return out
}

// Q10: a section renamed in Admin › Structure is renamed inside every
// finding, which keeps showing its text.
func TestStructureRenameRewritesFindings(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Data loss.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	v := e.structForm()
	v["section"] = replaced(v["section"], "Impact", "Business impact")
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, "<h2>Business impact</h2>") || strings.Contains(b, "<h2>Impact</h2>") || !strings.Contains(b, "Data loss.") {
		t.Fatalf("finding after the rename:\n%s", between(b, "<main>", "</main>"))
	}
}

// Q10: a rename that would stop at a finding (text under both names, as a
// push can write) is refused before the save: nothing is saved or renamed,
// so no finding is left under a name the page no longer shows.
func TestStructureRenameConflictRefused(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if err := st.UpdateSection("acme", fdir, "Impact", "Data loss.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSection("acme", fdir, "Business impact", "Fines.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(e.dir, "engagements", "acme", "findings", fdir, "finding.md"))
	v := e.structForm()
	v["section"] = replaced(v["section"], "Impact", "Business impact")
	v.Set("op", "save")
	rec := e.do(t, "dora", "POST", "/admin/structure", v, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "F-001") || !strings.Contains(rec.Body.String(), "text under both Impact and Business impact") {
		t.Fatalf("rename conflict %d:\n%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(e.dir, ".yars", "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("config.yaml written")
	}
	if after, _ := os.ReadFile(filepath.Join(e.dir, "engagements", "acme", "findings", fdir, "finding.md")); string(after) != string(before) {
		t.Fatalf("finding changed:\n%s", after)
	}
}

// Q10: a name findings still use cannot be removed: the page says which,
// as a push does, and nothing is saved.
func TestStructureRemoveInUseRefused(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Data loss.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	v := e.structForm()
	v["section"] = slices.DeleteFunc(slices.Clone(v["section"]), func(x string) bool { return x == "Impact" })
	v.Set("op", "save")
	rec := e.do(t, "dora", "POST", "/admin/structure", v, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Impact") || !strings.Contains(rec.Body.String(), "is still used by: acme/F-001") {
		t.Fatalf("remove in use %d:\n%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(e.dir, ".yars", "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("config.yaml written")
	}
}

// engHead is the last commit of the acme engagement repository.
func (e *env) engHead(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "-C", filepath.Join(e.dir, "engagements", "acme"), "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// swapRow is the form with the row named old removed and a new row named
// name, whose original is was ("" = an added row), at the end.
func swapRow(v url.Values, field, old, name, was string) {
	i := slices.Index(v[field], old)
	v[field] = append(slices.Delete(slices.Clone(v[field]), i, i+1), name)
	v["was_"+field] = append(slices.Delete(slices.Clone(v["was_"+field]), i, i+1), was)
}

// A removed name and an added one are not a rename: the row carries the name
// it had, and only a row that kept it is renamed. Removing a name in use is
// refused, whatever is added beside it.
func TestStructureRemoveAndAddIsNoRename(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Data loss.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(e.dir, "engagements", "acme", "findings", fdir, "finding.md")
	before, _ := os.ReadFile(file)
	for _, was := range []string{"", "Ghost"} { // an added row; a forged original
		v := e.structForm()
		swapRow(v, "section", "Impact", "Notes", was)
		v.Set("op", "save")
		rec := e.do(t, "dora", "POST", "/admin/structure", v, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "is still used by: acme/F-001") {
			t.Fatalf("was %q: %d:\n%s", was, rec.Code, rec.Body.String())
		}
		if _, err := os.Stat(filepath.Join(e.dir, ".yars", "config.yaml")); !os.IsNotExist(err) {
			t.Fatal("config.yaml written")
		}
		if after, _ := os.ReadFile(file); string(after) != string(before) {
			t.Fatalf("finding changed:\n%s", after)
		}
	}
	// an unused name leaves and another joins: saved, no finding is rewritten
	head := e.engHead(t)
	v := e.structForm()
	swapRow(v, "section", "References", "Notes", "")
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("unused %d:\n%s", rec.Code, rec.Body.String())
	}
	if now := e.engHead(t); now != head {
		t.Fatalf("findings rewritten: %s, was %s", now, head)
	}
	// an original another row still holds is no rename either
	v = e.structForm()
	v["section"] = append(v["section"], "Extra")
	v["was_section"] = append(v["was_section"], "Description")
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("claimed twice %d:\n%s", rec.Code, rec.Body.String())
	}
	if now := e.engHead(t); now != head {
		t.Fatalf("findings rewritten: %s, was %s", now, head)
	}
}

// A row keeps its original name through a move, so a rename made before the
// move still reaches the findings.
func TestStructureRenameKeptThroughMove(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Data loss.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	v := e.structForm()
	i := slices.Index(v["section"], "Impact")
	v["section"] = replaced(v["section"], "Impact", "Business impact")
	v.Set("op", "up:section:"+strconv.Itoa(i))
	b := e.do(t, "dora", "POST", "/admin/structure", v, nil).Body.String()
	row := `name="section" value="Business impact" aria-label="Sections Business impact"><input type="hidden" name="was_section" value="Impact">`
	if !strings.Contains(b, row) {
		t.Fatalf("the moved row lost its original:\n%s", between(b, "<main>", "</main>"))
	}
	// the form as the page now holds it
	v["section"][i-1], v["section"][i] = v["section"][i], v["section"][i-1]
	v["was_section"][i-1], v["was_section"][i] = v["was_section"][i], v["was_section"][i-1]
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	b = e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, "<h2>Business impact</h2>") || !strings.Contains(b, "Data loss.") {
		t.Fatalf("finding after the rename:\n%s", between(b, "<main>", "</main>"))
	}
	// an added row has no original
	v = e.structForm()
	v.Set("op", "add:detail")
	v.Set("new_detail", "Affected users")
	if b := e.do(t, "dora", "POST", "/admin/structure", v, nil).Body.String(); !strings.Contains(b, `name="detail" value="Affected users" aria-label="Details rows Affected users"><input type="hidden" name="was_detail" value="">`) {
		t.Fatalf("added row:\n%s", between(b, "<main>", "</main>"))
	}
}

// A report section removed beside one added keeps its text where it was.
func TestStructureReportRemoveAndAddKeepsText(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if err := st.UpdateReportSection("acme", "Scope", "The web portal.", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	v := e.structForm()
	swapRow(v, "report", "Scope", "Appendix", "")
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if got, _ := st.ReportSection("acme", "Appendix"); got != "" {
		t.Fatalf("Appendix took the text: %q", got)
	}
	if got, _ := st.ReportSection("acme", "Scope"); !strings.Contains(got, "The web portal.") {
		t.Fatalf("Scope lost its text: %q", got)
	}
}

func TestStructureSaveInvalid(t *testing.T) {
	e := setup(t)
	v := e.structForm()
	v["severity"] = []string{"critical", "high", "medium", "low"} // info missing
	v.Set("op", "save")
	rec := e.do(t, "dora", "POST", "/admin/structure", v, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "info") {
		t.Fatalf("invalid %d:\n%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(e.dir, ".yars", "config.yaml")); !os.IsNotExist(err) {
		t.Fatal("invalid config kept")
	}
	v = e.structForm()
	v["section"] = []string{"A", "A"}
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate %d", rec.Code)
	}
	// two report sections that would share a file
	v = e.structForm()
	v["report"] = []string{"Scope", "Scope."}
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "share a file") {
		t.Fatalf("report slug collision %d", rec.Code)
	}
	v = e.structForm()
	v.Set("std_AV", "Q")
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad standard %d", rec.Code)
	}
}
