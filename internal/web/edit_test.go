package web

import (
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

func TestCreateFindingFlow(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"Reflected XSS"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/002" {
		t.Fatalf("code %d loc %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := e.lastCommit(t); got != "alice|F-002: create" {
		t.Fatalf("commit %q", got)
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil); rec.Code != 200 {
		t.Fatalf("form code %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"  "}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty title code %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {strings.Repeat("a", 201)}}, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "1–200 characters") {
		t.Fatalf("overlong title code %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/e/nope/findings/new", url.Values{"title": {"x"}}, nil); rec.Code != 404 {
		t.Fatalf("unknown engagement code %d", rec.Code)
	}
}

func TestEditSectionCommits(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "GET", "/e/acme/f/F-001-sql-injection/s/Impact/edit", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<textarea") {
		t.Fatalf("edit form code %d", rec.Code)
	}
	rec = e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", url.Values{"body": {"Attacker reads **all** data."}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<strong>all</strong>") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if got := e.lastCommit(t); got != "bob|F-001: edit Impact" {
		t.Fatalf("commit %q", got)
	}
	rec = e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Steps%20to%20Reproduce", url.Values{"body": {"1. go"}}, nil)
	if rec.Code != 200 || e.lastCommit(t) != "bob|F-001: edit Steps to Reproduce" {
		t.Fatalf("spaced section: code %d commit %q", rec.Code, e.lastCommit(t))
	}
}

func TestNewEngagementForbiddenForPentester(t *testing.T) {
	e := setup(t)
	form := url.Values{"id": {"2026-12-x"}, "name": {"X"}, "client": {"X Corp"}}
	if rec := e.do(t, "alice", "POST", "/engagements/new", form, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester code %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/engagements/new", form, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/2026-12-x" {
		t.Fatalf("director code %d loc %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do(t, "dora", "POST", "/engagements/new", url.Values{"id": {"../x"}, "name": {"X"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id code %d", rec.Code)
	}
}

func TestNoGlobalNewFinding(t *testing.T) {
	e := setup(t)
	for _, m := range []string{"GET", "POST"} {
		if rec := e.do(t, "alice", m, "/findings/new", url.Values{"title": {"x"}}, nil); rec.Code != 404 {
			t.Fatalf("%s code %d", m, rec.Code)
		}
	}
}

func TestExtraSectionEditable(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Notes", "n", "", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Notes", url.Values{"body": {"updated"}}, nil); rec.Code != 200 {
		t.Fatalf("Notes code %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Bogus", url.Values{"body": {"x"}}, nil); rec.Code != 404 {
		t.Fatalf("Bogus code %d", rec.Code)
	}
	b, _ := os.ReadFile(filepath.Join(e.dir, "engagements/acme/findings/F-001-sql-injection/finding.md"))
	if strings.Contains(string(b), "Bogus") {
		t.Fatal("Bogus section written")
	}
}

func TestEditFormCarriesBase(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "GET", "/e/acme/f/F-001-sql-injection/s/Impact/edit", nil, nil)
	if !strings.Contains(rec.Body.String(), `name="base"`) {
		t.Fatal("editor form has no base field")
	}
}

func TestEditConflict409(t *testing.T) {
	e := setup(t)
	form := url.Values{"body": {"bob text"}, "base": {"0000000000000000"}}
	rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", form, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Changed by alice") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "bob text") {
		t.Fatal("user's text not kept in the editor")
	}
}

// htmx 2 drops 4xx bodies by default; the layout must opt 400/409 into
// swapping so conflict and validation editors reach the user.
func TestHtmxSwapsConflictResponses(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(b, `name="htmx-config"`) || !strings.Contains(b, `(400|409)`) {
		t.Fatalf("layout lacks htmx responseHandling for 400/409:\n%s", b[:min(len(b), 600)])
	}
}

func TestEditInvalidBody400(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", url.Values{"body": {"x\n## Remediation\ny"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reserved for sections") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	e := setup(t)
	hdr := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"x"}}, hdr)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d", rec.Code)
	}
	if rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}}, hdr); rec.Code != http.StatusForbidden {
		t.Fatalf("login CSRF code %d", rec.Code)
	}
}

func TestPreview(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/preview", url.Values{"body": {"# Hi\n<script>x</script>"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<h1") || strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

// The preview's f parameter names the finding whose attachments the links
// point at. It goes into src= and href= of the answer, so only a finding
// folder's name is taken: any other value is left out, and the links stay as
// written.
func TestPreviewFindingParamEscaped(t *testing.T) {
	e := setup(t)
	form := url.Values{"body": {"![x](attachments/a.png) [log](attachments/b.txt)"}}
	for _, evil := range []string{`"><img src=x onerror=alert(1)>`, `x" onerror="alert(1)`, `../../other`, `a/b`, `<script>`} {
		rec := e.do(t, "alice", "POST", "/e/acme/preview?f="+url.QueryEscape(evil)+"&s=Impact", form, nil)
		b := rec.Body.String()
		if rec.Code != 200 || strings.Contains(b, evil) || strings.Contains(b, "onerror") || strings.Contains(b, "<script>") || strings.Contains(b, "/e/acme/f/") {
			t.Errorf("f=%q: %d\n%s", evil, rec.Code, b)
		}
		if !strings.Contains(b, `src="attachments/a.png"`) || !strings.Contains(b, `href="attachments/b.txt"`) {
			t.Errorf("f=%q: the links were rewritten:\n%s", evil, b)
		}
	}
	// a finding's folder: the links point at its attachments
	b := e.do(t, "alice", "POST", "/e/acme/preview?f="+fdir+"&s=Impact", form, nil).Body.String()
	if !strings.Contains(b, `src="`+fshort+`/attachments/a.png"`) || !strings.Contains(b, `href="`+fshort+`/attachments/b.txt"`) {
		t.Fatalf("a finding's preview:\n%s", b)
	}
	// the sink itself refuses a folder that is not a name
	in := template.HTML(`<img src="attachments/a.png">`)
	if out := e.srv.linkAttachments(in, store.FindingRef{EngID: "acme", Dir: `x" onerror="alert(1)`}); out != in {
		t.Fatalf("linkAttachments took a bad folder: %s", out)
	}
}

// /engagements/new puts the ticked people and the creator on the team, so a
// director without the admin flag doesn't make an engagement nobody sees.
func TestNewEngagementTeam(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/engagements/new", nil, nil).Body.String()
	for _, n := range []string{"alice", "bob", "carol"} {
		if !strings.Contains(b, `name="member" value="`+n+`"`) {
			t.Fatalf("no checkbox for %s:\n%s", n, b)
		}
	}
	form := url.Values{"id": {"beta"}, "name": {"Beta"}, "member": {"alice", "bob", "nobody"}}
	if rec := e.do(t, "dora", "POST", "/engagements/new", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	got, err := e.srv.Store.Members("beta")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if strings.Join(got, ",") != "alice,bob,dora" {
		t.Fatalf("team %v", got)
	}
	if rec := e.do(t, "alice", "GET", "/e/beta", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("team member can't open it: %d", rec.Code)
	}
	if rec := e.do(t, "carol", "GET", "/e/beta", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("non-member opens it: %d", rec.Code)
	}
}

// Searching the picker keeps the picked template when it still matches,
// else picks the first match, and the preview always follows the pick.
func TestTemplateSearchKeepsPreviewInStep(t *testing.T) {
	e := setup(t)
	e.addTemplate(t, "missing-hsts", "Missing HSTS header")
	e.addTemplate(t, "verbose-errors", "Verbose error pages")
	hx := map[string]string{"HX-Request": "true"}
	b := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil).Body.String()
	if !strings.Contains(b, `hx-include="#tpllist input[name=template]:checked"`) {
		t.Fatalf("search does not send the pick:\n%s", b)
	}
	// the pick still matches: kept
	frag := e.do(t, "alice", "GET", "/e/acme/findings/new/templates?q=e&template=verbose-errors", nil, hx).Body.String()
	if !strings.Contains(frag, `value="verbose-errors" checked`) || strings.Contains(frag, `value="missing-hsts" checked`) ||
		!strings.Contains(frag, `id="tplpreview" hx-swap-oob="true"`) || !strings.Contains(frag, "Verbose error pages.") {
		t.Fatalf("kept pick:\n%s", frag)
	}
	// the pick is filtered out: the first match is picked and previewed
	frag = e.do(t, "alice", "GET", "/e/acme/findings/new/templates?q=hsts&template=verbose-errors", nil, hx).Body.String()
	if !strings.Contains(frag, `value="missing-hsts" checked`) || strings.Contains(frag, "Verbose error pages.") || !strings.Contains(frag, "Missing HSTS header.") {
		t.Fatalf("first match:\n%s", frag)
	}
	// nothing matches: the preview empties
	frag = e.do(t, "alice", "GET", "/e/acme/findings/new/templates?q=zzz&template=verbose-errors", nil, hx).Body.String()
	if !strings.Contains(frag, `id="tplpreview" hx-swap-oob="true"`) || strings.Contains(frag, "Verbose error pages.") || strings.Contains(frag, "<h3>") {
		t.Fatalf("no match:\n%s", frag)
	}
	// Template without a pick is refused, not made blank
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"x"}, "mode": {"template"}, "q": {"zzz"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no pick %d", rec.Code)
	}
	if _, err := e.srv.Store.Finding("acme", "2"); err == nil {
		t.Fatal("finding made without a template")
	}
}

// R6 (Q6): on the website the author can still edit a finding in
// Verification (git refuses it: TestPolicyEditDuringReview).
func TestAuthorEditsInVerificationOnWebsite(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	rec := e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"Fixed what the reviewer asked."}}, nil)
	if rec.Code != 200 || e.lastCommit(t) != "alice|F-001: edit Impact" {
		t.Fatalf("author's edit in verification: %d %q\n%s", rec.Code, e.lastCommit(t), rec.Body.String())
	}
}

// The conflict view shows each side against the text both started from:
// the base line removed, each side's own line added.
func TestConflictDiffAgainstBase(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	alice := config.User{Username: "alice", Role: "pentester"}
	if err := st.UpdateSection("acme", "F-001-sql-injection", "Impact", "base line", "", alice); err != nil {
		t.Fatal(err)
	}
	ref, _ := st.Finding("acme", "F-001-sql-injection")
	body, _ := ref.F.Section("Impact")
	base := store.BodyHash(body)
	if err := st.UpdateSection("acme", "F-001-sql-injection", "Impact", "their line", "", alice); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "alice", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", url.Values{"body": {"my line"}, "base": {base}}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code %d", rec.Code)
	}
	diff := between(rec.Body.String(), `class="cdiff`, "</section>")
	cols := strings.SplitN(diff, `class="ccol"`, 3)
	if len(cols) != 3 {
		t.Fatalf("diff:\n%s", diff)
	}
	for i, want := range []string{"my line", "their line"} {
		col := cols[i+1]
		if !regexp.MustCompile(`class="ln del">.*?base line`).MatchString(col) || !regexp.MustCompile(`class="ln add">.*?`+want).MatchString(col) {
			t.Errorf("column %d lacks the base removed and %q added:\n%s", i, want, col)
		}
	}
}

// A title made only of bidi controls is empty once cleaned: the form says
// so (400 with the form), not a bare error from the store.
func TestNewFindingBidiOnlyTitle(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"\u202e\u2066"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Title is required.") {
		t.Fatalf("%d:\n%s", rec.Code, rec.Body)
	}
}
