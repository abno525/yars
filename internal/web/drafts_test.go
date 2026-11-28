package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

// restoreSlot is the Restore button every guarded editor keeps in its
// footer: invisible until the browser holds a draft, so nothing moves.
const restoreSlot = `<button type="button" class="btn secondary sm w96 invisible" data-draft-restore>Restore</button>`

// guardedForm is the opening tag of the form that posts to save in html.
func guardedForm(t *testing.T, html, save string) string {
	t.Helper()
	i := strings.Index(html, `hx-post="`+save+`"`)
	if i < 0 {
		t.Fatalf("no form posting to %s:\n%s", save, html)
	}
	start := strings.LastIndex(html[:i], "<form")
	return html[start : i+strings.Index(html[i:], ">")+1]
}

// Every guarded editor has the Restore slot in its form, so the browser can
// offer a draft it kept without moving a button.
func TestEveryGuardedEditorHasRestoreSlot(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "Verbose stack trace", "api.acme.test", "open")
	for _, c := range []struct{ page, save string }{
		{fpath + "/s/Impact/edit", fshort + "/s/Impact"},
		{fpath + "/cvss/edit", fshort + "/cvss"},
		{fpath + "/details/edit", fshort + "/details"},
		{fpath + "/assets/edit", fshort + "/assets"},
		{"/e/acme/board?n=L-001", "/e/acme/board/n/L-001/post"},
		{"/e/acme/board?new=1", "/e/acme/board"},
	} {
		rec := e.do(t, "alice", "GET", c.page, nil, nil)
		b := rec.Body.String()
		if rec.Code != 200 {
			t.Fatalf("%s: %d", c.page, rec.Code)
		}
		tag := guardedForm(t, b, c.save)
		if !strings.Contains(tag, " data-guard") {
			t.Errorf("%s: the form is not guarded: %s", c.page, tag)
		}
		form := b[strings.Index(b, tag):]
		form = form[:strings.Index(form, "</form>")]
		if strings.Count(form, restoreSlot) != 1 {
			t.Errorf("%s: the form lacks the invisible Restore slot:\n%s", c.page, form)
		}
	}
	// the two editors the server draws again say where a draft is drawn from
	b := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()
	if tag := guardedForm(t, b, fshort+"/cvss"); !strings.Contains(tag, `data-draft-via="`+fshort+`/cvss/calc"`) {
		t.Errorf("CVSS editor: %s", tag)
	}
	b = e.do(t, "alice", "GET", fpath+"/assets/edit", nil, nil).Body.String()
	if tag := guardedForm(t, b, fshort+"/assets"); !strings.Contains(tag, `data-draft-via="`+fshort+`/assets"`) {
		t.Errorf("assets editor: %s", tag)
	}
	// the new lead's Cancel drops the draft as an editor's Cancel does
	b = e.do(t, "alice", "GET", "/e/acme/board?new=1", nil, nil).Body.String()
	if !regexp.MustCompile(`<a class="btn secondary sm w96"[^>]* data-guard-cancel>Cancel</a>`).MatchString(b) {
		t.Errorf("the new lead's Cancel is no guard-cancel:\n%s", between(b, `class="tbnew"`, "</form>"))
	}
}

// A draft of the assets editor can hold more rows than the editor opens
// with: the server draws the posted rows and saves nothing.
func TestAssetsDrawPostedRows(t *testing.T) {
	e := setup(t)
	base := editorBase(t, e.do(t, "alice", "GET", fpath+"/assets/edit", nil, nil).Body.String())
	rec := e.do(t, "alice", "POST", fpath+"/assets", url.Values{"op": {"draw"}, "base": {"old-base"}, "n": {"3"},
		"host_0": {"a.acme.test"}, "host_1": {"b.acme.test"}, "note_2": {"third row"}}, nil)
	b := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("draw %d:\n%s", rec.Code, b)
	}
	tag := guardedForm(t, b, fshort+"/assets")
	if !strings.Contains(tag, "data-unsaved") {
		t.Errorf("the drawn rows are not unsaved: %s", tag)
	}
	for _, want := range []string{`name="n" value="3"`, `name="host_0" value="a.acme.test"`, `name="host_1" value="b.acme.test"`, `name="note_2" value="third row"`,
		`name="base" value="old-base"`} {
		if !strings.Contains(b, want) {
			t.Errorf("drawn editor lacks %s:\n%s", want, b)
		}
	}
	if base == "old-base" {
		t.Fatal("test: the base is not told apart")
	}
	if ref, _ := e.srv.Store.Finding("acme", "F-001-sql-injection"); len(ref.F.Meta.Assets) != 0 {
		t.Fatalf("drawing saved rows: %v", ref.F.Meta.Assets)
	}
}

// A refused save never answers 2xx: the browser drops a draft on a 2xx
// answer only, so the text of a refused save stays kept.
func TestRefusedSaveKeepsDraft(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "Verbose stack trace", "api.acme.test", "open")
	carol := gitrepo.Author{Name: "carol", Email: "carol@yars.local"}
	// the bases an editor was opened with, then a colleague's change
	details := e.do(t, "alice", "GET", fpath+"/details/edit", nil, nil).Body.String()
	row := regexp.MustCompile(`name="(row:[^"]+)"`).FindStringSubmatch(details)
	rowBase := regexp.MustCompile(`name="(base:[^"]+)" value="([^"]*)"`).FindStringSubmatch(details)
	if row == nil || rowBase == nil {
		t.Fatalf("details editor has no row:\n%s", details)
	}
	name := strings.TrimPrefix(row[1], "row:")
	cvssBase := editorBase(t, e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String())
	assetsBase := editorBase(t, e.do(t, "alice", "GET", fpath+"/assets/edit", nil, nil).Body.String())
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.UpdateDetails("acme", "F-001-sql-injection", map[string]string{name: "carol's value"}, "", dora); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.UpdateCVSS("acme", "F-001-sql-injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil, "", dora); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "carol's newer text", "", carol); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what, path string
		form       url.Values
		want       int
	}{
		{"details: a row saved with the draft's base after a colleague's save", fpath + "/details",
			url.Values{row[1]: {"alice's draft"}, rowBase[1]: {rowBase[2]}}, http.StatusConflict},
		{"details: a draft without a base", fpath + "/details",
			url.Values{row[1]: {"alice's draft"}, rowBase[1]: {"none"}}, http.StatusConflict},
		{"cvss: the draft's base after a colleague's save", fpath + "/cvss",
			func() url.Values {
				f := vecForm(map[string]string{"AV": "L", "reason_AC": "race condition", "reason_AV": "local only"})
				f.Set("base", cvssBase)
				return f
			}(), http.StatusConflict},
		{"cvss: an incomplete vector", fpath + "/cvss", vecForm(map[string]string{"A": ""}), http.StatusBadRequest},
		{"assets: a row without host or URL", fpath + "/assets",
			url.Values{"base": {assetsBase}, "n": {"1"}, "port_0": {"notaport"}}, http.StatusBadRequest},
		{"assets: a draft without a base", fpath + "/assets",
			url.Values{"base": {"none"}, "n": {"1"}, "host_0": {"a.acme.test"}}, http.StatusConflict},
		{"board reply: empty", "/e/acme/board/n/L-001/post", url.Values{"text": {" "}}, http.StatusBadRequest},
		{"new lead: no title", "/e/acme/board", url.Values{"title": {""}, "text": {"x"}}, http.StatusBadRequest},
	} {
		rec := e.do(t, "alice", "POST", c.path, c.form, map[string]string{"HX-Request": "true"})
		if rec.Code != c.want {
			t.Errorf("%s: %d, want %d:\n%s", c.what, rec.Code, c.want, rec.Body.String())
		}
	}
}

// The script that keeps drafts: which fields it takes, its caps, and when a
// draft goes. Only the text is checked here; the writing runs in a browser.
func TestDraftScriptRules(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	fields := jsFunc(t, js, "function yarsDraftFields(form)", "\n}\n")
	for _, want := range []string{
		"yarsDraftSecret.test(el.name)",         // no field named like a secret
		"el.type === 'hidden'", "yarsDraftBase", // of the hidden fields, the bases only
		"el.type === 'radio'", "el.checked",
		"el.tagName === 'TEXTAREA'", "el.type === 'text'",
	} {
		if !strings.Contains(fields, want) {
			t.Errorf("yarsDraftFields lacks %q:\n%s", want, fields)
		}
	}
	for _, never := range []string{"password", "'file'", "checkbox"} {
		if strings.Contains(fields, never) {
			t.Errorf("yarsDraftFields names %q:\n%s", never, fields)
		}
	}
	if !strings.Contains(js, "var yarsDraftSecret = /pass|token|secret|api.?key/i;") {
		t.Error("no rule for fields named like a secret")
	}
	write := jsFunc(t, js, "function yarsDraftWrite(form)", "\n}\n")
	for _, want := range []string{
		"!yarsUser()",             // no account, no draft
		"!form.isConnected",       // a form that left the page writes nothing
		"yarsDirty(form)",         // only unsaved text
		"s.length > yarsDraftMax", // the size cap
		"yarsDraftTrim(",          // the count cap
		"at: Date.now()",          // the sweep reads it
	} {
		if !strings.Contains(write, want) {
			t.Errorf("yarsDraftWrite lacks %q:\n%s", want, write)
		}
	}
	for _, want := range []string{"var yarsDraftMax = 200000;", "var yarsDraftKeep = 20;", "var yarsDraftDays = 14;"} {
		if !strings.Contains(js, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// a 401 keeps every guarded form at once
	if fn := jsFunc(t, js, "function yarsExpired(own)", "\n}\n"); !strings.Contains(fn, "form[data-guard]") || !strings.Contains(fn, "yarsDraftWrite(form)") {
		t.Errorf("yarsExpired writes no draft:\n%s", fn)
	}
	// Restore sets values only: a draft is text another script could have written
	i := strings.Index(js, "closest('[data-draft-restore]')")
	if i < 0 {
		t.Fatal("no Restore handler")
	}
	restore := js[i : i+strings.Index(js[i:], "\n});")]
	put := jsFunc(t, js, "function yarsDraftPut(form, d)", "\n}\n")
	for _, fn := range []string{restore, put} {
		if strings.Contains(fn, "innerHTML") || strings.Contains(fn, "insertAdjacentHTML") {
			t.Errorf("Restore writes HTML:\n%s", fn)
		}
	}
	// Log out removes the account's drafts
	i = strings.Index(js, `form[action="/logout"]`)
	if i < 0 || !strings.Contains(js[i:i+400], "yarsForget('yars-draft:' + yarsUser() + ':')") {
		t.Error("Log out keeps the drafts")
	}
	// a draft is never sent: the only reader hands it to the form it came from
	if strings.Count(js, "localStorage.getItem(yarsDraftKey(form))") != 1 {
		t.Error("the draft is read in more than one place")
	}
	// a confirmed Discard on the team board drops its drafts: the question
	// names the board, and the request that follows it drops them
	if fn := jsFunc(t, js, "document.addEventListener('htmx:confirm'", "\n});"); !strings.Contains(fn, "yarsBoardDiscard = null;") || !strings.Contains(fn, "yarsBoardDiscard = tg;") {
		t.Errorf("a board Discard is not remembered:\n%s", fn)
	}
	if fn := jsFunc(t, js, "var yarsBoardDiscard = null;", "\n});"); !strings.Contains(fn, "'htmx:beforeRequest'") || !strings.Contains(fn, "evt.detail.target === b") || !strings.Contains(fn, "yarsDraftDrop") {
		t.Errorf("a board Discard keeps the draft:\n%s", fn)
	}
	// and so does a Back that was confirmed
	if fn := jsFunc(t, js, "var htmxBack = restore;", "\n  };"); !strings.Contains(fn, "yarsDirty(b)") || !strings.Contains(fn, "yarsDraftDrop") {
		t.Errorf("a confirmed Back keeps the draft:\n%s", fn)
	}
	// a write that is pending when the form is sent is cancelled
	i = strings.Index(js, "evt.detail.xhr.yarsDraftKey = yarsDraftKey(form);")
	if i < 0 || !strings.Contains(js[i-300:i], "clearTimeout(form.yarsDraftT);") {
		t.Error("a pending write is not cancelled when the form is sent")
	}
}
