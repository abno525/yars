package web

import (
	"image/color"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/store"
)

// redacted gives the test finding two images, shot.png redacted after its
// upload (marked) and other.png as uploaded (not marked).
func redacted(t *testing.T, e *env) {
	t.Helper()
	for n, c := range map[string]color.Color{"shot.png": color.White, "other.png": color.Gray{Y: 128}} {
		if rec := e.sendFile(t, "alice", fpath+"/attachments", n, testPNG(t, c)); rec.Code != 200 {
			t.Fatalf("upload %s %d", n, rec.Code)
		}
	}
	if rec := e.sendFile(t, "alice", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, color.Black)); rec.Code != 200 {
		t.Fatalf("redact %d:\n%s", rec.Code, rec.Body.String())
	}
}

// rowOf is the Attachments panel's row of one file.
func rowOf(t *testing.T, panel, name string) string {
	t.Helper()
	i := strings.Index(panel, `<tr><td class="mono" title="`+name+`">`)
	if i < 0 {
		t.Fatalf("no row %s:\n%s", name, panel)
	}
	return panel[i : i+strings.Index(panel[i:], "</tr>")]
}

const purgeLink = `<a class="btn ghost sm w96" href="/e/acme/f/001/attachments/shot.png/purge">Purge</a>`

// D28: a director sees Purge in the second slot of a marked row; other rows
// and other roles keep the empty slot.
func TestPurgeLinkOnlyForDirectorOnMarkedRow(t *testing.T) {
	e := setup(t)
	redacted(t, e)
	for _, b := range []string{e.do(t, "dora", "GET", fpath, nil, nil).Body.String(), e.do(t, "dora", "GET", fpath+"/attachments", nil, nil).Body.String()} {
		p := attachmentsPanel(t, b)
		if row := rowOf(t, p, "shot.png"); !strings.Contains(row, `>Open</a>`+purgeLink+`</div>`) {
			t.Fatalf("no Purge on the marked row:\n%s", row)
		}
		if row := rowOf(t, p, "other.png"); strings.Contains(row, "/purge") || !strings.Contains(row, `>Open</a><span class="slot w96"></span>`) {
			t.Fatalf("the unmarked row:\n%s", row)
		}
	}
	for _, u := range []string{"alice", "bob"} {
		if p := attachmentsPanel(t, e.do(t, u, "GET", fpath, nil, nil).Body.String()); strings.Contains(p, "/purge") || !strings.Contains(rowOf(t, p, "shot.png"), `<span class="slot w96"></span>`) {
			t.Fatalf("Purge for %s:\n%s", u, p)
		}
	}
}

// D28: the confirm page names the file and the engagement and says what a
// purge means for clones; Cancel goes back to the panel.
func TestPurgeConfirmPage(t *testing.T) {
	e := setup(t)
	redacted(t, e)
	rec := e.do(t, "dora", "GET", fpath+"/attachments/shot.png/purge", nil, nil)
	b := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm page %d:\n%s", rec.Code, b)
	}
	for _, want := range []string{`<form class="newf" method="post" action="/e/acme/f/001/attachments/shot.png/purge">`,
		`<h1 title="shot.png">Purge shot.png from history</h1>`, `<td class="mono" title="shot.png">shot.png</td>`, `<td title="ACME Web">ACME Web</td>`,
		"<td>Existing clones of this engagement must be cloned again</td>",
		`<table class="kv details purgekv flush"><thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead>`,
		`<a class="btn secondary w96" href="/e/acme/f/001#attachments">Cancel</a>`, `<button class="btn danger w112">Purge</button>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("confirm page lacks %s:\n%s", want, b)
		}
	}
	noInline(t, "purge page", b)
	// the label column keeps its width; the value column takes the rest
	if css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String(); !strings.Contains(css, ".kv.purgekv th + th { width: auto; }") {
		t.Fatal("style.css: the value column is not left to take the rest")
	}
	// a file that is not there: neither the page nor the purge; one with no
	// original in history (no mark, no link): no page
	for _, c := range []struct{ m, n string }{{"GET", "none.png"}, {"POST", "none.png"}, {"GET", "other.png"}} {
		if rec := e.do(t, "dora", c.m, fpath+"/attachments/"+c.n+"/purge", url.Values{}, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s %d", c.m, c.n, rec.Code)
		}
	}
}

// D28: the purge takes the mark away and lands on the panel.
func TestPurgePostRemovesMark(t *testing.T) {
	e := setup(t)
	redacted(t, e)
	rec := e.do(t, "dora", "POST", fpath+"/attachments/shot.png/purge", url.Values{}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001#attachments" {
		t.Fatalf("purge %d %q:\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	p := attachmentsPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	if strings.Contains(p, "histdot") || strings.Contains(p, "/purge") {
		t.Fatalf("still marked after the purge:\n%s", p)
	}
	// the redacted copy is what the finding still holds
	if rec := e.do(t, "dora", "GET", fpath+"/attachments/shot.png", nil, nil); rec.Code != 200 || rec.Body.String() != string(testPNG(t, color.Black)) {
		t.Fatalf("the current version %d", rec.Code)
	}
}

// D28: a copy of the original under another name keeps it in history: the
// page says where (409) and the mark stays.
func TestPurgeRefusedWhileCopyElsewhere(t *testing.T) {
	e := setup(t)
	redacted(t, e)
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "copy.png", testPNG(t, color.White)); rec.Code != 200 {
		t.Fatalf("upload %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", fpath+"/attachments/shot.png/purge", url.Values{}, nil)
	// the heading names the file; the slot (one line) says where the copy is
	if b := rec.Body.String(); rec.Code != http.StatusConflict || !strings.Contains(between(b, `<div class="errslot">`, "</div>"), ">An earlier version is also at F-001-sql-injection/attachments/copy.png; redact it there first</p>") {
		t.Fatalf("purge with a copy %d:\n%s", rec.Code, b)
	}
	if p := attachmentsPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); !strings.Contains(rowOf(t, p, "shot.png"), "histdot") {
		t.Fatalf("a refused purge took the mark:\n%s", p)
	}
}

// D28: on an archived engagement a director is told it is archived, and no
// row offers Purge.
func TestPurgeArchivedSaysArchived(t *testing.T) {
	e := setup(t)
	redacted(t, e)
	if rec := e.do(t, "dora", "POST", "/e/acme/archive", url.Values{}, nil); rec.Code >= 400 {
		t.Fatalf("archive %d", rec.Code)
	}
	for _, m := range []string{"GET", "POST"} {
		rec := e.do(t, "dora", m, fpath+"/attachments/shot.png/purge", url.Values{}, nil)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "archived") {
			t.Fatalf("%s on an archived engagement %d: %s", m, rec.Code, rec.Body.String())
		}
	}
	if p := attachmentsPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); strings.Contains(p, "/purge") {
		t.Fatalf("Purge on an archived engagement:\n%s", p)
	}
}

// D28: a purge runs git over the whole history, which may outlast the
// server's write timeout: the route lifts it.
func TestPurgeOutlivesWriteTimeout(t *testing.T) {
	e := setupSerial(t)
	redacted(t, e)
	// the purge waits for the lock (a push holding it) past the timeout
	unlock := e.srv.Store.LockEngagement("acme")
	go func() { time.Sleep(time.Second); unlock() }()
	hs := e.srv.HTTPServer("127.0.0.1:0")
	hs.WriteTimeout = 300 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+fpath+"/attachments/shot.png/purge", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["dora"]})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("code %d", resp.StatusCode)
	}
}

// D28: a purge whose cleanup failed says so on its page (500), keeps the
// mark and the Purge button; Purge again finishes it.
func TestPurgeNotFinishedPage(t *testing.T) {
	e := setup(t)
	redacted(t, e)
	lock := filepath.Join(e.dir, "engagements", "acme", ".git", "objects", "info", "commit-graph.lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "dora", "POST", fpath+"/attachments/shot.png/purge", url.Values{}, nil)
	b := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || !strings.Contains(between(b, `<div class="errslot">`, "</div>"), ">Purged from history, but not finished (see the server log); Purge again to finish</p>") ||
		!strings.Contains(b, `<button class="btn danger w112">Purge</button>`) {
		t.Fatalf("not finished %d:\n%s", rec.Code, b)
	}
	if p := attachmentsPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); !strings.Contains(rowOf(t, p, "shot.png"), purgeLink) {
		t.Fatalf("no mark or Purge while not finished:\n%s", p)
	}
	os.Remove(lock)
	if rec := e.do(t, "dora", "POST", fpath+"/attachments/shot.png/purge", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("Purge again %d:\n%s", rec.Code, rec.Body.String())
	}
	if p := attachmentsPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); strings.Contains(p, "histdot") {
		t.Fatalf("still marked:\n%s", p)
	}
}

// retests makes rt1 and rt2, retests of the test finding, after shot.png
// was uploaded; rt2 is archived.
func retests(t *testing.T, e *env) {
	t.Helper()
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "shot.png", testPNG(t, color.White)); rec.Code != 200 {
		t.Fatalf("upload %d", rec.Code)
	}
	// complete for the copies only (Q11): the tests go on to redact the
	// original as its author
	e.whileComplete(t, func() {
		for _, id := range []string{"rt1", "rt2"} {
			if err := e.srv.Store.CreateRetest(store.Engagement{ID: id, Name: "Retest " + id}, "acme", []string{fdir}, "", wDora); err != nil {
				t.Fatal(err)
			}
		}
	})
	if err := e.srv.Store.Archive("rt2", wDora); err != nil {
		t.Fatal(err)
	}
}

// Q12: a redaction reaches the retests' copies; one it leaves (archived)
// is named for a toast after the save, by its name, each time while it
// holds an earlier version; open again, the next redaction reaches it.
func TestRedactNamesRetestLeft(t *testing.T) {
	e := setup(t)
	retests(t, e)
	left := func(c color.Color) string {
		t.Helper()
		rec := e.sendFile(t, "alice", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, c))
		got, err := url.PathUnescape(rec.Header().Get("X-Yars-Unredacted"))
		if rec.Code != 200 || err != nil {
			t.Fatalf("redact %d %v", rec.Code, err)
		}
		return got
	}
	if got := left(color.Black); got != "not redacted in Retest rt2 (archived)" {
		t.Fatalf("left %q", got)
	}
	if b, _ := e.srv.Store.ReadAttachment("rt1", fdir, "attachments/shot.png"); string(b) != string(testPNG(t, color.Black)) {
		t.Fatal("rt1's copy was not redacted")
	}
	if js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String(); !strings.Contains(js, "var left = r.headers.get('X-Yars-Unredacted');") ||
		!strings.Contains(js, "if (left) yarsToast(name + ': ' + decodeURIComponent(left), true);") {
		t.Fatal("app.js does not show what the redaction left")
	}
	if got := left(color.Gray{Y: 32}); got != "not redacted in Retest rt2 (archived)" {
		t.Fatalf("second redaction left %q", got)
	}
	// none left: no header
	if err := e.srv.Store.Unarchive("rt2", wDora); err != nil {
		t.Fatal(err)
	}
	if got := left(color.Gray{Y: 64}); got != "" {
		t.Fatalf("third redaction left %q", got)
	}
	if b, _ := e.srv.Store.ReadAttachment("rt2", fdir, "attachments/shot.png"); string(b) != string(testPNG(t, color.Gray{Y: 64})) {
		t.Fatal("rt2's copy was not redacted once open")
	}
}

// Q12: the toast names each retest a redaction left by its name (the ID
// when it has none), and only counts the ones the redactor cannot see.
func TestUnredactedText(t *testing.T) {
	e := setup(t)
	retests(t, e)
	got := e.srv.unredacted(store.Redaction{Archived: []string{"rt2"}, Locked: []string{"rt1"}, Failed: []string{"gone"}, Hidden: []string{"x", "y"}})
	if want := "not redacted in Retest rt2 (archived), Retest rt1 (locked), gone (failed), 2 retests (no access)"; got != want {
		t.Fatalf("got %q", got)
	}
	if got := e.srv.unredacted(store.Redaction{Redacted: []string{"rt1"}}); got != "" {
		t.Fatalf("none left: %q", got)
	}
}

// Q12: the confirm page lists the retests holding the original (rt1 in
// its history, rt2 in its files), each linking to its copy; none: None.
func TestPurgePageListsRetests(t *testing.T) {
	e := setup(t)
	retests(t, e)
	if rec := e.sendFile(t, "alice", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, color.Black)); rec.Code != 200 {
		t.Fatalf("redact %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", fpath+"/attachments/shot.png/purge", nil, nil).Body.String()
	if !strings.Contains(b, `<tr><th>Retests</th><td title="Retest rt1, Retest rt2"><a href="/e/rt1/f/001#attachments">Retest rt1</a>, <a href="/e/rt2/f/001#attachments">Retest rt2</a></td></tr>`) {
		t.Fatalf("no retests row:\n%s", b)
	}
	// a copy deleted since: its history still holds the original; the
	// link goes to the retest
	repo := filepath.Join(e.dir, "engagements", "rt1")
	for _, args := range [][]string{{"rm", "-rq", "findings/" + fdir}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "delete"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	e.srv.Store.Invalidate("rt1")
	if b := e.do(t, "dora", "GET", fpath+"/attachments/shot.png/purge", nil, nil).Body.String(); !strings.Contains(b, `<a href="/e/rt1">Retest rt1</a>, <a href="/e/rt2/f/001#attachments">Retest rt2</a>`) {
		t.Fatalf("no link to the retest whose copy is gone:\n%s", b)
	}
	e2 := setup(t)
	redacted(t, e2)
	if b := e2.do(t, "dora", "GET", fpath+"/attachments/shot.png/purge", nil, nil).Body.String(); !strings.Contains(b, `<tr><th>Retests</th><td><span class="muted">None</span></td></tr>`) {
		t.Fatalf("no empty retests row:\n%s", b)
	}
}

// A retest the redactor cannot see is never named, also when its copy
// cannot be read: it is counted as one they have no access to.
func TestRedactHidesUnreadableRetest(t *testing.T) {
	e := setup(t)
	retests(t, e)
	if err := e.srv.Store.RemoveMember("rt1", "alice", wDora); err != nil {
		t.Fatal(err)
	}
	g := filepath.Join(e.dir, "engagements", "rt1", ".git")
	if err := os.Rename(g, g+"-off"); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(g+"-off", g)
	rec := e.sendFile(t, "alice", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, color.Black))
	got, _ := url.PathUnescape(rec.Header().Get("X-Yars-Unredacted"))
	if rec.Code != 200 || got != "not redacted in Retest rt2 (archived), 1 retest (no access)" {
		t.Fatalf("redact %d, left %q", rec.Code, got)
	}
}

// A retest whose repository cannot be read (being made, or broken) does
// not take the purge page down: it is listed as not read, linking to the
// retest, and a refused purge still says why (409).
func TestPurgePageUnreadableRetest(t *testing.T) {
	e := setup(t)
	retests(t, e)
	if rec := e.sendFile(t, "alice", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, color.Black)); rec.Code != 200 {
		t.Fatalf("redact %d", rec.Code)
	}
	g := filepath.Join(e.dir, "engagements", "rt1", ".git")
	if err := os.Rename(g, g+"-off"); err != nil {
		t.Fatal(err)
	}
	defer os.Rename(g+"-off", g)
	rec := e.do(t, "dora", "GET", fpath+"/attachments/shot.png/purge", nil, nil)
	if b := rec.Body.String(); rec.Code != 200 || !strings.Contains(b, `<a href="/e/rt2/f/001#attachments">Retest rt2</a>, <a href="/e/rt1">Retest rt1 (could not be read)</a>`) {
		t.Fatalf("purge page %d:\n%s", rec.Code, b)
	}
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "copy.png", testPNG(t, color.White)); rec.Code != 200 {
		t.Fatalf("upload %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", fpath+"/attachments/shot.png/purge", url.Values{}, nil); rec.Code != http.StatusConflict {
		t.Fatalf("purge with a copy elsewhere %d:\n%s", rec.Code, rec.Body.String())
	}
}

// D28: below director, neither the page nor the purge.
func TestPurgeForbiddenBelowDirector(t *testing.T) {
	e := setup(t)
	redacted(t, e)
	if rec := e.do(t, "bob", "GET", fpath+"/attachments/shot.png/purge", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("GET %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", fpath+"/attachments/shot.png/purge", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("POST %d", rec.Code)
	}
	if p := attachmentsPanel(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String()); !strings.Contains(p, "histdot") {
		t.Fatalf("a refused purge took the mark:\n%s", p)
	}
}
