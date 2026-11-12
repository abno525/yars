package web

import (
	"image/color"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// redacted gives the test finding two images, shot.png redacted after its
// upload (marked) and other.png as uploaded (not marked).
func redacted(t *testing.T, e *env) {
	t.Helper()
	for _, n := range []string{"shot.png", "other.png"} {
		if rec := e.sendFile(t, "alice", fpath+"/attachments", n, testPNG(t, color.White)); rec.Code != 200 {
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
		"<h1", "shot.png", "ACME Web", "Existing clones of this engagement must be cloned again",
		`<a class="btn secondary w96" href="/e/acme/f/001#attachments">Cancel</a>`, `<button class="btn danger w112">Purge</button>`} {
		if !strings.Contains(b, want) {
			t.Fatalf("confirm page lacks %s:\n%s", want, b)
		}
	}
	noInline(t, "purge page", b)
	if rec := e.do(t, "dora", "GET", fpath+"/attachments/none.png/purge", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("a file that is not there %d", rec.Code)
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
