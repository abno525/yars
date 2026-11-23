package web

import (
	"image/color"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/gitrepo"
)

// listState is how the findings list shows finding 001: its row tag, the
// two segment counts and whether the signed off filter lists it.
func (e *env) listState(t *testing.T) (tag, counts string, inSignedOff bool) {
	t.Helper()
	b := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	switch {
	case strings.Contains(b, `class="tag status-signed-off">signed off<`):
		tag = "signed off"
	case strings.Contains(b, `class="tag status-verification">verification<`):
		tag = "verification"
	}
	for _, c := range []string{`>Verification · 1</a>`, `>Signed off · 1</a>`} {
		if strings.Contains(b, c) {
			counts += c
		}
	}
	f := e.do(t, "dora", "GET", "/e/acme?status=signed-off", nil, nil).Body.String()
	return tag, counts, strings.Contains(f, `href="/e/acme/f/001"`)
}

func (e *env) wantVerification(t *testing.T, after string) {
	t.Helper()
	if tag, counts, in := e.listState(t); tag != "verification" || counts != `>Verification · 1</a>` || in {
		t.Fatalf("after %s: tag %q counts %q in signed off filter %v", after, tag, counts, in)
	}
}

func (e *env) wantSignedOff(t *testing.T) {
	t.Helper()
	if tag, counts, in := e.listState(t); tag != "signed off" || counts != `>Signed off · 1</a>` || !in {
		t.Fatalf("not signed off: tag %q counts %q in filter %v", tag, counts, in)
	}
}

// A sign-off that no longer counts takes the finding back to verification
// on the list: an edit through YARS, an edit pushed to git, a new reviewer.
func TestSignedOffVoided(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	clear := func() {
		t.Helper()
		e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
		e.wantSignedOff(t)
	}

	clear()
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "changed after review", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	e.wantVerification(t, "an edit")

	clear()
	p := filepath.Join(e.dir, "engagements", "acme", "findings", fdir, "finding.md")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, []byte("\npushed text\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	er, err := e.srv.Store.EngRepo("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := er.Commit([]string{"findings/" + fdir + "/finding.md"}, "push", gitrepo.Author{Name: "alice", Email: "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.Invalidate("acme") // what the git server does after a push
	e.wantVerification(t, "a pushed edit")

	clear()
	if err := e.srv.Store.SetReviewers("acme", fdir, []string{"bob", "carol"}, wAlice); err != nil {
		t.Fatal(err)
	}
	e.wantVerification(t, "a second reviewer")
}

// A sign-off covers the attachments too: an upload or a redaction on the
// finding page takes a signed-off finding back to verification on the list.
func TestSignedOffVoidedByAttachments(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	clear := func() {
		t.Helper()
		e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
		e.wantSignedOff(t)
	}
	clear()
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "shot.png", testPNG(t, color.White)); rec.Code != 200 {
		t.Fatalf("upload %d:\n%s", rec.Code, rec.Body.String())
	}
	e.wantVerification(t, "an upload")
	clear()
	if rec := e.sendFile(t, "bob", fpath+"/attachments/shot.png/redact", "blob", testPNG(t, color.Black)); rec.Code != 200 {
		t.Fatalf("redact %d:\n%s", rec.Code, rec.Body.String())
	}
	e.wantVerification(t, "a redaction")
}

// A director who signs off unassigned joins the reviewers: the finding stays
// in verification until the assigned reviewer signs off too.
func TestSignedOffDirectorUnassigned(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.do(t, "dora", "POST", fpath+"/action/clear", url.Values{}, nil)
	e.wantVerification(t, "the director's sign-off")
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	e.wantSignedOff(t)
}
