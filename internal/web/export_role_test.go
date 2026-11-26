package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// history is the number of export history rows of acme.
func (e *env) history(t *testing.T) int {
	t.Helper()
	h, err := e.srv.Store.DB().Exports("acme", 50)
	if err != nil {
		t.Fatal(err)
	}
	return len(h)
}

// Only a finding's author or a director sends it to a destination: a
// colleague on the team is refused before anything leaves, and nothing is
// marked or recorded.
func TestExportSendAuthorOrDirector(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	f2 := e.secondComplete(t) // F-002 by bob
	e.pen2(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	// the destination takes reported findings too (it updates their issue)
	yml := filepath.Join(e.srv.Export.Dir, "jira.yaml")
	b, err := os.ReadFile(yml)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(yml, append(b, "statuses: [complete, reported]\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	send := func(user string, dirs ...string) int {
		t.Helper()
		return e.do(t, user, "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": dirs}, nil).Code
	}
	refused := func(what string, code int) {
		t.Helper()
		if code != http.StatusForbidden {
			t.Fatalf("%s: %d, want 403", what, code)
		}
		if len(j.writes) != 0 || e.history(t) != 0 {
			t.Fatalf("%s: sent %v, %d history rows", what, j.writes, e.history(t))
		}
		if e.status(t) != "complete" || e.statusOf(t, "acme", f2) != "complete" {
			t.Fatalf("%s: marked", what)
		}
	}
	refused("a colleague sends alice's finding", send("pen2", fdir))
	refused("alice sends bob's finding", send("alice", f2))
	// one finding of another author refuses the whole send
	rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir, f2}}, nil)
	refused("alice sends hers and bob's", rec.Code)
	if !strings.Contains(rec.Body.String(), "F-002: only the author or a director can send a finding") {
		t.Fatalf("message:\n%s", rec.Body.String())
	}
	// the author sends their own
	if code := send("alice", fdir); code != http.StatusSeeOther {
		t.Fatalf("the author's send: %d", code)
	}
	if e.status(t) != "reported" || strings.Join(j.writes, " ") != "POST" {
		t.Fatalf("the author's send: %s %v", e.status(t), j.writes)
	}
	// a reported finding of another author is not sent again either
	if code := send("pen2", fdir); code != http.StatusForbidden || len(j.writes) != 1 {
		t.Fatalf("a colleague sends a reported finding again: %d %v", code, j.writes)
	}
	// a director sends anyone's
	if code := send("dora", f2); code != http.StatusSeeOther || e.statusOf(t, "acme", f2) != "reported" {
		t.Fatalf("the director's send: %d %s", code, e.statusOf(t, "acme", f2))
	}
	// the author sends a reported finding again (the issue is updated)
	if code := send("alice", fdir); code != http.StatusSeeOther || strings.Join(j.writes, " ") != "POST POST PUT PEN-1" {
		t.Fatalf("the author's second send: %d %v", code, j.writes)
	}
}

// A file destination is a destination too: a colleague gets no file of
// another author's finding and marks nothing; the author gets the file.
// Downloads and the preview stay with the team.
func TestExportFileAuthorOrDirector(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.pen2(t)
	e.exporters(t, fakePandoc)
	rec := e.do(t, "pen2", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil)
	if rec.Code != http.StatusForbidden || e.status(t) != "complete" || e.history(t) != 0 {
		t.Fatalf("a colleague's file send: %d %s, %d history rows", rec.Code, e.status(t), e.history(t))
	}
	if rec := e.do(t, "pen2", "POST", "/e/acme/export", url.Values{"download": {"docx"}, "finding": {fdir}}, nil); rec.Code != 200 || e.status(t) != "complete" {
		t.Fatalf("a colleague's download: %d %s", rec.Code, e.status(t))
	}
	if rec := e.do(t, "pen2", "GET", "/e/acme/export/preview?finding="+fdir, nil, nil); rec.Code != 200 {
		t.Fatalf("a colleague's preview: %d", rec.Code)
	}
	page := e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil))
	if !strings.Contains(page, "/e/acme/export/download/") || e.status(t) != "reported" {
		t.Fatalf("the author's file send: %s\n%s", e.status(t), page)
	}
}

// A failed send is sent again by the author or a director only, with the
// author's key or the server's; a colleague's refused try leaves the retry
// to them.
func TestExportResendAuthorOrDirector(t *testing.T) {
	for _, c := range []struct {
		name, route string
		form        url.Values
	}{
		{"retry", "/retry", url.Values{}},
		{"server key", "/server", url.Values{"dir": {fdir}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := setupSerial(t)
			e.toComplete(t)
			e.pen2(t)
			e.exporters(t, fakePandoc)
			j := e.jira(t, true)
			j.fail = true
			e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil))
			h, _ := e.srv.Store.DB().Exports("acme", 1)
			again := "/e/acme/export/history/" + itoa(h[0].ID) + c.route
			j.fail = false
			if rec := e.do(t, "pen2", "POST", again, c.form, nil); rec.Code != http.StatusForbidden {
				t.Fatalf("a colleague's resend: %d", rec.Code)
			}
			if len(j.writes) != 0 || e.status(t) != "complete" || e.history(t) != 1 {
				t.Fatalf("a colleague's resend: sent %v, %s, %d history rows", j.writes, e.status(t), e.history(t))
			}
			h, _ = e.srv.Store.DB().Exports("acme", 1)
			if items := itemsOf(h[0]); len(items) != 1 || !items[0].retryable() {
				t.Fatalf("the refused resend used the retry up: %+v", items)
			}
			page := e.follow(t, "alice", e.do(t, "alice", "POST", again, c.form, nil))
			if !strings.Contains(page, "/browse/PEN-1") || e.status(t) != "reported" {
				t.Fatalf("the author's resend: %s\n%s", e.status(t), page)
			}
		})
	}
}

// The picker ticks by default only what the viewer may send: their own
// complete findings, and every complete one for a director.
func TestExportTicksOwnFindings(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	f2 := e.secondComplete(t)
	e.exporters(t, fakePandoc)
	mine, bobs := `id="pick-`+fdir+`" checked`, `id="pick-`+f2+`" checked`
	b := e.do(t, "alice", "GET", "/e/acme/export", nil, nil).Body.String()
	if !strings.Contains(b, mine) || strings.Contains(b, bobs) || !strings.Contains(b, `id="pick-`+f2+`" aria-label`) || !strings.Contains(b, ">1 of 2</span>") {
		t.Fatalf("alice's picker:\n%s", between(b, `<section class="panel compact pickpanel">`, "</section>"))
	}
	b = e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	if !strings.Contains(b, mine) || !strings.Contains(b, bobs) || !strings.Contains(b, ">2 of 2</span>") {
		t.Fatalf("dora's picker:\n%s", between(b, `<section class="panel compact pickpanel">`, "</section>"))
	}
}
