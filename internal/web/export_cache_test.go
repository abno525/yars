package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/export"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

// fakeClock is a time the test moves.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func fileOf(n int) export.Result {
	return export.Result{Filename: "f.bin", Data: make([]byte, n)}
}

// A user's cached files are capped in bytes: a put over the cap drops that
// user's oldest files, never the new one and never another user's.
func TestExportCacheCapPerUser(t *testing.T) {
	c := &exportCache{max: 100}
	a1 := c.put("alice", "acme", fileOf(40))
	a2 := c.put("alice", "acme", fileOf(40))
	b1 := c.put("bob", "acme", fileOf(90))
	has := func(user, tok string) bool {
		_, ok := c.get(user, "acme", tok)
		return ok
	}
	if !has("alice", a1) || !has("alice", a2) || !has("bob", b1) {
		t.Fatal("files under the cap were dropped")
	}
	a3 := c.put("alice", "acme", fileOf(40)) // 120 > 100: her oldest goes
	if has("alice", a1) || !has("alice", a2) || !has("alice", a3) {
		t.Fatalf("after going over the cap: a1 %v a2 %v a3 %v", has("alice", a1), has("alice", a2), has("alice", a3))
	}
	if !has("bob", b1) {
		t.Fatal("another user's file was dropped")
	}
	// one file larger than the whole cap is still kept (the send has
	// happened), alone
	a4 := c.put("alice", "acme", fileOf(500))
	if !has("alice", a4) || has("alice", a2) || has("alice", a3) || !has("bob", b1) {
		t.Fatal("a file over the cap: it must stay alone for its user")
	}
	if n := c.bytes("alice"); n != 500 {
		t.Fatalf("alice holds %d bytes", n)
	}
	// the default cap is not unlimited
	if exportUserMax <= 0 || exportUserMax > 1<<30 {
		t.Fatalf("exportUserMax %d", exportUserMax)
	}
}

// An expired file is gone when the sweep runs, with no further put; before
// that it is refused by get already.
func TestExportCacheSweep(t *testing.T) {
	ck := &fakeClock{t: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	c := &exportCache{now: ck.now}
	tok := c.put("alice", "acme", fileOf(10))
	c.put("alice", "acme", fileOf(10))
	ck.t = ck.t.Add(exportKeep - time.Second)
	c.sweep()
	if _, ok := c.get("alice", "acme", tok); !ok || c.len() != 2 {
		t.Fatalf("swept before its time: %d left", c.len())
	}
	ck.t = ck.t.Add(2 * time.Second)
	if _, ok := c.get("alice", "acme", tok); ok {
		t.Fatal("an expired file was served")
	}
	if c.len() != 2 {
		t.Fatalf("%d entries before the sweep", c.len())
	}
	c.sweep()
	if c.len() != 0 || c.bytes("alice") != 0 {
		t.Fatalf("after the sweep: %d entries, %d bytes", c.len(), c.bytes("alice"))
	}
}

// The file is the engagement's it was made in: the same token under another
// engagement the user can see is 404, and so is another user's try.
func TestExportCacheEngagement(t *testing.T) {
	c := &exportCache{}
	tok := c.put("alice", "acme", fileOf(10))
	for name, try := range map[string][2]string{"another engagement": {"alice", "beta"}, "another user": {"bob", "acme"}, "no engagement": {"alice", ""}} {
		if _, ok := c.get(try[0], try[1], tok); ok {
			t.Errorf("%s got the file", name)
		}
	}
	if _, ok := c.get("alice", "acme", "nope"); ok {
		t.Error("an unknown token got a file")
	}
	if _, ok := c.get("alice", "acme", tok); !ok {
		t.Error("the sender did not get the file")
	}
}

// Over HTTP: the sender downloads the file under its engagement; a colleague
// with the same address gets 404, and so does the sender under another
// engagement, whose result panel offers no download either.
func TestExportDownloadTiedToEngagement(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	if err := e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, gitrepo.Author{Name: "dora", Email: "d@x"}); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.DB().AddMembers("beta", "alice"); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("send %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tok, sent := loc.Query().Get("dl"), loc.Query().Get("sent")
	if tok == "" || sent == "" {
		t.Fatalf("redirect %s", loc)
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/export/download/"+tok, nil, nil); rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), "acme.docx") {
		t.Fatalf("the sender's download: %d", rec.Code)
	}
	if page := e.do(t, "alice", "GET", "/e/acme/export?sent="+sent+"&dl="+tok, nil, nil).Body.String(); !strings.Contains(page, "/e/acme/export/download/"+tok) {
		t.Fatal("the sender's result panel offers no download")
	}
	if rec := e.do(t, "bob", "GET", "/e/acme/export/download/"+tok, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("a colleague's download: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", "/e/beta/export/download/"+tok, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("the sender through another engagement: %d", rec.Code)
	}
	if page := e.do(t, "alice", "GET", "/e/beta/export?sent="+sent+"&dl="+tok, nil, nil).Body.String(); strings.Contains(page, "/export/download/") {
		t.Fatal("another engagement's page offers the download")
	}
	// the sweep worker runs and ends with the server
	e.srv.Close()
}
