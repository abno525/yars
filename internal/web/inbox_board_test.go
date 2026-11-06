package web

import (
	"net/url"
	"strings"
	"testing"
)

// Inbox queue "New on team board": notes with an entry by someone else the
// user has not seen, for everyone, counted in the nav badge.
func TestInboxNewOnTeamBoard(t *testing.T) {
	e := setup(t)
	e.outsider(t)
	e.lead(t, "alice", "JWT <alg> none", "api.acme.test", "open")
	b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	sec := b[strings.Index(b, `class="q q-board"`):]
	sec = sec[:strings.Index(sec, "</section>")]
	for _, want := range []string{"New on team board", `<span class="qcnt">1</span>`, "<th", "JWT &lt;alg&gt; none",
		`<span class="tag lead-open">Open</span>`, `<span class="engid">acme</span> · <span class="fid">L-001</span>`, "<strong>alice</strong> · First look at JWT", `href="/e/acme/board?n=L-001"`} {
		if !strings.Contains(sec, want) {
			t.Errorf("queue lacks %q:\n%s", want, sec)
		}
	}
	if !strings.Contains(b, `Inbox <span class="badge">1</span>`) {
		t.Fatal("nav badge leaves the board out")
	}
	// alice wrote it: nothing new to her
	if b := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(); !strings.Contains(b, `q-board`) || strings.Contains(b, `<span class="fid">L-001</span>`) {
		t.Fatal("own note in alice's queue")
	}
	// another team's board stays out
	if b := e.do(t, "eve", "GET", "/inbox", nil, nil).Body.String(); strings.Contains(b, "L-001") {
		t.Fatal("outsider sees the note")
	}
	// opened: gone; a reply brings it back with the reply
	e.do(t, "bob", "GET", "/e/acme/board?n=L-001", nil, nil)
	if b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(); strings.Contains(b, `<span class="fid">L-001</span>`) {
		t.Fatal("seen note still listed")
	}
	e.do(t, "carol", "POST", "/e/acme/board/n/L-001/post", url.Values{"text": {"Cached by the CDN?"}}, nil)
	if b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(); !strings.Contains(b, "Cached by the CDN?") || !strings.Contains(b, "<strong>carol</strong>") {
		t.Fatal("reply not listed")
	}
}

// A director's bulk action from the inbox answers with the lists: the
// board queue stays as it was.
func TestInboxBulkKeepsBoardQueue(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.lead(t, "alice", "Open redirect", "", "open")
	e.do(t, "dora", "GET", "/e/acme/board?n=L-001", nil, nil) // dora follows it
	e.do(t, "alice", "POST", "/e/acme/board/n/L-001/post", url.Values{"text": {"after dora"}}, nil)
	rec := e.do(t, "dora", "POST", "/inbox/bulk", url.Values{"action": {"approve"}, "id": {"acme/F-001-sql-injection"}}, map[string]string{"HX-Request": "true"})
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `class="q q-board"`) || !strings.Contains(b, `<span class="fid">L-001</span>`) {
		t.Fatalf("bulk %d:\n%s", rec.Code, b)
	}
}
