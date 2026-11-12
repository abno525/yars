package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"yars/internal/db"
)

// notesSection is the inbox's Notifications section of user's inbox page b.
func notesSection(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `class="q q-notes"`)
	if i < 0 {
		t.Fatalf("no Notifications section:\n%s", b)
	}
	sec := b[i:]
	return sec[:strings.Index(sec, "</section>")]
}

// Inbox section "Notifications": the unread notices of the events no other
// section shows (not Returned to me or Review requested), for everyone,
// counted in the nav badge; Open marks one read and goes where it points.
func TestInboxNotifications(t *testing.T) {
	e := setup(t)
	returnToAlice(t, e) // alice: Returned to me; bob: Review requested
	b := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	sec := notesSection(t, b)
	// the bell is gone: the section leads to every notice and marks them read
	for _, want := range []string{"<h2>Notifications ", `<span class="qcnt zero">0</span>`, "<th", ">Event<", ">By<",
		`<a class="btn secondary sm w104" href="/notifications">History</a>`,
		`<button class="btn secondary sm w152" form="notes" formaction="/notifications/read" disabled>Mark all read</button>`} {
		if !strings.Contains(sec, want) {
			t.Errorf("empty section lacks %q:\n%s", want, sec)
		}
	}
	if strings.Contains(sec, "nev-returned") {
		t.Fatal("Returned to me listed twice")
	}
	if bs := notesSection(t, e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()); strings.Contains(bs, "nev-review") {
		t.Fatal("Review requested listed twice")
	}

	// a mention (an open thread too), then a token about to expire
	e.do(t, "bob", "POST", "/e/acme/f/001/chat", url.Values{"text": {"@alice which **roles**?"}}, map[string]string{"HX-Request": "true"})
	before := regexp.MustCompile(`Inbox <span class="badge">(\d+)</span>`).FindStringSubmatch(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String())
	if before == nil {
		t.Fatal("no inbox badge")
	}
	d := e.srv.Store.DB()
	exp := time.Now().Add(2 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := d.CreateToken("alice", "h-abcd", "abcd", db.TokenSpec{Name: "laptop", Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}, Expires: exp}); err != nil {
		t.Fatal(err)
	}
	e.srv.daily(d)
	b = e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	sec = notesSection(t, b)
	// the title opens the notice too (marking it read), so does Enter on it
	for _, want := range []string{`<span class="qcnt">2</span>`,
		`<span class="tag nev-mentioned">Mentioned</span>`, `<span class="engid">acme</span> · <span class="fid">F-001</span>`,
		"<strong>bob</strong> · @alice which roles?", `<span class="tag nev-token">Token expiring</span>`, "<strong>yars</strong> · MCP · …abcd · expires"} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %q:\n%s", want, sec)
		}
	}
	// the token is about no engagement: a dash, not " · "
	if strings.Contains(sec, `<span class="engid"></span>`) {
		t.Error("an empty engagement shown")
	}
	n, _ := strconv.Atoi(before[1])
	if !strings.Contains(b, `Inbox <span class="badge">`+strconv.Itoa(n+1)+`</span>`) {
		t.Errorf("nav badge leaves the notices out (was %d)", n)
	}
	// Open is a POST through the page's one form (none nested in a queue)
	ids := regexp.MustCompile(`<button class="btn secondary sm w104" form="notes" formaction="/notifications/(\d+)">Open</button>`).FindAllStringSubmatch(sec, -1)
	if len(ids) != 2 || !strings.Contains(b, notesForm) {
		t.Fatalf("open buttons %v", ids)
	}
	if !strings.Contains(sec, `<button class="btn secondary sm w152" form="notes" formaction="/notifications/read">Mark all read</button>`) {
		t.Fatal("Mark all read disabled")
	}
	titles := regexp.MustCompile(`<td class="title"><button class="noteopen" form="notes" formaction="/notifications/(\d+)" title="([^"]+)" data-nav id="row-notes-(\d+)">`).FindAllStringSubmatch(sec, -1)
	if len(titles) != 2 || titles[0][2] != "laptop" {
		t.Fatalf("title buttons %v", titles)
	}
	for i, ti := range titles {
		if ti[1] != ids[i][1] || ti[3] != ids[i][1] {
			t.Fatalf("title %d opens %s (id %s), Open %s", i, ti[1], ti[3], ids[i][1])
		}
	}
	if strings.Contains(sec, `href="/notifications/`) {
		t.Fatal("a GET link to a notice")
	}
	l, _ := d.Notifications("alice", 10)
	var mention string
	for _, x := range l {
		if x.Event == "mentioned" {
			mention = strconv.FormatInt(x.ID, 10)
		}
	}
	rec := e.do(t, "alice", "POST", "/notifications/"+mention, nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" {
		t.Fatalf("open %d %s", rec.Code, rec.Header().Get("Location"))
	}
	sec = notesSection(t, e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String())
	if !strings.Contains(sec, `<span class="qcnt">1</span>`) || strings.Contains(sec, "nev-mentioned") {
		t.Fatalf("read notice still listed:\n%s", sec)
	}
	// Load more asks for the section's rows
	rec = e.do(t, "alice", "GET", "/inbox?list=notes&offset=0", nil, map[string]string{"HX-Request": "true"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "nev-token") {
		t.Fatalf("rows %d:\n%s", rec.Code, rec.Body)
	}
	// Mark all read from the inbox marks what the section lists (not the
	// Returned to me notice, shown elsewhere) and comes back to the inbox
	rec = e.do(t, "alice", "POST", "/notifications/read", url.Values{"back": {"inbox"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/inbox" {
		t.Fatalf("read all %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if sec := notesSection(t, e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()); !strings.Contains(sec, `<span class="qcnt zero">0</span>`) {
		t.Fatalf("after read all:\n%s", sec)
	}
	if got := bell(t, e, "alice"); got != "1" {
		t.Fatalf("unread after the section's read all: %s", got)
	}
	// the notifications page is the inbox's
	if b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(); !strings.Contains(b, `<a class="on" href="/inbox"`) {
		t.Fatal("Inbox not lit on the notifications page")
	}
}

// notesForm is the one form the section's buttons post through (hidden: no
// gap under the last section).
const notesForm = `<form id="notes" method="post" hidden><input type="hidden" name="back" value="inbox"></form>`

// The section lists the newest 50 and counts them all.
func TestInboxNotificationsCapped(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	for range 55 {
		d.AddNotification(db.Notification{User: "alice", Event: "approved", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "dora"})
	}
	sec := notesSection(t, e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String())
	if !strings.Contains(sec, `<span class="qcnt">55</span>`) || strings.Count(sec, `id="row-notes-`) != 50 {
		t.Fatalf("%d rows:\n%s", strings.Count(sec, `id="row-notes-`), sec[:400])
	}
}

// A director's inbox is one bulk form: the notices' Open buttons use the
// form outside it, and a bulk run keeps the section.
func TestInboxNotificationsDirector(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.srv.Store.DB().AddNotification(db.Notification{User: "dora", Event: "mentioned", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "bob", Text: "@dora a look?"})
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	f := b[strings.Index(b, `class="fbulkform"`):]
	f = f[:strings.Index(f, "</form>")]
	if !strings.Contains(f, `form="notes"`) || strings.Contains(f, "<form") {
		t.Fatalf("bulk form:\n%s", f)
	}
	if !strings.Contains(b, notesForm) {
		t.Fatal("no open form")
	}
	rec := e.do(t, "dora", "POST", "/inbox/bulk", url.Values{"action": {"approve"}, "id": {"acme/F-001-sql-injection"}}, map[string]string{"HX-Request": "true"})
	if rec.Code != 200 || !strings.Contains(notesSection(t, rec.Body.String()), "@dora a look?") {
		t.Fatalf("bulk %d:\n%s", rec.Code, rec.Body)
	}
}
