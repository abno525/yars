package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/notify"
)

var inboxBadgeRe = regexp.MustCompile(`href="/inbox" aria-keyshortcuts="I">Inbox <span class="badge0?">(\d+)</span>`)

// inboxBadge is the Inbox number in the top bar of the page b.
func inboxBadge(t *testing.T, b string) int {
	t.Helper()
	m := inboxBadgeRe.FindStringSubmatch(b)
	if m == nil {
		t.Fatal("no Inbox badge")
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// Opening a finding's page marks the viewer's notices of that finding read,
// before the page counts the Inbox number it shows. Only the full page does:
// not the parts a live event or the poll fetches, not a prefetch, and never
// another finding's notices, a token's notice or another account's.
func TestFindingPageMarksNoticesRead(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	returnToAlice(t, e) // one notice (Returned to me) on F-001
	for _, n := range []db.Notification{
		{User: "alice", Event: notify.Mentioned, Eng: "acme", Dir: fdir, Fid: "F-001", Title: "SQL injection", Actor: "bob"},
		{User: "alice", Event: notify.Mentioned, Eng: "acme", Dir: "F-099-other", Fid: "F-099", Title: "Other", Actor: "bob"},
		{User: "alice", Event: notify.Token, Title: "laptop", Actor: "yars"},
		{User: "bob", Event: notify.Mentioned, Eng: "acme", Dir: fdir, Fid: "F-001", Title: "SQL injection", Actor: "alice"},
	} {
		if _, err := d.AddNotification(n); err != nil {
			t.Fatal(err)
		}
	}
	bobBefore := unread(t, e, "bob")
	if got := unread(t, e, "alice"); got != "4" {
		t.Fatalf("alice's unread before %s", got)
	}
	before := inboxBadge(t, e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String())
	// the parts of the page, and a prefetch of it, mark nothing
	for _, path := range []string{fshort + "/head", fshort + "/workflow", fshort + "/chat", fshort + "/history"} {
		if rec := e.do(t, "alice", "GET", path, nil, map[string]string{"HX-Request": "true"}); rec.Code >= 400 {
			t.Fatalf("%s: %d", path, rec.Code)
		}
	}
	for _, h := range []string{"Sec-Purpose", "Purpose"} {
		if rec := e.do(t, "alice", "GET", fshort, nil, map[string]string{h: "prefetch"}); rec.Code != http.StatusOK {
			t.Fatalf("prefetch %d", rec.Code)
		}
	}
	if got := unread(t, e, "alice"); got != "4" {
		t.Fatalf("a part of the page or a prefetch marked notices read: %s unread", got)
	}
	rec := e.do(t, "alice", "GET", fshort, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	// the page that cleared them already shows the lower number (the
	// Returned notice is not in the inbox's Notifications section, the
	// mention was)
	if got := inboxBadge(t, rec.Body.String()); got != before-1 {
		t.Errorf("the finding page's Inbox number %d, want %d", got, before-1)
	}
	if got := unread(t, e, "alice"); got != "2" {
		t.Fatalf("alice's unread after opening the finding %s, want 2 (another finding's, the token's)", got)
	}
	b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String()
	if n := strings.Count(b, `class="unread"`); n != 2 || !strings.Contains(b, "F-099") {
		t.Errorf("%d unread rows", n)
	}
	if got := unread(t, e, "bob"); got != bobBefore {
		t.Errorf("alice's view changed bob's unread: %s, was %s", got, bobBefore)
	}
}

// A notice about a chat message leads to its thread on the finding page
// (#t-<the thread's first message>), from the notifications page and from
// the inbox; any other notice leads to the top of the page.
func TestNoticeLeadsToItsThread(t *testing.T) {
	e := setup(t)
	st, d := e.srv.Store, e.srv.Store.DB()
	root, err := st.PostChat("acme", fdir, chat.Message{Text: "@carol which roles?"}, wBob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.PostChat("acme", fdir, chat.Message{Text: "admin only", Reply: root.ID}, wAlice); err != nil {
		t.Fatal(err)
	}
	want := fshort + "#t-" + root.ID
	for _, user := range []string{"carol", "bob"} { // a mention in a new thread, a reply
		l, err := d.Notifications(user, 1)
		if err != nil || len(l) != 1 {
			t.Fatalf("%s's notices: %v %v", user, l, err)
		}
		for _, m := range []string{"GET", "POST"} {
			rec := e.do(t, user, m, "/notifications/"+strconv.FormatInt(l[0].ID, 10), nil, nil)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
				t.Errorf("%s %s: %d %s, want %s", user, m, rec.Code, rec.Header().Get("Location"), want)
			}
		}
	}
	if b := e.do(t, "bob", "GET", fshort, nil, nil).Body.String(); !strings.Contains(b, `id="t-`+root.ID+`"`) {
		t.Error("the page has no element of that id")
	}
	// a notice that is not about a message
	returnToAlice(t, e)
	l, _ := d.Notifications("alice", 1)
	if rec := e.do(t, "alice", "GET", "/notifications/"+strconv.FormatInt(l[0].ID, 10), nil, nil); rec.Header().Get("Location") != fshort {
		t.Errorf("a Returned notice leads to %s", rec.Header().Get("Location"))
	}
}

// The notifications page lists 50 rows and a Load more row for the rest
// (before: the newest 200 and no way past them).
func TestNotificationsPaged(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	var ids []int64
	for i := range 60 {
		id, err := d.AddNotification(db.Notification{User: "alice", Event: notify.Mentioned, Eng: "acme", Fid: "F-099", Title: "note " + strconv.Itoa(i), Actor: "bob"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String()
	if n := strings.Count(b, `class="noteopen"`); n != 50 {
		t.Fatalf("%d rows on the first page", n)
	}
	last := strconv.FormatInt(ids[10], 10) // the 50th from the newest
	more := `<tr class="more" id="notes-more"><td colspan="5"><button type="button" class="btn secondary w152" hx-get="/notifications?before=` + last + `" hx-target="#notes-more" hx-swap="outerHTML">Load 50 more</button></td></tr>`
	if !strings.Contains(b, more) {
		t.Fatalf("no Load more row:\n%s", between(b, "<tbody>", "</table>"))
	}
	if got := unread(t, e, "alice"); got != "60" {
		t.Errorf("unread %s", got)
	}
	rec := e.do(t, "alice", "GET", "/notifications?before="+last, nil, map[string]string{"HX-Request": "true"})
	rest := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(rest, "<html") || strings.Contains(rest, "<tbody") {
		t.Fatalf("the next page is no row fragment: %d\n%s", rec.Code, rest)
	}
	if n := strings.Count(rest, `class="noteopen"`); n != 10 || strings.Contains(rest, "notes-more") || strings.Contains(rest, "emptyrow") {
		t.Fatalf("%d rows on the second page:\n%s", n, rest)
	}
	if !strings.Contains(rest, "note 0<") || strings.Contains(rest, "note 10<") {
		t.Error("the second page does not go on after the first")
	}
	// a page past the end is no rows and no dash; a bad number is the first page
	if rec := e.do(t, "alice", "GET", "/notifications?before=1", nil, map[string]string{"HX-Request": "true"}); strings.Contains(rec.Body.String(), "<tr") {
		t.Errorf("past the end:\n%s", rec.Body.String())
	}
	if b := e.do(t, "alice", "GET", "/notifications?before=x", nil, nil).Body.String(); strings.Count(b, `class="noteopen"`) != 50 {
		t.Error("a bad before is not the first page")
	}
}
