package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/notify"
	"yars/internal/store"
	"yars/internal/workflow"
)

// bell returns the header's notification count as shown ("0" black, other
// numbers orange).
func bell(t *testing.T, e *env, user string) string {
	t.Helper()
	b := e.do(t, user, "GET", "/inbox", nil, nil).Body.String()
	m := regexp.MustCompile(`<a class="bell[^"]*" href="/notifications"[^>]*>.*?<span class="(badge|badge0)">(\d+)</span>`).FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("no bell in header")
	}
	if (m[2] == "0") != (m[1] == "badge0") {
		t.Fatalf("count %s shown as %s", m[2], m[1])
	}
	return m[2]
}

func returnToAlice(t *testing.T, e *env) {
	t.Helper()
	st := e.srv.Store
	alice, bob := config.User{Username: "alice", Role: "pentester"}, config.User{Username: "bob", Role: "reviewer"}
	if err := st.SetReviewers("acme", "F-001-sql-injection", []string{"bob"}, alice); err != nil {
		t.Fatal(err)
	}
	st.UpdateSeverity("acme", "F-001-sql-injection", "high", "", e.authorOf(alice))
	if err := st.Transition("acme", "F-001-sql-injection", workflow.Submit, "", alice); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", "F-001-sql-injection", workflow.Return, "add a PoC", bob); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationsFlow(t *testing.T) {
	e := setup(t)
	if got := bell(t, e, "alice"); got != "0" {
		t.Fatalf("bell before %s", got)
	}
	returnToAlice(t, e)
	// bob was asked to review once: assigned on the draft, asked on submit
	if got := bell(t, e, "bob"); got != "1" {
		t.Fatalf("bob's bell %s", got)
	}
	// a mention through the web chat
	rec := e.do(t, "bob", "POST", "/e/acme/f/001/chat", url.Values{"text": {"@alice which roles? @carol"}}, map[string]string{"HX-Request": "true"})
	if rec.Code >= 300 {
		t.Fatalf("chat %d %s", rec.Code, rec.Body)
	}
	if got := bell(t, e, "alice"); got != "2" {
		t.Fatalf("alice's bell %s", got)
	}
	if got := bell(t, e, "carol"); got != "1" {
		t.Fatalf("carol's bell %s", got)
	}
	b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String()
	for _, want := range []string{"Returned to me", "Mentioned", "add a PoC", "@alice which roles?", "F-001", "<thead>", `class="bell on"`} {
		if !strings.Contains(b, want) {
			t.Errorf("notifications page lacks %q", want)
		}
	}
	if strings.Contains(b, ` style="`) || strings.Count(b, "<table") != strings.Count(b, "<thead>") {
		t.Fatal("inline style or a table without headers")
	}
	if strings.Count(b, `class="unread"`) != 2 {
		t.Fatal("unread rows not marked")
	}
	// opening one is a POST (a button, not a link): it marks it read and
	// goes to the finding
	id := regexp.MustCompile(`<form method="post" action="/notifications/(\d+)"><button class="noteopen"`).FindStringSubmatch(b)
	if id == nil || strings.Contains(b, `href="/notifications/`) {
		t.Fatal("no open button")
	}
	// a GET (a prefetch, a crawler, a pasted link) goes there but changes nothing
	rec = e.do(t, "alice", "GET", "/notifications/"+id[1], nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" {
		t.Fatalf("get %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if got := bell(t, e, "alice"); got != "2" {
		t.Fatalf("GET marked read: %s", got)
	}
	rec = e.do(t, "alice", "POST", "/notifications/"+id[1], url.Values{}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" {
		t.Fatalf("open %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if got := bell(t, e, "alice"); got != "1" {
		t.Fatalf("after open %s", got)
	}
	// someone else's notification is not found
	for _, m := range []string{"GET", "POST"} {
		if rec := e.do(t, "bob", m, "/notifications/"+id[1], url.Values{}, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("other's %s %d", m, rec.Code)
		}
	}
	if rec := e.do(t, "alice", "POST", "/notifications/read", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("read all %d", rec.Code)
	}
	if got := bell(t, e, "alice"); got != "0" {
		t.Fatalf("after read all %s", got)
	}
}

// Notifications from engagements the user was taken off are not listed.
func TestNotificationsHideUnseenEngagements(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	// F-099 is not listed, so its stored title shows (F-001 would show its current one)
	d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-099", Title: "visible one", Actor: "bob"})
	d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "hidden", Fid: "F-007", Title: "secret title", Actor: "bob"})
	b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String()
	if !strings.Contains(b, "visible one") || strings.Contains(b, "secret title") {
		t.Fatal("listed a notification of an engagement alice cannot see")
	}
	// the bell doesn't count it either
	if got := bell(t, e, "alice"); got != "1" {
		t.Fatalf("bell %s", got)
	}
	// many newer hidden ones don't push the visible one off the page
	for range 210 {
		d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "hidden", Fid: "F-007", Title: "secret title", Actor: "bob"})
	}
	if b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(); !strings.Contains(b, "visible one") {
		t.Fatal("visible notification cut by hidden ones")
	}
}

// Taking alice off the team removes her notifications of that engagement:
// gone from the bell and the page, and not back when she rejoins.
func TestNotificationsGoneAfterTeamRemoval(t *testing.T) {
	e := setup(t)
	returnToAlice(t, e)
	if got := bell(t, e, "alice"); got != "1" {
		t.Fatalf("bell before %s", got)
	}
	st := e.srv.Store
	dora := config.User{Username: "dora", Role: "director"}
	if err := st.RemoveMember("acme", "alice", dora); err != nil {
		t.Fatal(err)
	}
	if err := st.AddMembers("acme", []string{"alice"}, dora); err != nil {
		t.Fatal(err)
	}
	if got := bell(t, e, "alice"); got != "0" {
		t.Fatalf("bell after removal %s", got)
	}
	if b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(); strings.Contains(b, "Returned to me") {
		t.Fatal("listed after removal")
	}
}

// The notification choices: the default (in app) shows ticked, the email
// column only when the server can send mail, and a saved choice is honoured.
func TestNotificationSettingsChannels(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String()
	if !strings.Contains(b, `value="returned.app" checked`) || !strings.Contains(b, `value="check.app" checked`) {
		t.Fatal("default not shown")
	}
	if strings.Contains(b, ".email") || strings.Contains(b, ">Email</th>") {
		t.Fatal("email column without SMTP")
	}
	// email hidden: saving keeps an earlier email choice
	e.srv.Store.DB().SetNotify("alice", "approved", "email", true)
	e.do(t, "alice", "POST", "/settings/notifications", url.Values{"n": {"mentioned.app"}}, nil)
	if !e.srv.Store.DB().Wants("alice", "approved", "email") || e.srv.Store.DB().Wants("alice", "returned", "app") {
		t.Fatal("saved choice")
	}
	returnToAlice(t, e)
	if got := bell(t, e, "alice"); got != "0" {
		t.Fatalf("notified against the choice: %s", got)
	}
	// with SMTP configured the column is there
	c := e.srv.conf()
	c.SMTP = config.SMTPConfig{Host: "mail.example", Port: 25, From: "yars@example.com"}
	e.srv.setConfig(c)
	if b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `value="returned.email"`) {
		t.Fatal("email column missing with SMTP")
	}
}

// Saving the notification choices is all or nothing: a failure part way
// leaves the earlier choices as they were.
func TestNotificationSettingsSaveAtomic(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	first, last := notify.Events[0].Key, notify.Events[len(notify.Events)-1].Key
	e.do(t, "alice", "POST", "/settings/notifications", url.Values{"n": {first + ".app"}}, nil)
	if !d.Wants("alice", first, "app") || d.Wants("alice", last, "app") {
		t.Fatal("first save")
	}
	if _, err := d.Exec("CREATE TRIGGER boom BEFORE INSERT ON notify_prefs WHEN NEW.event = '" + last + "' BEGIN SELECT RAISE(ABORT, 'disk full'); END"); err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, ev := range notify.Events[1:] {
		all = append(all, ev.Key+".app")
	}
	if rec := e.do(t, "alice", "POST", "/settings/notifications", url.Values{"n": all}, nil); rec.Code == http.StatusSeeOther {
		t.Fatal("failed save reported as saved")
	}
	if !d.Wants("alice", first, "app") {
		t.Fatal("earlier choice lost")
	}
	for _, ev := range notify.Events[1:] {
		if d.Wants("alice", ev.Key, "app") {
			t.Fatalf("%s half saved", ev.Key)
		}
	}
}

// The check-finished notification reaches the finding's author.
func TestNotificationCheckFinished(t *testing.T) {
	e := setup(t)
	ref, _ := e.srv.Store.Finding("acme", "001")
	e.srv.Store.Emit(store.Event{Kind: store.EventCheck, Eng: ref.EngID, Dir: ref.Dir, Fid: ref.F.Meta.ID, Author: ref.F.Meta.Author,
		Actor: "bob", State: "done", Errors: 1})
	if got := bell(t, e, "alice"); got != "1" {
		t.Fatalf("bell %s", got)
	}
	if b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(); !strings.Contains(b, "Check finished") || !strings.Contains(b, "1 error · 0 warnings") {
		t.Fatal("check notification not listed")
	}
}

// Notifications show the finding's title as it is now.
func TestNotificationsCurrentTitle(t *testing.T) {
	e := setup(t)
	returnToAlice(t, e)
	if err := e.srv.Store.UpdateTitle("acme", "F-001-sql-injection", "Blind SQL injection in login", e.authorOf(config.User{Username: "dora", Role: "director"})); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String()
	if !strings.Contains(b, "Blind SQL injection in login") {
		t.Fatalf("notifications keep the old title:\n%s", between(b, "<tbody", "</tbody>"))
	}
	// a withdrawn finding is left off the board but keeps its current title here
	if err := e.srv.Store.Transition("acme", "F-001-sql-injection", workflow.Withdraw, "dup", config.User{Username: "alice", Role: "pentester"}); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(); !strings.Contains(b, "Blind SQL injection in login") {
		t.Fatalf("withdrawn finding shows the old title:\n%s", between(b, "<tbody", "</tbody>"))
	}
}
