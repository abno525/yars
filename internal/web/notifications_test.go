package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/config"
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
	// bob was asked to review (assigned, then submitted)
	if got := bell(t, e, "bob"); got != "2" {
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
	// opening one marks it read and goes to the finding
	id := regexp.MustCompile(`href="/notifications/(\d+)"`).FindStringSubmatch(b)
	if id == nil {
		t.Fatal("no link")
	}
	rec = e.do(t, "alice", "GET", "/notifications/"+id[1], nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" {
		t.Fatalf("open %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if got := bell(t, e, "alice"); got != "1" {
		t.Fatalf("after open %s", got)
	}
	// someone else's notification is not found
	if rec := e.do(t, "bob", "GET", "/notifications/"+id[1], nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("other's %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/notifications/read", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("read all %d", rec.Code)
	}
	if got := bell(t, e, "alice"); got != "0" {
		t.Fatalf("after read all %s", got)
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
