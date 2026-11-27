package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// Without base_url a mail's link would be a bare path: no mail is sent then,
// whatever was chosen before, and the settings show no Email column. With
// base_url both are back.
func TestNoMailWithoutBaseURL(t *testing.T) {
	e := setup(t)
	set := func(base string) {
		t.Helper()
		c := e.srv.conf()
		c.SMTP = config.SMTPConfig{Host: "mail.acme.example", Port: 25, From: "yars@acme.example"}
		c.BaseURL = base
		e.srv.Store.SetConfig(c)
		if got := e.srv.conf(); got.BaseURL != base || !got.SMTP.Configured() {
			t.Fatalf("the server's config did not follow: %+v", got)
		}
	}
	// alice chose mail while it could be sent
	if err := e.srv.Store.DB().SetNotify("alice", "returned", "email", true); err != nil {
		t.Fatal(err)
	}
	set("")
	if m := e.srv.Notifier.MailFor(); m != nil {
		t.Fatalf("a mailer without base_url: %+v", m)
	}
	tbl := between(e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(), `<table class="table stable notifytable">`, "</table>")
	if strings.Contains(tbl, "Email") || strings.Contains(tbl, `.email"`) {
		t.Fatalf("the Email column shows without base_url:\n%s", tbl)
	}
	// a Save of the page keeps the hidden choice
	e.do(t, "alice", "POST", "/settings/notifications", url.Values{"n": {"approved.app"}}, nil)
	if !e.srv.Store.DB().Wants("alice", "returned", "email") {
		t.Fatal("the hidden email choice was lost")
	}

	set("https://yars.acme.example")
	if m := e.srv.Notifier.MailFor(); m == nil {
		t.Fatal("no mailer with SMTP and base_url set")
	}
	tbl = between(e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(), `<table class="table stable notifytable">`, "</table>")
	if !strings.Contains(tbl, "Email") || !strings.Contains(tbl, `value="returned.email" checked`) {
		t.Fatalf("the Email column is not back with base_url:\n%s", tbl)
	}
}

// The writer of @name is told who gets no notice: an unknown name, a
// disabled account and one off the team read the same. The message is
// posted all the same.
func TestChatSaysWhoIsNotNotified(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	for _, u := range []config.User{{Username: "out", Role: "pentester"}, {Username: "gone", Role: "pentester"}} {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.SetDisabled("gone", true); err != nil {
		t.Fatal(err)
	}
	if err := d.AddMembers("acme", "gone"); err != nil {
		t.Fatal(err)
	}
	hx := map[string]string{"HX-Request": "true"}
	rec := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"@alice @out @gone @nobody @bob which roles?"}}, hx)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `<p class="error">Not notified: @out @gone @nobody</p>`) {
		t.Fatalf("new thread %d:\n%s", rec.Code, b)
	}
	if !strings.Contains(b, "which roles?") {
		t.Fatal("the message is not posted")
	}
	// the page's rule is the notifier's: who is named got nothing, alice did
	for user, want := range map[string]int{"alice": 1, "out": 0, "gone": 0} {
		if l, _ := d.Notifications(user, 10); len(l) != want {
			t.Errorf("%s has %d notices, want %d", user, len(l), want)
		}
	}
	// a reply says it on the list
	msgs, _ := d.Messages("acme", "F-001")
	rec = e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"ask @out"}, "reply": {msgs[0].ID}}, hx)
	if b := rec.Body.String(); rec.Code != 200 || !strings.Contains(b, `<p class="error">Not notified: @out</p>`) || !strings.Contains(b, `id="chat-list"`) {
		t.Fatalf("reply %d:\n%s", rec.Code, b)
	}
	// everyone hears: no line
	rec = e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"@alice thanks"}}, hx)
	if b := rec.Body.String(); rec.Code != 200 || strings.Contains(b, "Not notified") {
		t.Fatalf("a line although everyone is told:\n%s", b)
	}
	// many names: the line is capped
	rec = e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"@n1 @n2 @n3 @n4 @n5 @n6 @n7"}}, hx)
	if b := rec.Body.String(); !strings.Contains(b, `<p class="error">Not notified: @n1 @n2 @n3 @n4 @n5 and 2 more</p>`) {
		t.Fatalf("capped line:\n%s", b)
	}
	// the team board says it on the lead's line
	rec = e.do(t, "bob", "POST", "/e/acme/board", url.Values{"title": {"Odd header"}, "state": {"open"}, "text": {"@alice @out look"}}, hx)
	if b := rec.Body.String(); rec.Code != 200 || !strings.Contains(b, "Not notified: @out") || strings.Contains(b, "Not notified: @alice") {
		t.Fatalf("new lead %d:\n%s", rec.Code, b)
	}
	rec = e.do(t, "bob", "POST", "/e/acme/board/n/L-001/post", url.Values{"text": {"cc @nobody"}}, hx)
	if b := rec.Body.String(); rec.Code != 200 || !strings.Contains(b, "Not notified: @nobody") {
		t.Fatalf("board message %d:\n%s", rec.Code, b)
	}
}
