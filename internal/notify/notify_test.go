package notify

import (
	"mime"
	netmail "net/mail"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/store"
)

type mail struct{ to, subject, body string }

type fakeMailer struct {
	mu   sync.Mutex
	sent []mail
}

func (f *fakeMailer) Send(to, subject, body string) error {
	f.mu.Lock()
	f.sent = append(f.sent, mail{to, subject, body})
	f.mu.Unlock()
	return nil
}

var users = []config.User{
	{Username: "pen1", Role: "pentester", Email: "pen1@acme.example"},
	{Username: "rev1", Role: "reviewer", Email: "rev1@acme.example"},
	{Username: "rev2", Role: "reviewer"},
	// out is not on the team; gone is disabled
	{Username: "out", Role: "reviewer"},
	{Username: "gone", Role: "reviewer", Disabled: true},
	{Username: "dir1", Role: "director"},
}

func newNotifier(t *testing.T) (*Notifier, *db.DB, *fakeMailer) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "y.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	for _, u := range users {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	m := &fakeMailer{}
	n := &Notifier{DB: d, Users: func() []config.User { return users }, Mail: m,
		CanSee:  func(u config.User, eng string) bool { return u.Username != "out" },
		BaseURL: func() string { return "https://yars.example.com" }}
	return n, d, m
}

func list(t *testing.T, d *db.DB, user string) string {
	t.Helper()
	l, err := d.Notifications(user, 50)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(l) - 1; i >= 0; i-- { // oldest first
		out = append(out, l[i].Event+":"+l[i].Actor+":"+l[i].Text)
	}
	return strings.Join(out, ",")
}

func ev(kind string) store.Event {
	return store.Event{Kind: kind, Eng: "demo", Dir: "F-005-sqli", Fid: "F-005", Title: "SQL injection", Author: "pen1", Reviewers: []string{"rev1"}}
}

func TestWhoIsNotified(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventReviewers)
	e.Actor, e.Added = "pen1", []string{"rev1", "out", "gone"}
	n.Handle(e)
	e = ev(store.EventStatus)
	e.Actor, e.Action, e.Reason = "rev1", "return", "add a PoC"
	n.Handle(e)
	e.Actor, e.Action, e.Reason = "dir1", "approve", ""
	n.Handle(e)
	e.Actor, e.Action = "pen1", "submit" // the reviewers are asked again
	n.Handle(e)
	e = ev(store.EventChat)
	e.Actor, e.Text = "rev1", "@pen1 which roles? cc @rev2 @out @rev1 @nobody"
	n.Handle(e)
	e = ev(store.EventChat)
	e.Actor, e.Text, e.Reply, e.ReplyTo = "pen1", "admins only", "m-1", "rev1"
	n.Handle(e)
	e = ev(store.EventCheck)
	e.Actor, e.State, e.Errors, e.Warnings = "rev1", "done", 2, 1
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "returned:rev1:add a PoC,approved:dir1:,mentioned:rev1:@pen1 which roles? cc @rev2 @out @rev1 @nobody,check:rev1:2 errors · 1 warning" {
		t.Fatalf("pen1: %s", got)
	}
	if got := list(t, d, "rev1"); got != "review:pen1:,review:pen1:,reply:pen1:admins only" {
		t.Fatalf("rev1: %s", got)
	}
	if got := list(t, d, "rev2"); got != "mentioned:rev1:@pen1 which roles? cc @rev2 @out @rev1 @nobody" {
		t.Fatalf("rev2: %s", got)
	}
	for _, u := range []string{"out", "gone", "dir1"} {
		if got := list(t, d, u); got != "" {
			t.Errorf("%s: %s", u, got)
		}
	}
}

func TestPrefsAndEmail(t *testing.T) {
	n, d, m := newNotifier(t)
	// pen1: returned by email only; rev1 keeps the default (in app)
	d.SetNotify("pen1", "returned", "email", true)
	e := ev(store.EventStatus)
	e.Actor, e.Action, e.Reason = "rev1", "return", "add a PoC"
	n.Handle(e)
	e.Action = "approve"
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "" {
		t.Fatalf("in app despite the choice: %s", got)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) != 1 {
		t.Fatalf("mails %+v", m.sent)
	}
	ml := m.sent[0]
	if ml.to != "pen1@acme.example" || !strings.Contains(ml.subject, "Returned to me") || !strings.Contains(ml.subject, "F-005") ||
		!strings.Contains(ml.body, "add a PoC") || !strings.Contains(ml.body, "https://yars.example.com/e/demo/f/005") {
		t.Fatalf("%+v", ml)
	}
	// without a mailer no email goes out
	n.Mail = nil
	e.Action = "return"
	n.Handle(e)
	n.Wait()
	if len(m.sent) != 1 {
		t.Fatal("mailed without a mailer")
	}
}

func TestMailMessage(t *testing.T) {
	msg := string(message("yars@acme.example", "pen1@acme.example", "[YARS] Returned to me: F-005", "line\nnext"))
	for _, want := range []string{"From: yars@acme.example\r\n", "To: pen1@acme.example\r\n", "Subject: [YARS] Returned to me: F-005\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n", "\r\n\r\nline\r\nnext"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %q", want, msg)
		}
	}
	// header injection is cut off
	if strings.Contains(string(message("a@b", "c@d", "x\r\nBcc: evil@x", "b")), "\r\nBcc:") {
		t.Fatal("header injection")
	}
}

// A subject with non-ASCII text (a finding title) is MIME-encoded.
func TestMailSubjectEncoded(t *testing.T) {
	subject := "[YARS] Returned to me: F-005 Überprüfung — XSS"
	msg := string(message("a@b", "c@d", subject, "b"))
	head, _, _ := strings.Cut(msg, "\r\n\r\n")
	for _, r := range head {
		if r > 127 {
			t.Fatalf("raw non-ASCII in headers: %q", head)
		}
	}
	m, err := netmail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	got, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || got != subject {
		t.Fatalf("subject %q %v", got, err)
	}
}
