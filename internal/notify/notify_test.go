package notify

import (
	"mime"
	netmail "net/mail"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

// A reviewer assigned on a draft hears nothing yet: there is nothing to
// review until submit, which asks once.
func TestDraftAssignmentNotNotified(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventReviewers)
	e.Actor, e.Added, e.State = "pen1", []string{"rev1"}, "draft"
	n.Handle(e)
	e = ev(store.EventStatus)
	e.Actor, e.Action = "pen1", "submit"
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "rev1"); got != "review:pen1:" {
		t.Fatalf("rev1: %s", got)
	}
}

func TestWhoIsNotified(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventReviewers)
	e.Actor, e.Added, e.State = "pen1", []string{"rev1", "out", "gone"}, "verification"
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

// A take back tells the assigned reviewers: the finding left their queue and
// their sign-offs are gone.
func TestTakeBackNotifiesReviewers(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventStatus)
	e.Actor, e.Action, e.Reviewers = "pen1", "take_back", []string{"rev1", "rev2", "pen1"}
	n.Handle(e)
	n.Wait()
	for _, u := range []string{"rev1", "rev2"} {
		if got := list(t, d, u); got != "taken_back:pen1:" {
			t.Errorf("%s: %q", u, got)
		}
	}
	if got := list(t, d, "pen1"); got != "" {
		t.Errorf("the actor heard of it: %q", got)
	}
	if Label(TakenBack) != "Taken back" {
		t.Errorf("label %q", Label(TakenBack))
	}
}

// R4: a revert tells the author and the reviewers (not who reverted it),
// with its reason.
func TestNotifyRevert(t *testing.T) {
	n, d, _ := newNotifier(t)
	e := ev(store.EventStatus)
	e.Actor, e.Action, e.Reason = "dir1", "unreport", "sent too early"
	n.Handle(e)
	e.Actor, e.Action, e.Reason = "pen1", "reopen", "wrong host"
	n.Handle(e)
	n.Wait()
	if got := list(t, d, "pen1"); got != "reverted:dir1:sent too early" {
		t.Errorf("author: %q", got)
	}
	if got := list(t, d, "rev1"); got != "reverted:dir1:sent too early,reverted:pen1:wrong host" {
		t.Errorf("reviewer: %q", got)
	}
	if got := list(t, d, "dir1"); got != "" {
		t.Errorf("the actor heard of it: %q", got)
	}
	if Label(Reverted) != "Reverted" {
		t.Errorf("label %q", Label(Reverted))
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

// A token's owner hears once, on the channels they chose, when it has less
// than TokenSoon left; a later token, a disabled owner and an expired token
// make no notice.
func TestTokenExpiring(t *testing.T) {
	n, d, m := newNotifier(t)
	now := time.Now()
	add := func(user, hash, name, kind string, left time.Duration) {
		t.Helper()
		exp := now.Add(left).UTC().Format(time.RFC3339)
		if _, err := d.CreateToken(user, hash, hash[len(hash)-4:], db.TokenSpec{Name: name, Kind: kind, Scopes: []string{db.ScopeAll}, Expires: exp}); err != nil {
			t.Fatal(err)
		}
	}
	add("pen1", "h-abcd", "laptop", db.TokenMCP, 3*24*time.Hour)
	add("pen1", "h-wxyz", "", db.TokenGit, 2*24*time.Hour)
	add("rev1", "h-late", "ci", db.TokenMCP, 30*24*time.Hour)
	add("gone", "h-gone", "old", db.TokenMCP, 24*time.Hour)
	add("rev2", "h-past", "dead", db.TokenMCP, -time.Hour)
	d.SetNotify("pen1", Token, "app", true)
	d.SetNotify("pen1", Token, "email", true)
	if err := n.Tokens(now); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	day := func(left time.Duration) string { return now.Add(left).Format("2006-01-02") }
	want := "token:yars:MCP · …abcd · expires " + day(3*24*time.Hour) + ",token:yars:Git · …wxyz · expires " + day(2*24*time.Hour)
	if got := list(t, d, "pen1"); got != want {
		t.Fatalf("pen1: %s\nwant %s", got, want)
	}
	l, _ := d.Notifications("pen1", 10)
	if titles := l[1].Title + "," + l[0].Title; titles != "laptop,…wxyz" {
		t.Errorf("titles %s", titles)
	}
	for _, u := range []string{"rev1", "gone", "rev2"} {
		if got := list(t, d, u); got != "" {
			t.Errorf("%s: %s", u, got)
		}
	}
	m.mu.Lock()
	if len(m.sent) != 2 {
		t.Fatalf("mails %+v", m.sent)
	}
	// mails go out concurrently: find laptop's by its subject
	var ml mail
	for _, x := range m.sent {
		if x.subject == "[YARS] Token expiring: laptop" {
			ml = x
		}
	}
	if ml.to != "pen1@acme.example" ||
		!strings.Contains(ml.body, "MCP · …abcd · expires") || !strings.Contains(ml.body, "https://yars.example.com/settings#tokens") {
		t.Errorf("%+v", ml)
	}
	m.mu.Unlock()
	// once per token
	if err := n.Tokens(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	n.Wait()
	if got := list(t, d, "pen1"); got != want || len(m.sent) != 2 {
		t.Fatalf("told twice: %s, %d mails", got, len(m.sent))
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
