// Package notify turns YARS events into notifications for the people they
// concern: an in-app list (the bell) and, when the server has SMTP settings,
// email. Each user chooses the channels per event (notify_prefs).
package notify

import (
	"fmt"
	"log"
	"mime"
	"net/smtp"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/store"
)

// Notification events a user can choose channels for.
const (
	Returned  = "returned"
	Review    = "review"
	Reply     = "reply"
	Approved  = "approved"
	Mentioned = "mentioned"
	Check     = "check"
	Token     = "token"
	TakenBack = "taken_back" // the author took a finding I review back to draft
	Reverted  = "reverted"   // a finding I wrote or review went back a step (R4)
)

// Event is one choosable notification event.
type Event struct{ Key, Label string }

// Events in the order the settings list them.
var Events = []Event{{Returned, "Returned to me"}, {Review, "Review requested"}, {TakenBack, "Taken back"}, {Reply, "Reply in my thread"},
	{Approved, "Approved"}, {Reverted, "Reverted"}, {Mentioned, "Mentioned"}, {Check, "Check finished"}, {Token, "Token expiring"}}

// Label is an event's name for people.
func Label(key string) string {
	for _, e := range Events {
		if e.Key == key {
			return e.Label
		}
	}
	return key
}

// Keys lists the event keys.
func Keys() []string {
	var out []string
	for _, e := range Events {
		out = append(out, e.Key)
	}
	return out
}

// Mailer sends one plain-text email.
type Mailer interface {
	Send(to, subject, body string) error
}

// Notifier delivers notifications (a store OnEvent subscriber).
type Notifier struct {
	DB *db.DB
	// Users lists the accounts; CanSee tells whether one is on an
	// engagement's team.
	Users  func() []config.User
	CanSee func(u config.User, eng string) bool
	// Mail sends email; when nil, MailFor gives the mailer of the current
	// config (nil = no email).
	Mail    Mailer
	MailFor func() Mailer
	// BaseURL starts the links in email.
	BaseURL func() string
	wg      sync.WaitGroup
}

func (n *Notifier) mailer() Mailer {
	if n.Mail != nil {
		return n.Mail
	}
	if n.MailFor != nil {
		return n.MailFor()
	}
	return nil
}

// Wait waits for email being sent.
func (n *Notifier) Wait() { n.wg.Wait() }

// recipients maps who should hear about e to the event key.
func recipients(e store.Event) map[string]string {
	out := map[string]string{}
	add := func(user, key string) {
		if user != "" && user != e.Actor {
			if _, ok := out[user]; !ok {
				out[user] = key
			}
		}
	}
	switch e.Kind {
	case store.EventReviewers:
		// on a draft there is nothing to review yet: submit asks them
		if e.State == "verification" {
			for _, u := range e.Added {
				add(u, Review)
			}
		}
	case store.EventStatus:
		switch e.Action {
		case "submit":
			for _, u := range e.Reviewers {
				add(u, Review)
			}
		case "return":
			add(e.Author, Returned)
		case "approve":
			add(e.Author, Approved)
		case "take_back":
			// it left their queue, and any sign-off they gave is gone
			for _, u := range e.Reviewers {
				add(u, TakenBack)
			}
		case "reopen", "unreport":
			// R4: back a step, with a reason, for its author and reviewers
			add(e.Author, Reverted)
			for _, u := range e.Reviewers {
				add(u, Reverted)
			}
		}
	case store.EventChat:
		for _, u := range store.Mentions(e.Text) {
			add(u, Mentioned)
		}
		add(e.ReplyTo, Reply)
	case store.EventCheck:
		if e.Author != "" {
			out[e.Author] = Check // the author hears even of their own run
		}
	}
	return out
}

// text is the line shown with the notification.
func text(e store.Event) string {
	switch e.Kind {
	case store.EventStatus:
		return e.Reason
	case store.EventChat:
		t := strings.Join(strings.Fields(e.Text), " ")
		if r := []rune(t); len(r) > 200 {
			t = string(r[:200]) + "…"
		}
		return t
	case store.EventCheck:
		if e.State == db.RunFailed {
			return "failed"
		}
		return plural(e.Errors, "error") + " · " + plural(e.Warnings, "warning")
	}
	return ""
}

func plural(n int, w string) string {
	if n == 1 {
		return "1 " + w
	}
	return strconv.Itoa(n) + " " + w + "s"
}

// Handle notifies the people e concerns, on the channels they chose.
func (n *Notifier) Handle(e store.Event) {
	to := recipients(e)
	if len(to) == 0 {
		return
	}
	var accounts []config.User
	if n.Users != nil {
		accounts = n.Users()
	}
	names := make([]string, 0, len(to))
	for u := range to {
		names = append(names, u)
	}
	slices.Sort(names)
	mail := n.mailer()
	for _, name := range names {
		i := slices.IndexFunc(accounts, func(u config.User) bool { return u.Username == name })
		if i < 0 || accounts[i].Disabled || (n.CanSee != nil && !n.CanSee(accounts[i], e.Eng)) {
			continue
		}
		u, key := accounts[i], to[name]
		n.deliver(u, db.Notification{User: u.Username, Event: key, Eng: e.Eng, Dir: e.Dir, Fid: e.Fid, Title: e.Title, Actor: e.Actor, Text: text(e)}, mail)
	}
}

// deliver stores note in u's list and emails it, as u chose for its event.
func (n *Notifier) deliver(u config.User, note db.Notification, mail Mailer) {
	if n.DB.Wants(u.Username, note.Event, "app") {
		if _, err := n.DB.AddNotification(note); err != nil {
			log.Printf("notify %s: %v", u.Username, err)
		}
	}
	if mail != nil && u.Email != "" && n.DB.Wants(u.Username, note.Event, "email") {
		subject, body := n.mailFor(note)
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			if err := mail.Send(u.Email, subject, body); err != nil {
				log.Printf("notify %s by email: %v", u.Username, err)
			}
		}()
	}
}

// TokenSoon is how long before its expiry a token's owner is told, once;
// the token lists tag it "Expires soon" from then on.
const TokenSoon = 7 * 24 * time.Hour

// Tokens tells the owner of each token with less than TokenSoon left that
// it expires (once per token; a disabled account is not told, and is told
// once enabled again if the token is still about to expire). The notice is
// by yars, titled with the token's name (its ending when it has none).
func (n *Notifier) Tokens(now time.Time) error {
	l, err := n.DB.TokensExpiring(now, TokenSoon)
	if err != nil || len(l) == 0 {
		return err
	}
	var accounts []config.User
	if n.Users != nil {
		accounts = n.Users()
	}
	mail := n.mailer()
	for _, t := range l {
		i := slices.IndexFunc(accounts, func(u config.User) bool { return u.Username == t.User })
		if i < 0 || accounts[i].Disabled {
			continue
		}
		if ok, err := n.DB.TokenNoted(t.ID); err != nil || !ok {
			if err != nil {
				return err
			}
			continue // told already, or revoked meanwhile
		}
		kind := "MCP"
		if t.Kind == db.TokenGit {
			kind = "Git"
		}
		title := t.Name
		if title == "" {
			title = "…" + t.Last4
		}
		exp, _ := time.Parse(time.RFC3339, t.Expires) // TokensExpiring parsed it
		n.deliver(accounts[i], db.Notification{User: t.User, Event: Token, Title: title, Actor: "yars",
			Text: kind + " · …" + t.Last4 + " · expires " + exp.Local().Format("2006-01-02")}, mail)
	}
	return nil
}

func (n *Notifier) mailFor(x db.Notification) (string, string) {
	if x.Event == Token {
		subject := "[YARS] " + Label(x.Event) + ": " + x.Title
		base := ""
		if n.BaseURL != nil {
			base = n.BaseURL()
		}
		return subject, Label(x.Event) + " · " + x.Actor + "\n" + x.Title + " · " + x.Text + "\n\n" + base + "/settings#tokens\n"
	}
	subject := "[YARS] " + Label(x.Event) + ": " + x.Fid + " " + x.Title
	var b strings.Builder
	fmt.Fprintf(&b, "%s · %s\n%s · %s %s\n", Label(x.Event), x.Actor, x.Eng, x.Fid, x.Title)
	if x.Text != "" {
		b.WriteString("\n" + x.Text + "\n")
	}
	base := ""
	if n.BaseURL != nil {
		base = n.BaseURL()
	}
	b.WriteString("\n" + base + "/e/" + x.Eng + "/f/" + store.ShortID(x.Dir) + "\n")
	return subject, b.String()
}

// SMTP sends email through the configured server.
type SMTP struct{ Cfg config.SMTPConfig }

// NewSMTP is the mailer for c, or nil when email isn't configured.
func NewSMTP(c config.SMTPConfig) Mailer {
	if !c.Configured() {
		return nil
	}
	return SMTP{Cfg: c}
}

func (m SMTP) Send(to, subject, body string) error {
	addr := m.Cfg.Host + ":" + strconv.Itoa(m.Cfg.Port)
	var a smtp.Auth
	if m.Cfg.Username != "" {
		a = smtp.PlainAuth("", m.Cfg.Username, os.Getenv(m.Cfg.PasswordEnv), m.Cfg.Host)
	}
	return smtp.SendMail(addr, a, m.Cfg.From, []string{to}, message(m.Cfg.From, to, subject, body))
}

// oneLine keeps a header value on one line.
func oneLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// message is a plain-text email with CRLF line ends.
func message(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + oneLine(from) + "\r\n")
	b.WriteString("To: " + oneLine(to) + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", oneLine(subject)) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}
