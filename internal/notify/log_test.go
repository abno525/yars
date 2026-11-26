package notify

import (
	"errors"
	"fmt"
	"log/slog"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
)

// refusingMailer refuses every mail with err.
type refusingMailer struct{ err error }

func (m refusingMailer) Send(string, string, string) error { return m.err }

// A mail writes one line when it ends: info when it was sent, warn when it
// was not, with the account, the engagement, the finding and the event. A
// refusal is named by the SMTP reply code alone: the server's words quote
// the recipient's address, which no line holds.
func TestMailIsLogged(t *testing.T) {
	n, d, _ := newNotifier(t)
	lg, out := logs.NewRecorder()
	n.Logger = lg
	d.SetNotify("pen1", "returned", "email", true)
	e := ev(store.EventStatus)
	e.Actor, e.Action, e.Reason = "rev1", "return", "zqreason7f3kq"
	n.Handle(e)
	n.Wait()
	sent := out.With("notification email sent")
	if len(sent) != 1 || sent[0].Level != slog.LevelInfo || sent[0].Str("user") != "pen1" || sent[0].Str("eng") != "demo" ||
		sent[0].Str("finding") != "F-005" || sent[0].Str("event") != "returned" || !sent[0].Has("ms") {
		t.Fatalf("log:\n%s", out.Text())
	}
	if n.Sending() != 0 {
		t.Fatalf("%d mails still counted as being sent", n.Sending())
	}

	for want, err := range map[string]error{
		"SMTP 550":      &textproto.Error{Code: 550, Msg: "5.1.1 <pen1@acme.example>: Recipient address rejected"},
		"SMTP 554":      fmt.Errorf("send: %w", &textproto.Error{Code: 554, Msg: "pen1@acme.example blocked"}),
		"not delivered": errors.New("550 5.1.1 <pen1@acme.example>: Recipient address rejected"),
	} {
		out.Reset()
		n.Mail = refusingMailer{err}
		n.Handle(e)
		n.Wait()
		failed := out.With("notification email not sent")
		if len(failed) != 1 || failed[0].Level != slog.LevelWarn || failed[0].Str("user") != "pen1" || failed[0].Str("err") != want || !failed[0].Has("ms") {
			t.Fatalf("%s: log:\n%s", want, out.Text())
		}
		if text := out.Text(); strings.Contains(text, "acme.example") || strings.Contains(text, "zqreason7f3kq") || strings.Contains(text, "SQL injection") {
			t.Fatalf("the log holds an address or text:\n%s", text)
		}
	}
}

// A token notice is about no engagement and no finding: its mail line has
// neither field, sent or not.
func TestTokenMailLineHasNoEmptyFields(t *testing.T) {
	n, d, _ := newNotifier(t)
	lg, out := logs.NewRecorder()
	n.Logger = lg
	now := time.Now()
	for i, hash := range []string{"h-abcd", "h-wxyz"} {
		if i == 1 {
			n.Mail = refusingMailer{&textproto.Error{Code: 550, Msg: "refused"}}
		}
		exp := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
		if _, err := d.CreateToken("pen1", hash, hash[len(hash)-4:], db.TokenSpec{Name: "laptop", Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}, Expires: exp}); err != nil {
			t.Fatal(err)
		}
		d.SetNotify("pen1", Token, "email", true)
		if err := n.Tokens(now); err != nil {
			t.Fatal(err)
		}
		n.Wait()
	}
	recs := append(out.With("notification email sent"), out.With("notification email not sent")...)
	if len(recs) != 2 {
		t.Fatalf("log:\n%s", out.Text())
	}
	for _, r := range recs {
		if r.Has("eng") || r.Has("finding") || r.Str("user") != "pen1" || r.Str("event") != Token || !r.Has("ms") {
			t.Errorf("line: %s", r)
		}
	}
}
