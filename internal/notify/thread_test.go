package notify

import (
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// A notice about a chat message knows its thread: the message a reply
// answers, else the message itself (a mention in a new thread). The mail's
// link ends with the thread's anchor; an id that is no plain ID never
// reaches the link. Other notices have no thread.
func TestChatNoticeCarriesThread(t *testing.T) {
	n, d, m := newNotifier(t)
	for _, set := range [][3]string{{"rev1", Reply, "app"}, {"rev1", Reply, "email"}, {"pen1", Mentioned, "app"}, {"pen1", Mentioned, "email"}, {"pen1", Returned, "app"}} {
		if err := d.SetNotify(set[0], set[1], set[2], true); err != nil {
			t.Fatal(err)
		}
	}
	e := ev(store.EventChat)
	e.Actor, e.Text, e.MsgID = "rev1", "@pen1 which roles?", "aaa111"
	n.Handle(e)
	e = ev(store.EventChat)
	e.Actor, e.Text, e.MsgID, e.Reply, e.ReplyTo = "pen1", "admins only", "bbb222", "aaa111", "rev1"
	n.Handle(e)
	e = ev(store.EventStatus)
	e.Actor, e.Action, e.Reason = "rev1", "return", "add a PoC"
	n.Handle(e)
	e = ev(store.EventChat)
	e.Actor, e.Text, e.MsgID = "rev1", "@pen1 again", "x/../y z"
	n.Handle(e)
	n.Wait()
	threads := func(user string) string {
		t.Helper()
		l, err := d.Notifications(user, 50)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for i := len(l) - 1; i >= 0; i-- { // oldest first
			out = append(out, l[i].Event+":"+l[i].Thread)
		}
		return strings.Join(out, ",")
	}
	if got := threads("pen1"); got != "mentioned:aaa111,returned:,mentioned:" {
		t.Errorf("pen1: %s", got)
	}
	if got := threads("rev1"); got != "reply:aaa111" {
		t.Errorf("rev1: %s", got)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	links := map[string]int{}
	for _, x := range m.sent {
		lines := strings.Split(strings.TrimSpace(x.body), "\n")
		links[x.to+" "+lines[len(lines)-1]]++
	}
	for _, want := range []string{
		"rev1@acme.example https://yars.example.com/e/demo/f/005#t-aaa111",
		"pen1@acme.example https://yars.example.com/e/demo/f/005#t-aaa111",
		"pen1@acme.example https://yars.example.com/e/demo/f/005", // the id that is no ID
	} {
		if links[want] != 1 {
			t.Errorf("no mail %q: %v", want, links)
		}
	}
}
