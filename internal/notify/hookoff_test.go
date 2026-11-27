package notify

import (
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
)

// A webhook switched off is told to the admins whose account is on, in app
// whatever they chose, never by mail, with the host and not the address.
func TestHookOffTellsAdmins(t *testing.T) {
	n, d, m := newNotifier(t)
	for _, u := range []config.User{{Username: "adm", Role: "pentester", IsAdmin: true, Email: "adm@acme.example"},
		{Username: "oldadm", Role: "director", IsAdmin: true, Disabled: true}} {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	all := append([]config.User{{Username: "adm", Role: "pentester", IsAdmin: true, Email: "adm@acme.example"},
		{Username: "oldadm", Role: "director", IsAdmin: true, Disabled: true}}, users...)
	n.Users = func() []config.User { return all }
	// adm saved choices once, and chose mail for everything they could
	d.SetNotify("adm", Returned, "email", true)
	n.HookOff(db.Webhook{ID: 7, URL: "https://hooks.example:8443/zqpath?key=zqkey", Failures: 5})
	n.Wait()
	l, _ := d.Notifications("adm", 10)
	if len(l) != 1 || l[0].Event != Webhook || l[0].Title != "hooks.example:8443" || l[0].Ref != "7" || l[0].Actor != "yars" ||
		l[0].Text != "5 deliveries given up in a row" || l[0].Eng != "" || strings.Contains(l[0].Title+l[0].Text, "zq") {
		t.Fatalf("adm: %+v", l)
	}
	if Target(l[0]) != "/admin/webhooks?hook=7" || Label(Webhook) != "Webhook off" {
		t.Fatalf("target %q label %q", Target(l[0]), Label(Webhook))
	}
	for _, u := range []string{"oldadm", "dir1", "pen1"} {
		if got := list(t, d, u); got != "" {
			t.Errorf("%s: %s", u, got)
		}
	}
	if len(m.sent) != 0 {
		t.Fatalf("mailed: %+v", m.sent)
	}
	// the settings do not list it
	for _, e := range append(EventsFor(false), EventsFor(true)...) {
		if e.Key == Webhook {
			t.Fatal("the settings list the webhook notice")
		}
	}
}

// Where a notice leads: one function for the pages, the mail and MCP.
func TestTarget(t *testing.T) {
	for _, c := range []struct {
		n    db.Notification
		want string
	}{
		{db.Notification{Event: Token}, "/settings#tokens"},
		{db.Notification{Event: Webhook, Ref: "x"}, "/admin/webhooks"},
		{db.Notification{Event: Reply, Eng: "demo", Dir: "F-005-sqli", Fid: "F-005", Thread: "m-1"}, "/e/demo/f/005#t-m-1"},
		{db.Notification{Event: Returned, Eng: "demo", Dir: "F-005-sqli", Fid: "F-005"}, "/e/demo/f/005"},
		{db.Notification{Event: Returned, Eng: "demo"}, "/e/demo"},
		{db.Notification{Event: Returned, Eng: "../x", Dir: "F-005-sqli"}, "/notifications"},
	} {
		if got := Target(c.n); got != c.want {
			t.Errorf("%+v: %q, want %q", c.n, got, c.want)
		}
	}
}
