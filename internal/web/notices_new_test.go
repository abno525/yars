package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/notify"
)

// A notice about a lead of the team board and one about a retest have no
// finding: their rows name the engagement and the lead (or the engagement
// alone), and Open leads to the lead or the retest.
func TestNoticesWithoutAFinding(t *testing.T) {
	e := setup(t)
	bob := config.User{Username: "bob", Role: "reviewer"}
	if _, err := e.srv.Store.CreateNote("acme", "Odd header on /login", "", "open", "@alice can you look?", bob); err != nil {
		t.Fatal(err)
	}
	d := e.srv.Store.DB()
	// a retest notice as the notifier stores it
	if _, err := d.AddNotification(db.Notification{User: "alice", Event: notify.Retest, Eng: "acme", Title: "Acme retest", Actor: "dora"}); err != nil {
		t.Fatal(err)
	}
	l, _ := d.Notifications("alice", 10)
	if len(l) != 2 || l[1].Event != notify.Mentioned || l[1].Ref != "L-001" || l[1].Fid != "" {
		t.Fatalf("alice's notices %+v", l)
	}
	b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String()
	for _, want := range []string{">Mentioned<", `<span class="fid">acme · L-001</span> Odd header on /login`, "@alice can you look?",
		">Retest assigned<", `<span class="fid">acme</span> Acme retest`} {
		if !strings.Contains(b, want) {
			t.Errorf("notifications page lacks %q", want)
		}
	}
	if strings.Contains(b, "acme · <") || strings.Contains(b, `<span class="fid"> · `) {
		t.Error("a row has a dangling separator")
	}
	if b := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(); !strings.Contains(b, "Odd header on /login") || !strings.Contains(b, "Acme retest") {
		t.Error("the inbox lacks the notices")
	}
	for i, want := range []string{"/e/acme", "/e/acme/board?n=L-001"} {
		rec := e.do(t, "alice", "POST", "/notifications/"+strconv.FormatInt(l[i].ID, 10), url.Values{}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
			t.Errorf("open %d: %d %q, want %q", i, rec.Code, rec.Header().Get("Location"), want)
		}
	}
	// every notice has its tag colour
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, ev := range append(notify.Events, notify.Event{Key: notify.Webhook}) {
		if !strings.Contains(css, ".tag.nev-"+ev.Key+" ") && !strings.Contains(css, ".tag.nev-"+ev.Key+",") {
			t.Errorf("style.css has no colour for the %s notice", ev.Key)
		}
	}
}
