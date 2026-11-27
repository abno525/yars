package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/workflow"
)

// Sending a finding again updates its issue instead of making another; an
// issue deleted at Jira is made again. The result says which.
func TestExportUpdatesSentFinding(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, false)
	send := func() string {
		return e.follow(t, "dora", e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil))
	}
	page := send()
	if !strings.Contains(page, `<span class="tag sent-created">created</span>`) || !strings.Contains(page, ">Change</th>") {
		t.Fatalf("first send:\n%s", page)
	}
	if ls := j.issues["PEN-1"]; len(ls) != 1 || ls[0] != "yars-acme-F-001" {
		t.Fatalf("labels %v", ls)
	}
	rm, ok, _ := e.srv.Store.DB().ExportRemote("jira", "acme", "F-001")
	if !ok || rm.RemoteID != "PEN-1" || !strings.HasSuffix(rm.URL, "/browse/PEN-1") || !strings.HasSuffix(rm.Target, " PEN") {
		t.Fatalf("remembered %+v", rm)
	}
	page = send()
	if strings.Join(j.writes, " ") != "POST PUT PEN-1" || !strings.Contains(page, `<span class="tag sent-updated">updated</span>`) || !strings.Contains(page, "/browse/PEN-1") {
		t.Fatalf("second send %v:\n%s", j.writes, page)
	}
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	if items := itemsOf(h[0]); len(items) != 1 || items[0].Action != "updated" {
		t.Fatalf("history %+v", items)
	}
	// R4, Review focus 1: reported, then reverted to complete, the next send
	// updates the same issue
	for _, step := range []struct {
		a      workflow.Action
		reason string
	}{{workflow.Report, ""}, {workflow.Unreport, "sent too early"}} {
		if err := e.srv.Store.Transition("acme", fdir, step.a, step.reason, wDora); err != nil {
			t.Fatal(err)
		}
	}
	send()
	if strings.Join(j.writes, " ") != "POST PUT PEN-1 PUT PEN-1" {
		t.Fatalf("send after a revert %v", j.writes)
	}
	delete(j.issues, "PEN-1")
	send()
	if strings.Join(j.writes, " ") != "POST PUT PEN-1 PUT PEN-1 POST" {
		t.Fatalf("after delete %v", j.writes)
	}
	if rm, _, _ := e.srv.Store.DB().ExportRemote("jira", "acme", "F-001"); rm.RemoteID != "PEN-2" {
		t.Fatalf("not replaced %+v", rm)
	}
}

// A send that failed on the author's own key offers the author to renew it
// and anyone to send again with the server's key.
func TestExportFailedOwnKey(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	svc := "jira@" + j.host()
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {svc}, "key": {"alice@acme:ownkey"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("key %d", rec.Code)
	}
	j.reject = "alice@acme:ownkey"
	page := e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil))
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	server := "/e/acme/export/history/" + itoa(h[0].ID) + "/server"
	for _, want := range []string{"key expired", `<a class="btn secondary sm w112" href="/settings#conn-` + svc + `">Renew key</a>`,
		`<button class="btn secondary sm w136" formaction="` + server + `" name="dir" value="` + fdir + `">Use server key</button>`} {
		if !strings.Contains(page, want) {
			t.Errorf("failed send lacks %q", want)
		}
	}
	if strings.Contains(page, "style=") {
		t.Error("inline style")
	}
	// the settings page has the anchor
	if b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `id="conn-`+svc+`"`) {
		t.Error("no connections anchor")
	}
	// someone else can't renew alice's key
	other := e.do(t, "dora", "GET", "/e/acme/export?sent="+itoa(h[0].ID), nil, nil).Body.String()
	if strings.Contains(other, "Renew key") || !strings.Contains(other, "Use server key") || !strings.Contains(other, `<span class="slot w112"></span>`) {
		t.Fatalf("director view:\n%s", other)
	}
	// only a failed finding of that send
	if rec := e.do(t, "alice", "POST", server, url.Values{"dir": {"F-009-nope"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown finding %d", rec.Code)
	}
	page = e.follow(t, "alice", e.do(t, "alice", "POST", server, url.Values{"dir": {fdir}}, nil))
	if last := j.users[len(j.users)-1]; last != "bot:srvkey5c2e" || !strings.Contains(page, "server key") || e.status(t) != "reported" {
		t.Fatalf("server key send %s:\n%s", last, page)
	}
	h, _ = e.srv.Store.DB().Exports("acme", 1)
	if items := itemsOf(h[0]); !h[0].OK || len(items) != 1 || items[0].SentAs != "server" || items[0].Action != "created" {
		t.Fatalf("history %+v", h[0])
	}
	// a successful send has nothing to send again
	if rec := e.do(t, "alice", "POST", "/e/acme/export/history/"+itoa(h[0].ID)+"/server", url.Values{"dir": {fdir}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("again %d", rec.Code)
	}
}

// A stored personal key that cannot be read fails the finding with the
// reason: nothing goes out under the server's name unless the sender picks
// Use server key.
func TestExportUnreadableOwnKey(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	svc := "jira@" + j.host()
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {svc}, "key": {"alice@acme:ownkey"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("key %d", rec.Code)
	}
	if _, err := e.srv.Store.DB().Exec("UPDATE connections SET secret_enc = 'x' WHERE username = 'alice'"); err != nil {
		t.Fatal(err)
	}
	send := func(path string, form url.Values) string {
		return e.follow(t, "alice", e.do(t, "alice", "POST", path, form, nil))
	}
	page := send("/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}})
	if len(j.users) != 0 || len(j.writes) != 0 {
		t.Fatalf("the service was reached: logins %v, writes %v", j.users, j.writes)
	}
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	items := itemsOf(h[0])
	if h[0].OK || len(items) != 1 || items[0].OK || items[0].Marked || items[0].SentAs != "alice" || items[0].Error != "alice: personal key unreadable" {
		t.Fatalf("history %+v, items %+v", h[0], items)
	}
	if st := e.status(t); st != "complete" {
		t.Fatalf("status %s", st)
	}
	server := "/e/acme/export/history/" + itoa(h[0].ID) + "/server"
	for _, want := range []string{"alice: personal key unreadable", "Renew key", `formaction="` + server + `"`, "Use server key"} {
		if !strings.Contains(page, want) {
			t.Errorf("failed send lacks %q", want)
		}
	}
	// a retry with the key still broken fails again and can be tried again
	send("/e/acme/export/history/"+itoa(h[0].ID)+"/retry", nil)
	h, _ = e.srv.Store.DB().Exports("acme", 1)
	if items := itemsOf(h[0]); h[0].OK || len(items) != 1 || !items[0].retryable() || len(j.users) != 0 || e.status(t) != "complete" {
		t.Fatalf("retry: history %+v, logins %v", h[0], j.users)
	}
	// the sender picks the server's key, in the open
	page = send("/e/acme/export/history/"+itoa(h[0].ID)+"/server", url.Values{"dir": {fdir}})
	if len(j.users) == 0 || j.users[len(j.users)-1] != "bot:srvkey5c2e" || !strings.Contains(page, "server key") || e.status(t) != "reported" {
		t.Fatalf("server key send %v:\n%s", j.users, page)
	}
}

// Without a server key there is no server-key button; its slot stays.
func TestExportFailedNoServerKey(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {"jira@" + j.host()}, "key": {"alice@acme:ownkey"}}, nil)
	j.reject = "alice@acme:ownkey"
	e.srv.Export.Getenv = func(string) string { return "" }
	page := e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil))
	if strings.Contains(page, "Use server key") || !strings.Contains(page, `<span class="slot w136"></span>`) || !strings.Contains(page, "Renew key") {
		t.Fatalf("page:\n%s", page)
	}
}
