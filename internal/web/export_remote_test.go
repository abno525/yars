package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
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
	delete(j.issues, "PEN-1")
	send()
	if strings.Join(j.writes, " ") != "POST PUT PEN-1 POST" {
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
