package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/export"
)

// host is the stub's host as its destination names it.
func (j *jiraStub) host() string {
	u, _ := url.Parse(strings.Replace(j.srv.URL, "127.0.0.1", "localhost", 1))
	return u.Host
}

func (j *jiraStub) lastUser() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.users) == 0 {
		return ""
	}
	return j.users[len(j.users)-1]
}

// A personal key is kept for one service host and sent only there: another
// destination of the same service gets the server's key, and a key bound to
// no host (stored before keys had hosts) is never sent.
func TestExportKeyBoundToHost(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	client := e.jira(t, false)
	if err := os.Rename(filepath.Join(e.srv.Export.Dir, "jira.yaml"), filepath.Join(e.srv.Export.Dir, "client.yaml")); err != nil {
		t.Fatal(err)
	}
	firm := e.jira(t, false)
	send := func(dest string) {
		t.Helper()
		e.follow(t, "dora", e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {dest}, "finding": {fdir}}, nil))
	}
	// a key stored for the service alone
	box, err := e.srv.secrets()
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := box.Encrypt("alice@acme:legacy")
	if err := e.srv.Store.DB().SetConnection("alice", "jira", enc); err != nil {
		t.Fatal(err)
	}
	send("jira")
	if u := firm.lastUser(); u != "bot:srvkey5c2e" {
		t.Fatalf("unbound key sent: %s", u)
	}
	// a key for the firm's Jira
	svc := "jira@" + firm.host()
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {svc}, "key": {"alice@acme:ownkey"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("key %d:\n%s", rec.Code, rec.Body.String())
	}
	if b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `id="conn-`+svc+`"`) || !strings.Contains(b, firm.host()) || !strings.Contains(b, client.host()) {
		t.Fatalf("settings:\n%s", b)
	}
	send("client")
	if u := client.lastUser(); u != "bot:srvkey5c2e" {
		t.Fatalf("firm key sent to the client's Jira: %s", u)
	}
	send("jira")
	if u := firm.lastUser(); u != "alice@acme:ownkey" {
		t.Fatalf("own key not used at its host: %s", u)
	}
	// keys only for the hosts of destinations
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {"jira@evil.example"}, "key": {"x"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown host %d", rec.Code)
	}
	// the unbound key can still be removed
	if rec := e.do(t, "alice", "POST", "/settings/connections/jira/remove", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove %d", rec.Code)
	}
	if _, ok, _ := e.srv.Store.DB().Connection("alice", "jira"); ok {
		t.Fatal("unbound key not removed")
	}
}

// Only an admin sets where a service destination sends its keys: a
// director who is not an admin can't change its address or key variables
// or create one, but can edit the rest.
func TestDestAddressAdminOnly(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	e.addUser(t, config.User{Username: "dir2", Role: "director"})
	base := "http://" + j.host()
	form := func(mod func(url.Values)) url.Values {
		f := url.Values{"id": {"jira"}, "name": {"Jira PEN"}, "type": {"jira"}, "base_url": {base}, "project": {"PEN"},
			"user_env": {"JIRA_USER"}, "token_env": {"JIRA_TOKEN"}, "status": {"complete"}, "mark_reported": {"1"}}
		if mod != nil {
			mod(f)
		}
		return f
	}
	hostNow := func() string {
		es, _ := export.Load(e.srv.Export.Dir)
		ex, _ := findExporter(es, "jira")
		return ex.Host() + " " + ex.Jira.TokenEnv
	}
	b := e.do(t, "dir2", "GET", "/e/acme/export/setup?edit=jira", nil, nil).Body.String()
	if !strings.Contains(b, `name="base_url" value="`+base+`" readonly`) || !strings.Contains(b, `name="token_env" value="JIRA_TOKEN" readonly`) {
		t.Fatalf("editor:\n%s", b)
	}
	for name, f := range map[string]url.Values{
		"address":   form(func(f url.Values) { f.Set("base_url", "https://attacker.example") }),
		"token env": form(func(f url.Values) { f.Set("token_env", "JIRA_OTHER") }),
		"new":       form(func(f url.Values) { f.Set("new", "1"); f.Set("id", "jira2") }),
	} {
		if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", f, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, rec.Code)
		}
	}
	if h := hostNow(); h != j.host()+" JIRA_TOKEN" {
		t.Fatalf("changed to %s", h)
	}
	if _, err := os.Stat(filepath.Join(e.srv.Export.Dir, "jira2.yaml")); err == nil {
		t.Fatal("new service destination saved")
	}
	// the rest is the director's
	if rec := e.do(t, "dir2", "POST", "/e/acme/export/setup", form(func(f url.Values) { f.Set("project", "SEC") }), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("director edit %d:\n%s", rec.Code, rec.Body.String())
	}
	// an admin may move it
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", form(func(f url.Values) { f.Set("base_url", "https://jira.acme.com") }), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("admin edit %d:\n%s", rec.Code, rec.Body.String())
	}
	if h := hostNow(); h != "jira.acme.com JIRA_TOKEN" {
		t.Fatalf("admin change: %s", h)
	}
	if b := e.do(t, "dora", "GET", "/e/acme/export/setup?edit=jira", nil, nil).Body.String(); !strings.Contains(b, `name="base_url" value="https://jira.acme.com">`) {
		t.Fatal("admin editor read only")
	}
}

// A failed send is retried once: after its retry the old row offers no
// Retry and refuses one, so its findings are never sent twice.
func TestExportRetryOnce(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, false)
	j.fail = true
	e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil))
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	first := itoa(h[0].ID)
	retry := "/e/acme/export/history/" + first + "/retry"
	j.fail = false
	e.follow(t, "alice", e.do(t, "alice", "POST", retry, url.Values{}, nil))
	if rec := e.do(t, "alice", "POST", retry, url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("second retry %d", rec.Code)
	}
	if strings.Join(j.writes, " ") != "POST" {
		t.Fatalf("sent again: %v", j.writes)
	}
	b := e.do(t, "alice", "GET", "/e/acme/export?sent="+first, nil, nil).Body.String()
	if strings.Contains(b, `action="`+retry+`"`) || strings.Contains(b, `formaction="`+retry+`"`) {
		t.Fatalf("old row still retries:\n%s", b)
	}
}
