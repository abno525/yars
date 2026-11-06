package web

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/db"
	"yars/internal/secret"
)

func zipNames(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = b
	}
	return out
}

// The backup holds the main repo, every engagement repo and a snapshot of
// the database; the secret key only when asked for.
func TestBackupZip(t *testing.T) {
	e := setup(t)
	if err := secret.EnsureKey(e.dir); err != nil {
		t.Fatal(err)
	}
	// the live database file inside the data dir is never copied as is
	os.WriteFile(filepath.Join(e.dir, ".yars", "yars.db"), []byte("live"), 0o600)
	rec := e.do(t, "dora", "GET", "/admin/system/backup", nil, nil)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" || !strings.Contains(rec.Header().Get("Content-Disposition"), "yars-backup-") {
		t.Fatalf("backup %d %v", rec.Code, rec.Header())
	}
	files := zipNames(t, rec.Body.Bytes())
	for _, want := range []string{".git/HEAD", "engagements/acme/.git/HEAD", "engagements/acme/engagement.yaml", ".yars/yars.db"} {
		if _, ok := files[want]; !ok {
			t.Errorf("backup lacks %s", want)
		}
	}
	// the database is a snapshot (VACUUM INTO), in place of the live file
	if !bytes.HasPrefix(files[".yars/yars.db"], []byte("SQLite format 3")) {
		t.Fatal("database snapshot is not a database")
	}
	for name := range files {
		if strings.HasSuffix(name, "secret.key") || strings.HasSuffix(name, "-wal") {
			t.Fatalf("backup has %s", name)
		}
	}
	files = zipNames(t, e.do(t, "dora", "GET", "/admin/system/backup?key=1", nil, nil).Body.Bytes())
	if _, ok := files[".yars/secret.key"]; !ok {
		t.Fatal("key not included when asked for")
	}
	l, _ := e.srv.Store.DB().AuditLog(1)
	if len(l) != 1 || l[0].Action != "backup" || l[0].Detail != "with key" {
		t.Fatalf("audit %+v", l)
	}
}

func TestAdminSystem(t *testing.T) {
	e := setup(t)
	e.srv.MigrateStatus = func() []string { return []string{".yars/users.yaml"} }
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	for _, want := range []string{"Users", "Engagements", "Findings", "Chat messages", "Data folder", "Index build", `name="key"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("system page lacks %q", want)
		}
	}
	// every panel's actions sit in its header, next to the title
	heads := map[string][]string{
		"Health":     {"Checked", ">Check again<"},
		"Backup":     {">Download backup<"},
		"Operations": {">Sync pointers<", ">Rebuild index<", ">Migrate status<"},
	}
	for h, wants := range heads {
		head := between(b, "<h2>"+h, `<div class="pbody`)
		if head == "" {
			t.Fatalf("no %s panel", h)
		}
		for _, w := range wants {
			if !strings.Contains(head, w) {
				t.Fatalf("%s header lacks %q:\n%s", h, w, head)
			}
		}
	}
	// stat rows: equal cells
	if strings.Count(b, `<div class="st">`) < 10 {
		t.Fatalf("stat cells:\n%s", b)
	}
	// a backup shows as the last one, with who made it
	e.do(t, "dora", "GET", "/admin/system/backup", nil, nil)
	b = e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	if st := between(b, "<h2>Backup", "</form>"); !strings.Contains(st, `<span class="sv">dora</span>`) || strings.Contains(st, `<span class="sv">—</span>`) {
		t.Fatalf("last backup:\n%s", st)
	}
	if rec := e.do(t, "dora", "POST", "/admin/system/reindex", url.Values{}, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Rebuilt") {
		t.Fatalf("reindex %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/system/sync", url.Values{}, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Synced") {
		t.Fatalf("sync %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/admin/system/migrate", url.Values{}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), ".yars/users.yaml") || !strings.Contains(rec.Body.String(), "v"+strconv.Itoa(db.SchemaVersion)) {
		t.Fatalf("migrate status %d", rec.Code)
	}
}

func TestAdminAI(t *testing.T) {
	e := setup(t)
	const key = "sk-live-0123456789abcdef3f2a"
	form := url.Values{"provider": {"openai"}, "base_url": {"https://api.example.com/v1"}, "model": {"m1"}, "key": {key}}
	if rec := e.do(t, "dora", "POST", "/admin/ai", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d %s", rec.Code, rec.Body.String())
	}
	d := e.srv.Store.DB()
	if v, _ := d.Setting("ai.model"); v != "m1" {
		t.Fatalf("model %q", v)
	}
	if v, _ := d.Setting("ai.key"); v == "" || strings.Contains(v, key) || strings.Contains(v, "3f2a") {
		t.Fatalf("key stored as %q", v)
	}
	b := e.do(t, "dora", "GET", "/admin/ai", nil, nil).Body.String()
	if strings.Contains(b, key) || !strings.Contains(b, "…3f2a") {
		t.Fatalf("key shown:\n%s", b)
	}
	// saving with an empty key field keeps the stored key
	form.Set("key", "")
	form.Set("model", "m2")
	e.do(t, "dora", "POST", "/admin/ai", form, nil)
	if b := e.do(t, "dora", "GET", "/admin/ai", nil, nil).Body.String(); !strings.Contains(b, "…3f2a") || !strings.Contains(b, `value="m2"`) {
		t.Fatal("key lost on save")
	}
	// http is only for localhost, unknown providers are refused
	for _, f := range []url.Values{
		{"provider": {"openai"}, "base_url": {"http://example.com"}},
		{"provider": {"bard"}},
	} {
		if rec := e.do(t, "dora", "POST", "/admin/ai", f, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", f, rec.Code)
		}
	}
	// the environment variable wins
	e.srv.Cfg.AI.APIKeyEnv = "YARS_TEST_AI_KEY"
	t.Setenv("YARS_TEST_AI_KEY", "from-env-9z9z")
	b = e.do(t, "dora", "GET", "/admin/ai", nil, nil).Body.String()
	if !strings.Contains(b, "YARS_TEST_AI_KEY") || strings.Contains(b, "9z9z") {
		t.Fatalf("env key:\n%s", b)
	}
	// … only at config.yaml's provider and address: here the page set
	// another address, so the env key is not in use
	if !strings.Contains(b, `class="tag idle" title="YARS_TEST_AI_KEY"`) {
		t.Fatalf("env key shown in use for the page's address:\n%s", b)
	}
	e.srv.Cfg.AI.Provider, e.srv.Cfg.AI.BaseURL = "openai", "https://api.example.com/v1"
	b = e.do(t, "dora", "GET", "/admin/ai", nil, nil).Body.String()
	if !strings.Contains(b, `class="tag good" title="YARS_TEST_AI_KEY"`) {
		t.Fatalf("env key not in use at config.yaml's address:\n%s", b)
	}
	// Test without rules configured: a failed state, no network
	if rec := e.do(t, "dora", "POST", "/admin/ai/test", url.Values{}, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `class="tag bad"`) {
		t.Fatalf("test %d", rec.Code)
	}
	// "Off" clears the provider
	e.do(t, "dora", "POST", "/admin/ai", url.Values{"provider": {"off"}}, nil)
	if v, _ := d.Setting("ai.provider"); v != "off" {
		t.Fatalf("provider %q", v)
	}
}

func TestAdminHealth(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	for _, want := range []string{`<th class="c-check">Check</th><th class="c-state">Status</th><th class="c-result">Result</th><th>Detail</th>`,
		">Rules<", ">Git server repos<", ">AI provider<", ">Disk free<", ">Database integrity<", `class="tag good"`, `href="/admin/rules"`, `href="/admin/ai"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("health lacks %q:\n%s", want, b)
		}
	}
}

func TestAdminActivity(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String()
	for _, want := range []string{"<th class=\"c-time\">Time</th>", ">login<", "Sessions", "Tokens"} {
		if !strings.Contains(b, want) {
			t.Fatalf("activity lacks %q", want)
		}
	}
	if b := e.do(t, "dora", "GET", "/admin/activity?actor=bob", nil, nil).Body.String(); strings.Contains(b, `<td class="clip">alice</td>`) {
		t.Fatal("actor filter ignored")
	}
	// revoke alice's session
	ss, _ := e.srv.Store.DB().Sessions()
	var id int64
	for _, s := range ss {
		if s.User == "alice" {
			id = s.ID
		}
	}
	if rec := e.do(t, "dora", "POST", "/admin/activity/sessions/"+strconv.FormatInt(id, 10)+"/revoke", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke session %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatal("revoked session still works")
	}
	// revoke anyone's token
	_, info, err := auth.NewTokens(e.srv.Store.DB()).Create("bob", "bob", db.TokenSpec{Name: "t", Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String(); !strings.Contains(b, "…"+info.Last4) {
		t.Fatal("token not listed")
	}
	if rec := e.do(t, "dora", "POST", "/admin/activity/tokens/"+strconv.FormatInt(info.ID, 10)+"/revoke", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke token %d", rec.Code)
	}
	if l, _ := e.srv.Store.DB().UserTokens("bob"); len(l) != 0 {
		t.Fatal("token not revoked")
	}
}
