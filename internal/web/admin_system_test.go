package web

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/backup"
	"yars/internal/config"
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
	// a download, the key with it, is a POST: a link from another site can't start one
	if rec := e.do(t, "dora", "GET", "/admin/system/backup?key=1", nil, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET backup %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{"key": {"1"}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site backup %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/admin/system/backup", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin backup %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil)
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
	files = zipNames(t, e.do(t, "dora", "POST", "/admin/system/backup", url.Values{"key": {"1"}}, nil).Body.Bytes())
	if _, ok := files[".yars/secret.key"]; !ok {
		t.Fatal("key not included when asked for")
	}
	l, _ := e.srv.Store.DB().AuditLog(1)
	if len(l) != 1 || l[0].Action != "backup" || !strings.HasPrefix(l[0].Detail, "with key · ") || !strings.HasSuffix(l[0].Detail, " KB") {
		t.Fatalf("audit %+v", l)
	}
}

// The download copies each repository under the store's lock of it, so it
// waits for a commit in progress; what it sends is a whole backup.
func TestBackupDownloadUsesStoreLocks(t *testing.T) {
	e := setup(t)
	unlock := e.srv.Store.LockEngagement("acme")
	done := make(chan []byte)
	go func() {
		done <- e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil).Body.Bytes()
	}()
	select {
	case <-done:
		unlock()
		t.Fatal("the download did not wait for the engagement's lock")
	case <-time.After(300 * time.Millisecond):
	}
	unlock()
	p := filepath.Join(t.TempDir(), "backup.zip")
	if err := os.WriteFile(p, <-done, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := backup.Verify(p)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Engagements != 1 || rep.Findings != 1 {
		t.Fatalf("report %+v", rep)
	}
}

// A backup that fails before any byte is sent (here: no temporary folder for
// the database snapshot) answers with an error, not a broken download.
func TestBackupEarlyFailureIsAnError(t *testing.T) {
	e := setupSerial(t)
	t.Setenv("TMPDIR", filepath.Join(e.dir, "missing"))
	rec := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "zip") || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("an error sent as a download: %v", rec.Header())
	}
	if l, _ := e.srv.Store.DB().AuditLog(1); len(l) == 1 && l[0].Action == "backup" {
		t.Fatalf("a failed backup is audited: %+v", l)
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
		"Health":     {"Checked", ">Run integrity<"},
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
	e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil)
	b = e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	if st := between(b, "<h2>Backup", "</form>"); !strings.Contains(st, `<span class="sv">dora</span>`) || strings.Contains(st, `<span class="sv">—</span>`) {
		t.Fatalf("last backup:\n%s", st)
	}
	// the backup's own size, not the database's (the Server panel has that);
	// the settings (.yars in the main repo) go in too
	st := between(b, "<h2>Backup", "</form>")
	if !strings.Contains(st, `<span class="sl">Size</span><span class="sv">`) || strings.Contains(st, `<span class="sl">Database</span>`) ||
		!strings.Contains(st, `<span class="sv">without key</span>`) || !strings.Contains(st, "checked disabled>Settings</label>") {
		t.Fatalf("backup stats:\n%s", st)
	}
	if sv := between(b, "<h2>Server", "</section>"); !strings.Contains(sv, `<span class="sl">Git clone</span>`) {
		t.Fatalf("server panel:\n%s", sv)
	}
	// an operation answers with a redirect (a reload doesn't run it again);
	// the page after it shows the result once
	op := func(path, want string) {
		t.Helper()
		rec := e.do(t, "dora", "POST", path, url.Values{}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/system" {
			t.Fatalf("%s %d %q", path, rec.Code, rec.Header().Get("Location"))
		}
		if b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(); !strings.Contains(b, want) {
			t.Fatalf("%s result lacks %q:\n%s", path, want, b)
		}
		if b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(); strings.Contains(b, want) {
			t.Fatalf("%s result shown twice", path)
		}
	}
	op("/admin/system/reindex", "Rebuilt")
	op("/admin/system/sync", "Synced")
	op("/admin/system/migrate", ".yars/users.yaml")
	e.do(t, "dora", "POST", "/admin/system/migrate", url.Values{}, nil)
	if b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(); !strings.Contains(b, "v"+strconv.Itoa(db.SchemaVersion)) {
		t.Fatal("migrate status lacks the schema")
	}
}

// The health checks run on Run integrity, not on every page load or after
// an operation; the page shows the last run. The AI provider is only
// pinged on Run integrity.
func TestSystemHealthCached(t *testing.T) {
	e := setupSerial(t) // t.Setenv
	// a provider with a key, at an address that refuses at once
	e.srv.Cfg.AI = config.AIConfig{Provider: "openai", BaseURL: "http://127.0.0.1:1/v1", Model: "m1", APIKeyEnv: "YARS_TEST_AI_KEY"}
	t.Setenv("YARS_TEST_AI_KEY", "k")
	e.rules(t, styleRules, nil)
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	if n := e.srv.healthRuns.Load(); n != 1 {
		t.Fatalf("%d runs on first load", n)
	}
	if !strings.Contains(between(b, ">AI provider<", "</tr>"), ">Not run<") {
		t.Fatalf("AI pinged on a page load:\n%s", b)
	}
	e.do(t, "dora", "GET", "/admin/system", nil, nil)
	e.do(t, "dora", "POST", "/admin/system/reindex", url.Values{}, nil)
	e.do(t, "dora", "GET", "/admin/system", nil, nil)
	if n := e.srv.healthRuns.Load(); n != 1 {
		t.Fatalf("%d runs after reloads and an operation", n)
	}
	if rec := e.do(t, "alice", "POST", "/admin/system/check", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin check %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/admin/system/check", url.Values{}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/system" || e.srv.healthRuns.Load() != 2 {
		t.Fatalf("run integrity %d runs %d", rec.Code, e.srv.healthRuns.Load())
	}
	b = e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	if strings.Contains(between(b, ">AI provider<", "</tr>"), ">Not run<") {
		t.Fatalf("AI not checked by Run integrity:\n%s", b)
	}
	if !strings.Contains(b, `action="/admin/system/check"`) {
		t.Fatal("no Run integrity form")
	}
}

func TestAdminAI(t *testing.T) {
	e := setupSerial(t) // t.Setenv
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

// healthRow is the Health table's row for a check.
func healthRowOf(t *testing.T, b, name string) string {
	t.Helper()
	i := strings.Index(b, ">"+name+"<")
	if i < 0 {
		t.Fatalf("no %s row:\n%s", name, b)
	}
	return b[i : i+strings.Index(b[i:], "</tr>")]
}

// D24: one button checks everything; it replaces Check again.
func TestRunIntegrityButton(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	head := between(b, "<h2>Health", `<div class="pbody`)
	if !strings.Contains(head, `<form method="post" action="/admin/system/check"><button class="btn save sm w128">Run integrity</button></form>`) || strings.Contains(b, "Check again") {
		t.Fatalf("Health head:\n%s", head)
	}
	// a page load runs no fsck: the row says so
	if row := healthRowOf(t, b, "Git repositories"); !strings.Contains(row, `<span class="tag off">Not run</span>`) {
		t.Fatalf("git row on a page load:\n%s", row)
	}
	if row := healthRowOf(t, b, "Database integrity"); !strings.Contains(row, "quick_check ok") {
		t.Fatalf("database row on a page load:\n%s", row)
	}
}

// D24: Run integrity checks every repository and the whole database.
func TestRunIntegrityRunsFsck(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "dora", "POST", "/admin/system/check", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("run %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	row := healthRowOf(t, b, "Git repositories")
	if !strings.Contains(row, `<span class="tag good">OK</span>`) || !strings.Contains(row, `title="2 repos">2 repos<`) {
		t.Fatalf("git row:\n%s", row)
	}
	if dbRow := healthRowOf(t, b, "Database integrity"); !strings.Contains(dbRow, "integrity_check ok") {
		t.Fatalf("database row:\n%s", dbRow)
	}
	if i, j := strings.Index(b, ">Database integrity<"), strings.Index(b, ">Git repositories<"); i > j {
		t.Fatal("Git repositories is not after Database integrity")
	}
}

// D24: a repository that lost an object is named.
func TestRunIntegrityReportsBrokenRepo(t *testing.T) {
	e := setup(t)
	repo := filepath.Join(e.dir, "engagements", "acme")
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD:findings/"+fdir+"/finding.md").Output()
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.TrimSpace(string(out))
	if err := os.Remove(filepath.Join(repo, ".git", "objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	e.do(t, "dora", "POST", "/admin/system/check", url.Values{}, nil)
	row := healthRowOf(t, e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(), "Git repositories")
	if !strings.Contains(row, `<span class="tag bad">Error</span>`) || !strings.Contains(row, `title="acme">acme<`) || !strings.Contains(row, "missing blob "+blob) {
		t.Fatalf("git row with a broken repository:\n%s", row)
	}
}

func TestAdminHealth(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	for _, want := range []string{`<th class="c-check">Check</th><th class="c-state">Status</th><th class="c-result">Result</th><th>Detail</th>`,
		">Rules<", ">Destinations<", ">pandoc &#43; PDF engine<", ">Git server repos<", ">AI provider<", ">Disk free<", ">Database integrity<",
		`class="tag good"`, `href="/admin/rules"`, `href="/admin/ai"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("health lacks %q:\n%s", want, b)
		}
	}
	// the board's order
	if i, j, k := strings.Index(b, `<a class="lk" href="/admin/rules">Rules</a>`), strings.Index(b, ">Destinations<"), strings.Index(b, ">Git server repos<"); !(i < j && j < k) {
		t.Fatalf("order %d %d %d", i, j, k)
	}
	// exporting off: both rows say so
	for _, name := range []string{">Destinations<", ">pandoc &#43; PDF engine<"} {
		if !strings.Contains(between(b, name, "</tr>"), `<span class="tag off">Off</span>`) {
			t.Fatalf("%s with exporting off:\n%s", name, between(b, name, "</tr>"))
		}
	}
	// an invalid rule is an error
	e.rules(t, "- id: bad-level\n  target: title\n  regex_forbid: x\n  level: critical\n", nil)
	e.do(t, "dora", "POST", "/admin/system/check", url.Values{}, nil)
	b = e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	if r := between(b, `<a class="lk" href="/admin/rules">Rules</a>`, "</tr>"); !strings.Contains(r, `<span class="tag bad">Error</span>`) || !strings.Contains(r, "1 invalid") {
		t.Fatalf("invalid rule:\n%s", r)
	}
}

// With exporting on, Destinations lists them and the pandoc row has the
// version of pandoc.
func TestAdminHealthExport(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, "#!/bin/sh\necho pandoc 3.1.11\necho Features: +server\n")
	e.do(t, "dora", "POST", "/admin/system/check", url.Values{}, nil)
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	if r := between(b, ">Destinations<", "</tr>"); !strings.Contains(r, `<span class="tag good">OK</span>`) || !strings.Contains(r, "Confluence HTML, Client report (DOCX)") {
		t.Fatalf("destinations with exporting on:\n%s", r)
	}
	if r := between(b, ">pandoc &#43; PDF engine<", "</tr>"); !strings.Contains(r, "pandoc 3.1.11") || strings.Contains(r, "Features") {
		t.Fatalf("pandoc with exporting on:\n%s", r)
	}
}

func TestAdminActivity(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String()
	for _, want := range []string{"<th class=\"c-time\">Time</th>", ">login<", "Sessions"} {
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
	if b := e.do(t, "dora", "GET", "/admin/tokens", nil, nil).Body.String(); !strings.Contains(b, "…"+info.Last4) || !strings.Contains(b, ">Tokens · 1<") {
		t.Fatal("token not listed")
	}
	if rec := e.do(t, "dora", "POST", "/admin/activity/tokens/"+strconv.FormatInt(info.ID, 10)+"/revoke", url.Values{}, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/tokens" {
		t.Fatalf("revoke token %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if l, _ := e.srv.Store.DB().UserTokens("bob"); len(l) != 0 {
		t.Fatal("token not revoked")
	}
}
