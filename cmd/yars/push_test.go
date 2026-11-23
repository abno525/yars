package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/gitserve"
	"yars/internal/store"
	"yars/internal/webhook"
)

type pushEnv struct {
	t     *testing.T
	repo  *gitrepo.Repo // the server's acme engagement repo
	st    *store.Store
	clone string // recursive clone of the main repo
	url   string
	srv   *httptest.Server
	// beforeReceive, when set, runs once as a push's POST arrives, before
	// the engagement lock is taken (after the client read the refs).
	beforeReceive atomic.Pointer[func()]
}

// A push that loses the race to a website commit (made between the client's
// ref read and its POST) is refused with a hint, leaves the server's work
// tree at HEAD (the website edit stays on disk), and a pull plus push works.
func TestPushLosesRaceToWebCommit(t *testing.T) {
	p := newPushEnv(t)
	alice := config.User{Username: "alice", Role: "pentester"}
	webEdit := func() {
		if err := p.st.UpdateSection("acme", "F-001-sqli", "Remediation", "Web edit.", "", alice); err != nil {
			t.Error(err)
		}
	}
	p.beforeReceive.Store(&webEdit)
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "Pushed impact.") })
	out, err := p.git("push", "origin", "HEAD")
	if err == nil {
		t.Fatalf("push over a newer web commit accepted:\n%s", out)
	}
	if !strings.Contains(out, "remote: yars:") || !strings.Contains(out, "pull") {
		t.Errorf("no pull hint:\n%s", out)
	}
	if st, _ := exec.Command("git", "-C", p.repo.Dir, "status", "--porcelain", "--untracked-files=no").Output(); len(st) != 0 {
		t.Fatalf("server work tree dirty after the lost race:\n%s", st)
	}
	ref, _ := p.st.Finding("acme", "F-001-sqli")
	if b, _ := ref.F.Section("Remediation"); !strings.Contains(b, "Web edit.") {
		t.Fatalf("web edit reverted on disk: %q", b)
	}
	if out, err := p.git("pull", "-q", "--no-rebase", "--no-edit", "origin", "main"); err != nil {
		t.Fatalf("pull: %v\n%s", err, out)
	}
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("push after pull: %v\n%s", err, out)
	}
}

// A push bigger than git's http.postBuffer goes up with a chunked body,
// which the CGI host refuses on its own; it must still reach the hook.
func TestPushChunkedBody(t *testing.T) {
	p := newPushEnv(t)
	blob := make([]byte, 256<<10)
	rand.Read(blob)
	os.MkdirAll(filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "attachments"), 0o755)
	// a text attachment (as the website accepts) that does not compress
	os.WriteFile(filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "attachments", "big.txt"), []byte(hex.EncodeToString(blob)), 0o644)
	if out, err := p.git("add", "-A"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := p.git("commit", "-qm", "big attachment"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := p.git("-c", "http.postBuffer=4096", "push", "origin", "HEAD"); err != nil {
		t.Fatalf("chunked push failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(p.repo.Dir, "findings", "F-001-sqli", "attachments", "big.txt")); err != nil {
		t.Fatal("pushed attachment not on the server")
	}
}

// Through the real hook: with the server's config.yaml broken, a
// pentester's push is refused with the reason, and a director's push that
// repairs config.yaml over /git/yars is accepted.
func TestPushRepairsBrokenConfig(t *testing.T) {
	p := newPushEnv(t)
	main := filepath.Dir(filepath.Dir(p.repo.Dir))
	in := func(dir string, args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=dora", "-c", "user.email=dora@yars.local", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	os.WriteFile(filepath.Join(main, ".yars", "config.yaml"), []byte("severities: [x\n"), 0o644)
	if out, err := in(main, "add", ".yars/config.yaml"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := in(main, "commit", "-qm", "broken config"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "blocked") })
	if out, err := p.git("push", "origin", "HEAD"); err == nil || !strings.Contains(out, "cannot be loaded") {
		t.Fatalf("push with a broken server config: %v\n%s", err, out)
	}
	if out, err := in(p.clone, "pull", "-q", "--no-rebase", "--no-edit", "origin", "main"); err != nil {
		t.Fatalf("pull: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(p.clone, ".yars", "config.yaml"), []byte("severities: [critical, high, medium, low, info]\n"), 0o644)
	if out, err := in(p.clone, "commit", "-qm", "repair config", "--", ".yars/config.yaml"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	dora := strings.Replace(p.url, "http://", "http://dora:pw@", 1) + "/git/yars"
	if out, err := in(p.clone, "push", dora, "HEAD:main"); err != nil {
		t.Fatalf("repair push refused: %v\n%s", err, out)
	}
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("push after the repair: %v\n%s", err, out)
	}
}

// Through the real hook: a director's push to an approved finding moves the
// approval only once it lands. A push the hook passed that git then refused
// (a change left in the server's work tree stops the checkout) leaves the
// finding approved for the content it still has; the same push, once it
// lands, keeps it approved for the new content.
func TestPushCarriesApprovalOnceLanded(t *testing.T) {
	p := newPushEnv(t)
	d := p.st.DB()
	sp := filepath.Join(p.repo.Dir, "findings", "F-001-sqli", "finding.md")
	raw, _ := os.ReadFile(sp)
	was := store.ContentHash(raw)
	if err := d.Tx(func(tx *db.Tx) error {
		return tx.PutState("acme", "F-001", db.State{Status: "complete", ApprovedHash: was})
	}); err != nil {
		t.Fatal(err)
	}
	ed := filepath.Join(p.clone, "engagements", "acme")
	dora := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", ed, "-c", "user.name=dora", "-c", "user.email=dora@yars.local", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	cp := filepath.Join(ed, "findings", "F-001-sqli", "finding.md")
	b, _ := os.ReadFile(cp)
	f, err := finding.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	f.SetSection("Impact", "Director's polish.")
	os.WriteFile(cp, f.Bytes(), 0o644)
	if out, err := dora("commit", "-qam", "polish"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	url := strings.Replace(p.url, "http://", "http://dora:pw@", 1) + "/git/e/acme"
	leftOver := func() {
		os.WriteFile(filepath.Join(p.repo.Dir, "engagement.yaml"), []byte("name: ACME\n# left over\n"), 0o644)
	}
	p.beforeReceive.Store(&leftOver)
	if out, err := dora("push", url, "HEAD:main"); err == nil {
		t.Fatalf("push into a changed work tree accepted:\n%s", out)
	}
	state := func() (db.State, string) {
		t.Helper()
		st, err := d.State("acme", "F-001")
		if err != nil {
			t.Fatal(err)
		}
		ref, err := p.st.Finding("acme", "F-001-sqli")
		if err != nil {
			t.Fatal(err)
		}
		return st, ref.F.Meta.Status
	}
	if st, shown := state(); st.ApprovedHash != was || shown != "complete" {
		t.Fatalf("after a push that did not land: approval %s (was %s), shown %s", st.ApprovedHash, was, shown)
	}
	if out, err := dora("push", url, "HEAD:main"); err != nil {
		t.Fatalf("director's push refused: %v\n%s", err, out)
	}
	now, _ := os.ReadFile(sp)
	if st, shown := state(); st.ApprovedHash != store.ContentHash(now) || shown != "complete" {
		t.Fatalf("after the push landed: approval %s, content %s, shown %s", st.ApprovedHash, store.ContentHash(now), shown)
	}
}

// A chunked body over the cap is refused (413) and leaves no spool file.
func TestPushChunkedBodyCapped(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	p := newPushEnvWith(t, func(gs *gitserve.Server) { gs.MaxBody = 64 << 10 })
	blob := make([]byte, 256<<10)
	rand.Read(blob)
	os.WriteFile(filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "big.bin"), blob, 0o644)
	p.git("add", "-A")
	p.git("commit", "-qm", "too big")
	out, err := p.git("-c", "http.postBuffer=4096", "push", "origin", "HEAD")
	if err == nil || !strings.Contains(out, "413") {
		t.Fatalf("oversized chunked push: %v\n%s", err, out)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("spool files left: %v", ents)
	}
}

// A work tree left dirty by a push that never moved the branch (a crash
// between checkout and the ref update) is put back to HEAD on start, the
// main repo's too.
func TestSetupRestoresDirtyEngagementTree(t *testing.T) {
	p := newPushEnv(t)
	os.WriteFile(filepath.Join(p.repo.Dir, "findings", "F-001-sqli", "finding.md"), []byte("half a push"), 0o644)
	exec.Command("git", "-C", p.repo.Dir, "add", "-A").Run()
	main := filepath.Dir(filepath.Dir(p.repo.Dir))
	os.WriteFile(filepath.Join(main, ".yars", "config.yaml"), []byte("severities: [x\n"), 0o644)
	exec.Command("git", "-C", main, "add", ".yars/config.yaml").Run()
	mr, _ := gitrepo.Open(main)
	if err := gitserve.RestoreTrees(mr); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{p.repo.Dir, main} {
		if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=all").Output(); len(st) != 0 {
			t.Fatalf("dirty tree kept on start in %s:\n%s", dir, st)
		}
	}
}

// Each engagement can be cloned on its own; its history holds only that
// engagement's commits.
func TestEngagementCloneHistory(t *testing.T) {
	p := newPushEnv(t)
	dst := filepath.Join(t.TempDir(), "acme")
	cmd := exec.Command("git", "clone", "-q", strings.Replace(p.url, "http://", "http://alice:pw@", 1)+"/git/e/acme", dst)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	log, _ := exec.Command("git", "-C", dst, "log", "--format=%s").Output()
	if string(log) != "F-001: create\nengagement acme: create\n" {
		t.Fatalf("history:\n%s", log)
	}
	if _, err := os.Stat(filepath.Join(dst, "findings", "F-001-sqli", "finding.md")); err != nil {
		t.Fatal("finding missing from the engagement clone")
	}
}

func newPushEnv(t *testing.T) *pushEnv {
	t.Helper()
	return newPushEnvWith(t, nil)
}

// newPushEnvWith lets tune change the git server before it serves.
func newPushEnvWith(t *testing.T, tune func(gs *gitserve.Server)) *pushEnv {
	t.Helper()
	bin := hookBinary(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	withTestRules(t, dir) // the server's check rules, which pushes run
	r, _ := gitrepo.Open(dir)
	hash := testHash(t, "pw")
	users := []config.User{{Username: "alice", Role: "pentester", PasswordHash: hash}, {Username: "dora", Role: "director", PasswordHash: hash, IsAdmin: true}}
	d := openDB(t, dir)
	for _, u := range users {
		d.AddUser(u) // the database stays on the server
	}
	st := store.New(r, config.Default(), d)
	alice := users[0]
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, users[1].GitAuthor())
	st.CreateFinding("acme", "SQLi", alice.GitAuthor())
	d.AddMembers("acme", "alice") // alice's team

	p := &pushEnv{t: t, st: st}
	receive := func(eng string, u config.User, serve func()) {
		if fn := p.beforeReceive.Swap(nil); fn != nil {
			(*fn)()
		}
		st.ReceivePush(eng, u, serve)
	}
	gs := &gitserve.Server{Repo: r, Auth: auth.New(d), HookCmd: hookCmd(bin, dir), Sync: st.SyncPointers, Invalidate: st.Invalidate,
		Receive: receive, Tokens: auth.NewTokens(d), CanSee: st.CanSee}
	if tune != nil {
		tune(gs)
	}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/git/", gs.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// download everything: the main repo with every engagement as a submodule
	clone := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(srv.URL, "http://", "http://alice:pw@", 1) + "/git/yars"
	cmd := exec.Command("git", "clone", "-q", "--recurse-submodules", url, clone)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	er, _ := st.EngRepo("acme")
	p.repo, p.clone, p.url, p.srv = er, clone, srv.URL, srv
	if out, err := p.git("switch", "-q", "main"); err != nil {
		t.Fatalf("switch: %v %s", err, out)
	}
	return p
}

// git runs in the acme engagement inside the recursive clone.
func (p *pushEnv) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", filepath.Join(p.clone, "engagements", "acme"), "-c", "user.name=alice", "-c", "user.email=alice@yars.local", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (p *pushEnv) editFinding(fn func(f *finding.Finding)) {
	path := filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "finding.md")
	b, _ := os.ReadFile(path)
	f, err := finding.Parse(b)
	if err != nil {
		p.t.Fatal(err)
	}
	fn(f)
	os.WriteFile(path, f.Bytes(), 0o644)
	if out, err := p.git("commit", "-qam", "edit"); err != nil {
		p.t.Fatalf("commit: %v %s", err, out)
	}
}

// End to end through the real hook: a push to an archived engagement is
// rejected, and accepted again once a director reopens it.
func TestPushArchivedRejected(t *testing.T) {
	p := newPushEnv(t)
	dora := config.User{Username: "dora", Role: "director"}
	if err := p.st.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "Full database read.") })
	out, err := p.git("push", "origin", "HEAD")
	if err == nil || !strings.Contains(out, "archived") {
		t.Fatalf("push to archived engagement: %v\n%s", err, out)
	}
	p.st.Unarchive("acme", dora)
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("push after reopen: %v\n%s", err, out)
	}
}

func TestPushEndToEnd(t *testing.T) {
	p := newPushEnv(t)
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "Full database read.") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("allowed push rejected: %v\n%s", err, out)
	}
	ref, err := p.st.Finding("acme", "F-001-sqli")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := ref.F.Section("Impact"); !strings.Contains(b, "Full database read.") {
		t.Fatalf("server not updated: %q", b)
	}

	before, _ := p.repo.Head()
	p.editFinding(func(f *finding.Finding) { f.SetMeta("status", "complete") })
	out, err := p.git("push", "origin", "HEAD")
	if err == nil || !strings.Contains(out, "remote: yars:") || !strings.Contains(out, "managed in YARS") {
		t.Fatalf("forbidden push: err=%v\n%s", err, out)
	}
	if after, _ := p.repo.Head(); after != before {
		t.Fatal("server HEAD moved after a rejected push")
	}
}

// The hook reads workflow state from the database: once a finding is
// approved, a pentester's push to it is refused.
func TestPushLockedByDatabaseState(t *testing.T) {
	p := newPushEnv(t)
	d := p.st.DB()
	if err := d.Tx(func(tx *db.Tx) error {
		return tx.PutState("acme", "F-001", db.State{Status: "complete"})
	}); err != nil {
		t.Fatal(err)
	}
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "late") })
	if out, err := p.git("push", "origin", "HEAD"); err == nil || !strings.Contains(out, "complete") {
		t.Fatalf("locked finding pushed: err=%v\n%s", err, out)
	}
}

// An AI editing the local clone through MCP stdio commits as the user; the
// push of that commit passes the server policy.
func TestMCPStdioThenPush(t *testing.T) {
	p := newPushEnv(t)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"update_section","arguments":{"engagement":"acme","finding":"F-001","section":"Impact","body":"Written by the assistant."}}}` + "\n")
	var out bytes.Buffer
	if err := runMCP([]string{"--data", p.clone, "--user", "alice"}, in, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "isError") {
		t.Fatalf("mcp error: %s", out.String())
	}
	if o, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("push rejected: %v\n%s", err, o)
	}
	ref, _ := p.st.Finding("acme", "F-001-sqli")
	if b, _ := ref.F.Section("Impact"); !strings.Contains(b, "Written by the assistant.") {
		t.Fatalf("server not updated: %q", b)
	}
}

// A push is as good as an edit on the site: a section edit and a new
// finding pushed over git queue the webhook deliveries the same changes
// through YARS would, as the pusher; a rejected push queues nothing.
func TestPushEmitsEvents(t *testing.T) {
	p := newPushEnv(t)
	d := p.st.DB()
	id, err := d.AddWebhook(db.Webhook{URL: "http://127.0.0.1:9/hook", Events: []string{store.EventCreated, store.EventUpdated}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	ws := &webhook.Service{DB: d}
	p.st.OnEvent(ws.Handle)
	payloads := func() map[string]string {
		l, _ := d.Deliveries(id, 50)
		out := map[string]string{}
		for _, x := range l {
			out[x.Event] += x.Payload
		}
		return out
	}

	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "Full database read.") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	got := payloads()
	if up := got[store.EventUpdated]; !strings.Contains(up, `"actor":"alice"`) || !strings.Contains(up, `"changed":["Impact"]`) || !strings.Contains(up, `"id":"F-001"`) {
		t.Fatalf("updated delivery %q", up)
	}
	if got[store.EventCreated] != "" {
		t.Fatalf("created for an edit: %s", got[store.EventCreated])
	}

	nf := finding.New("F-002", "Stored XSS", "alice", config.Default().Sections)
	fd := filepath.Join(p.clone, "engagements", "acme", "findings", "F-002-stored-xss")
	os.MkdirAll(fd, 0o755)
	os.WriteFile(filepath.Join(fd, "finding.md"), nf.Bytes(), 0o644)
	if out, err := p.git("add", "-A"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := p.git("commit", "-qm", "F-002: create"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("push new finding: %v\n%s", err, out)
	}
	if c := payloads()[store.EventCreated]; !strings.Contains(c, `"id":"F-002"`) || !strings.Contains(c, `"title":"Stored XSS"`) || !strings.Contains(c, `"actor":"alice"`) {
		t.Fatalf("created delivery %q", c)
	}

	n := len(payloads()[store.EventUpdated]) + len(payloads()[store.EventCreated])
	p.editFinding(func(f *finding.Finding) { f.SetMeta("status", "complete") })
	if _, err := p.git("push", "origin", "HEAD"); err == nil {
		t.Fatal("forbidden push accepted")
	}
	if m := len(payloads()[store.EventUpdated]) + len(payloads()[store.EventCreated]); m != n {
		t.Fatal("a rejected push queued deliveries")
	}
}

// A git token's scopes reach the hook: a create-only token can't change an
// existing finding; a token with "edit" can.
func TestPushTokenScopes(t *testing.T) {
	p := newPushEnv(t)
	tk := auth.NewTokens(p.st.DB())
	push := func(scope string) (string, error) {
		tok, _, err := tk.Create("alice", "alice", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{scope}})
		if err != nil {
			t.Fatal(err)
		}
		return p.git("push", strings.Replace(p.url, "http://", "http://alice:"+tok+"@", 1)+"/git/e/acme", "HEAD:main")
	}
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "one") })
	if out, err := push("create"); err == nil || !strings.Contains(out, "cannot edit") {
		t.Fatalf("create-only token edited: %v\n%s", err, out)
	}
	if out, err := push("edit"); err != nil {
		t.Fatalf("edit token rejected: %v\n%s", err, out)
	}
}

func TestTokensUntracked(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	openDB(t, dir).AddUser(config.User{Username: "alice", Role: "pentester"})
	var out bytes.Buffer
	if code, _ := cmdToken([]string{"add", "--data", dir, "mallory"}, &out); code == 0 {
		t.Fatal("token for unknown user")
	}
	if code, err := cmdToken([]string{"add", "--data", dir, "alice"}, &out); code != 0 || err != nil || !strings.Contains(out.String(), "yars_") {
		t.Fatalf("token add: %d %v %s", code, err, out.String())
	}
	r, _ := gitrepo.Open(dir)
	if r.Tracked(".yars/tokens.yaml") {
		t.Fatal("tokens tracked")
	}
	st, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if len(st) != 0 {
		t.Fatalf("tokens file not ignored: %s", st)
	}
}

// Through the real hook: a commit carrying the pusher's name but another
// email is refused, naming the commit and the account's email; amended to
// the account's email (any name), the same change goes in.
func TestPushAuthorEmail(t *testing.T) {
	p := newPushEnv(t)
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "one") })
	p.git("-c", "user.email=a@a", "commit", "-q", "--amend", "--no-edit", "--reset-author")
	short, _ := p.git("rev-parse", "--short=7", "HEAD")
	out, err := p.git("push", "origin", "HEAD")
	if err == nil || !strings.Contains(out, "commit "+strings.TrimSpace(short)+": ") || !strings.Contains(out, "a@a") || !strings.Contains(out, "alice@yars.local") {
		t.Fatalf("other email: %v\n%s", err, out)
	}
	p.git("-c", "user.name=Alice L", "commit", "-q", "--amend", "--no-edit", "--reset-author")
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("account email refused: %v\n%s", err, out)
	}
}

// Through the real hook: a push is refused for what the website refuses,
// in any of its commits, each refusal naming the commit, the file and the
// rule; nothing lands.
func TestPushRefusesWhatWebRefuses(t *testing.T) {
	p := newPushEnv(t)
	head := func() string { s, _ := p.git("rev-parse", "--short=7", "HEAD"); return strings.TrimSpace(s) }
	refused := func(what, want string) {
		t.Helper()
		before, _ := p.repo.Head()
		out, err := p.git("push", "origin", "HEAD")
		if err == nil || !strings.Contains(out, want) {
			t.Errorf("%s: %v\n%s", what, err, out)
		}
		if after, _ := p.repo.Head(); after != before {
			t.Errorf("%s: server HEAD moved", what)
		}
		p.git("reset", "-q", "--hard", "origin/main")
	}
	// a broken middle commit, repaired by the last one
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "one") })
	p.editFinding(func(f *finding.Finding) { f.SetMeta("cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") })
	mid := head()
	p.editFinding(func(f *finding.Finding) { f.SetMeta("severity", "critical") })
	refused("middle commit", "remote: yars: commit "+mid+" findings/F-001-sqli/finding.md: severity (none) does not match the CVSS vector (score 9.8 is critical)")

	att := filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "attachments")
	os.MkdirAll(att, 0o755)
	os.WriteFile(filepath.Join(att, "poc.png"), []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"), 0o755)
	p.git("add", "-A")
	p.git("commit", "-qm", "program")
	refused("program attachment", "remote: yars: commit "+head()+" findings/F-001-sqli/attachments/poc.png: attachments cannot be executable")

	os.WriteFile(filepath.Join(p.clone, "engagements", "acme", "engagement.yaml"), []byte("name: ACME\ntype: retest\nsource: other\n"), 0o644)
	p.git("commit", "-qam", "retest now")
	refused("type change", "remote: yars: commit "+head()+" engagement.yaml: only a director can create or change engagements")

	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "fine") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("valid push after the refusals: %v\n%s", err, out)
	}
}

// Through the real hook: the server's check rules run on pushed findings.
// A draft with a rule error goes in, and the push output says so; in
// verification the same error refuses the push (commit, file, rule); AI
// rules are reported as not run.
func TestPushRunsCheckRules(t *testing.T) {
	p := newPushEnv(t)
	p.editFinding(func(f *finding.Finding) { f.SetMeta("title", "SQLi.") })
	out, err := p.git("push", "origin", "HEAD")
	head := func() string { s, _ := p.git("rev-parse", "--short=7", "HEAD"); return strings.TrimSpace(s) }
	if err != nil || !strings.Contains(out, "remote: yars: commit "+head()+" findings/F-001-sqli/finding.md: check title-no-trailing-dot (error; blocks Submit): The title must not end with a dot") {
		t.Fatalf("draft with a rule error: %v\n%s", err, out)
	}
	if err := p.st.DB().Tx(func(tx *db.Tx) error {
		return tx.PutState("acme", "F-001", db.State{Status: "verification", Reviewers: []db.Reviewer{{Name: "alice"}}})
	}); err != nil {
		t.Fatal(err)
	}
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "Reviewer's words.") })
	out, err = p.git("push", "origin", "HEAD")
	if err == nil || !strings.Contains(out, "remote: yars: commit "+head()+" findings/F-001-sqli/finding.md: check title-no-trailing-dot (error): The title must not end with a dot") ||
		!strings.Contains(out, "check acronyms-expanded (could not run): AI rules run with Check on the finding page, not on push") {
		t.Fatalf("rule error in verification: %v\n%s", err, out)
	}
	p.editFinding(func(f *finding.Finding) { f.SetMeta("title", "SQLi") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("fixed: %v\n%s", err, out)
	}
}

// Through the real hook: settings pushed to the main repo apply at once,
// without a restart; a pushed config.yaml the website would refuse is
// refused, and the running config stays.
func TestPushedConfigApplies(t *testing.T) {
	p := newPushEnv(t)
	main := filepath.Dir(filepath.Dir(p.repo.Dir))
	in := func(args ...string) (string, error) {
		cmd := exec.Command("git", append([]string{"-C", p.clone, "-c", "user.name=dora", "-c", "user.email=dora@yars.local", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	dora := strings.Replace(p.url, "http://", "http://dora:pw@", 1) + "/git/yars"
	push := func(body string) (string, error) {
		os.WriteFile(filepath.Join(p.clone, ".yars", "config.yaml"), []byte(body), 0o644)
		if out, err := in("commit", "-qm", "config", "--", ".yars/config.yaml"); err != nil {
			t.Fatalf("%v %s", err, out)
		}
		return in("push", dora, "HEAD:main")
	}
	if out, err := push("sections: [Description, Impact, Proof]\n"); err != nil {
		t.Fatalf("config push: %v\n%s", err, out)
	}
	if got := p.st.Config().Sections; !slices.Equal(got, []string{"Description", "Impact", "Proof"}) {
		t.Fatalf("sections after the push: %v", got)
	}
	out, err := push("sections: [Description, Impact, impact]\n")
	if err == nil || !strings.Contains(out, `.yars/config.yaml: Sections: "impact" twice`) {
		t.Fatalf("bad config: %v\n%s", err, out)
	}
	if got := p.st.Config().Sections; len(got) != 3 || got[2] != "Proof" {
		t.Fatalf("running config changed by a refused push: %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(main, ".yars", "config.yaml")); !strings.Contains(string(b), "Proof") {
		t.Fatalf("server config.yaml: %s", b)
	}
}

func TestPushForceRejected(t *testing.T) {
	p := newPushEnv(t)
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "one") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	p.git("reset", "-q", "--hard", "HEAD~1")
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "rewritten") })
	// refused for what it is (backlog, M6)
	if out, err := p.git("push", "--force", "origin", "HEAD"); err == nil || !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("force push: %v\n%s", err, out)
	}
}

// Deleting the branch and pushing a tag are refused end to end, each with
// its reason (backlog, M6).
func TestPushDeleteAndTagRefused(t *testing.T) {
	p := newPushEnv(t)
	if out, err := p.git("push", "origin", ":main"); err == nil || !strings.Contains(out, "deleting the branch is not allowed") {
		t.Fatalf("branch delete: %v\n%s", err, out)
	}
	if out, err := p.git("tag", "v1"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := p.git("push", "origin", "v1"); err == nil || !strings.Contains(out, "refs/tags/v1: only refs/heads/main can be pushed") {
		t.Fatalf("tag push: %v\n%s", err, out)
	}
}
