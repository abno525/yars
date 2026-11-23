package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/workflow"
)

// initSimple sets up a data folder with the simple workflow.
func initSimple(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	if err := cmdInitOut([]string{"--simple", dir}, &out); err != nil {
		t.Fatal(err)
	}
	return dir
}

// yars init --simple writes the workflow key at the top of config.yaml and
// the database setting, commits the config, and says which workflow it set
// up; the flag goes before the folder.
func TestInitSimple(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := cmdInitOut([]string{"--simple", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "initialised "+dir+" (simple workflow)\n" {
		t.Errorf("output %q", got)
	}
	b, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil || !strings.HasPrefix(string(b), "workflow: simple\n") {
		t.Fatalf("config.yaml %v:\n%s", err, b)
	}
	cfg, err := config.Load(dir)
	if err != nil || !cfg.Simple() {
		t.Fatalf("config %+v %v", cfg, err)
	}
	if w, err := openDB(t, dir).Setting("workflow"); w != "simple" || err != nil {
		t.Fatalf("database setting %q %v", w, err)
	}
	if shown, err := exec.Command("git", "-C", dir, "show", "HEAD:.yars/config.yaml").Output(); err != nil || string(shown) != string(b) {
		t.Fatalf("committed config %v:\n%s", err, shown)
	}
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(st) != 0 {
		t.Fatalf("not clean after init:\n%s", st)
	}
	// a flag after the folder is not taken for a second folder, and nothing
	// is set up
	late := t.TempDir()
	if err := cmdInitOut([]string{late, "--simple"}, &out); err == nil || !strings.Contains(err.Error(), "flags go before the folder") {
		t.Fatalf("flag after the folder: %v", err)
	}
	if _, err := os.Stat(config.ConfigPath(late)); err == nil {
		t.Fatal("a folder was set up")
	}
}

// handEdit commits config.yaml as body in the data folder, as an admin's
// edit on the server would land (an uncommitted one is put back to HEAD on
// start).
func handEdit(t *testing.T, dir string, body []byte) {
	t.Helper()
	if err := os.WriteFile(config.ConfigPath(dir), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", dir, "-c", "user.name=x", "-c", "user.email=x@x", "-c", "commit.gpgsign=false",
		"commit", "-qam", "hand edit").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

// serve does not start when config.yaml's workflow is not the one yars init
// set up (its database setting), whichever way, and says how to put it
// back; a folder whose two agree starts on its workflow.
func TestServeRefusesWorkflowMismatch(t *testing.T) {
	std, _ := yaml.Marshal(config.Default())
	simple := append([]byte("workflow: simple\n"), std...)

	dir := initSimple(t)
	handEdit(t, dir, std)
	r, _ := gitrepo.Open(dir)
	if _, _, _, err := prepareData(r); err == nil || err.Error() != "config.yaml says workflow standard but this data folder was set up with simple (yars init); put workflow: simple back" {
		t.Fatalf("simple folder, standard config: %v", err) // fatal: yars serve below would serve
	}
	// through yars serve: it stops before it listens
	if err := cmdServe([]string{"--data", dir, "--addr", "127.0.0.1:0"}); err == nil || !strings.Contains(err.Error(), "put workflow: simple back") {
		t.Errorf("yars serve: %v", err)
	}

	dir = t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	handEdit(t, dir, simple)
	r, _ = gitrepo.Open(dir)
	if _, _, _, err := prepareData(r); err == nil || err.Error() != "config.yaml says workflow simple but this data folder was set up with standard (yars init); put workflow: standard back" {
		t.Errorf("standard folder, simple config: %v", err)
	}

	r, _ = gitrepo.Open(initSimple(t))
	cfg, d, st, err := prepareData(r)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !cfg.Simple() || !st.Flow().Simple {
		t.Fatalf("a simple folder starts on %s", st.Flow().Name())
	}
}

// A data folder whose database is missing (yars.db deleted, or the folder
// copied without it) gets a new one that holds no accounts or states yet:
// it takes the workflow config.yaml names, as yars init records it. A
// simple folder then refuses roles and starts on the simple workflow; a
// standard one stays standard.
func TestNewDatabaseTakesConfigWorkflow(t *testing.T) {
	dropDB := func(dir string) {
		for _, p := range []string{db.Path(dir), db.Path(dir) + "-wal", db.Path(dir) + "-shm"} {
			os.Remove(p)
		}
		if _, err := os.Stat(db.Path(dir)); err == nil {
			t.Fatal("yars.db still there")
		}
	}
	start := func(dir string) (config.Config, *db.DB, *store.Store) {
		t.Helper()
		r, _ := gitrepo.Open(dir)
		cfg, d, st, err := prepareData(r)
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		t.Cleanup(func() { d.Close() })
		return cfg, d, st
	}

	dir := initSimple(t)
	dropDB(dir)
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--data", dir, "--role", "pentester", "carl"}, strings.NewReader("pw\n"), &out); err == nil || err.Error() != "the simple workflow has no roles" {
		t.Errorf("useradd --role pentester on a new database: %v", err)
	}

	dir = initSimple(t)
	dropDB(dir)
	cfg, d, st := start(dir)
	if !cfg.Simple() || !st.Flow().Simple {
		t.Errorf("a simple folder with a new database starts on %s", st.Flow().Name())
	}
	if w, err := d.Setting("workflow"); w != "simple" || err != nil {
		t.Errorf("the new database's setting %q %v", w, err)
	}

	dir = t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	dropDB(dir)
	cfg, d, st = start(dir)
	if cfg.Simple() || st.Flow().Simple {
		t.Errorf("a standard folder with a new database starts on %s", st.Flow().Name())
	}
	if w, err := d.Setting("workflow"); w != "" || err != nil {
		t.Errorf("standard: the new database's setting %q %v", w, err)
	}
}

// In the simple workflow useradd stores a director, with --role director or
// without --role; any other role is refused. Its output and audit name the
// admin flag only.
func TestUseraddSimple(t *testing.T) {
	dir := initSimple(t)
	add := func(args ...string) (string, error) {
		var out bytes.Buffer
		err := cmdUseradd(append([]string{"--data", dir}, args...), strings.NewReader("pw\n"), &out)
		return out.String(), err
	}
	for want, args := range map[string][]string{
		"password: \nadded anna (admin)\n": {"--admin", "anna"},
		"password: \nadded ben\n":          {"ben"},
		"password: \nadded dave\n":         {"--role", "director", "dave"},
	} {
		if out, err := add(args...); err != nil || out != want {
			t.Errorf("%v: %q %v", args, out, err)
		}
	}
	for _, args := range [][]string{{"--role", "pentester", "carl"}, {"--role", "reviewer", "--admin", "eve"}, {"--role", "admin", "fay"}} {
		if _, err := add(args...); err == nil || err.Error() != "the simple workflow has no roles" {
			t.Errorf("%v: %v", args, err)
		}
	}
	d := openDB(t, dir)
	for name, admin := range map[string]bool{"anna": true, "ben": false, "dave": false} {
		if u, ok, _ := d.User(name); !ok || u.Role != "director" || u.IsAdmin != admin {
			t.Errorf("%s: %+v", name, u)
		}
	}
	for _, name := range []string{"carl", "eve", "fay"} {
		if _, ok, _ := d.User(name); ok {
			t.Errorf("%s added", name)
		}
	}
	l, _ := d.AuditLog(10)
	details := map[string]string{}
	for _, e := range l {
		if e.Action == "user.add" {
			details[e.Target] = e.Detail
		}
	}
	if len(details) != 3 || details["anna"] != "admin" || details["ben"] != "" || details["dave"] != "" {
		t.Fatalf("audit %+v", l)
	}
}

// yars role is refused in the simple workflow, whatever the role; the
// account stays a director.
func TestRoleRefusedSimple(t *testing.T) {
	dir := initSimple(t)
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--data", dir, "ben"}, strings.NewReader("pw\n"), &out); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"pentester", "director"} {
		if err := cmdRole([]string{"--data", dir, "ben", role}, &out); err == nil || err.Error() != "the simple workflow has no roles" {
			t.Errorf("%s: %v", role, err)
		}
	}
	d := openDB(t, dir)
	if u, _, _ := d.User("ben"); u.Role != "director" {
		t.Fatalf("ben is a %s", u.Role)
	}
	if l, _ := d.AuditLog(10); len(l) != 1 || l[0].Action != "user.add" {
		t.Fatalf("audit %+v", l)
	}
}

// yars mcp on a clone of a simple-workflow folder serves as a director: an
// explicit --role other than director is refused; without one (the
// standard default, pentester, is no choice) the account is a director.
func TestMCPRoleSimple(t *testing.T) {
	dir := initSimple(t)
	hello := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	var out bytes.Buffer
	if err := runMCP([]string{"--data", dir, "--user", "ben", "--role", "reviewer"}, strings.NewReader(hello), &out); err == nil || err.Error() != "the simple workflow has no roles" {
		t.Fatalf("--role reviewer: %v", err)
	}
	for _, args := range [][]string{{"--data", dir, "--user", "ben"}, {"--data", dir, "--user", "ben", "--role", "director"}} {
		out.Reset()
		if err := runMCP(args, strings.NewReader(hello), &out); err != nil || !strings.Contains(out.String(), `"serverInfo"`) {
			t.Fatalf("%v: %v %s", args, err, out.String())
		}
	}
	simple := config.Default()
	simple.Workflow = config.WorkflowSimple
	for _, c := range []struct {
		cfg   config.Config
		given bool
		role  string
		want  string
	}{
		{simple, false, "pentester", "director"},
		{simple, true, "director", "director"},
		{config.Default(), false, "pentester", "pentester"},
		{config.Default(), true, "reviewer", "reviewer"},
	} {
		u, err := mcpUser(c.cfg, c.given, config.User{Username: "ben", Role: c.role, Email: "b@x"})
		if err != nil || u.Role != c.want || u.Username != "ben" || u.Email != "b@x" {
			t.Errorf("%s, --role %s given %v: %+v %v", c.cfg.Workflow, c.role, c.given, u, err)
		}
	}
	if _, err := mcpUser(simple, true, config.User{Username: "ben", Role: "pentester"}); err == nil {
		t.Error("simple, --role pentester accepted")
	}
}

// yars seed --simple builds a data folder of the simple workflow that
// starts (config.yaml and the database agree), with two directors and the
// simple workflow's states only.
func TestSeedSimple(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	var out bytes.Buffer
	if err := cmdSeed([]string{"--simple", "--data", dir, "--engagements", "2", "--findings", "12", "--messages", "10"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `; users dir1, dir2 (password "password")`) {
		t.Errorf("output %q", out.String())
	}
	r, _ := gitrepo.Open(dir)
	cfg, d, st, err := prepareData(r)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !cfg.Simple() || !st.Flow().Simple {
		t.Fatalf("seeded folder runs the %s workflow", st.Flow().Name())
	}
	users, _ := d.Users()
	if len(users) != 2 {
		t.Fatalf("users %+v", users)
	}
	for _, u := range users {
		if u.Role != "director" || u.IsAdmin != (u.Username == "dir1") {
			t.Errorf("user %+v", u)
		}
	}
	for _, e := range []string{"e001", "e002"} {
		refs, err := st.ListFindings(e)
		if err != nil || len(refs) != 12 {
			t.Fatalf("%s: %d findings %v", e, len(refs), err)
		}
		for _, ref := range refs {
			if s := ref.F.Meta.Status; !slices.Contains(workflow.Flow{Simple: true}.AllStatuses(), s) || len(ref.F.Meta.Reviewers) != 0 {
				t.Errorf("%s/%s: %s, reviewers %v", e, ref.F.Meta.ID, s, ref.F.Meta.Reviewers)
			}
		}
	}
}

// With the server's config.yaml broken past reading (the hook then runs on
// the defaults), the workflow is still the one yars init set up: in a
// simple folder a repair that keeps workflow: simple is accepted, and one
// that drops it is refused.
func TestHookBrokenConfigKeepsSimple(t *testing.T) {
	dir := initSimple(t)
	if err := openDB(t, dir).AddUser(config.User{Username: "anna", Role: "director", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	run := func(in string, args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", in, "-c", "user.name=anna", "-c", "user.email=anna@yars.local", "-c", "commit.gpgsign=false"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	os.WriteFile(config.ConfigPath(dir), []byte("workflow: simple\nseverities: [x\n"), 0o644)
	run(dir, "commit", "-qam", "broken")
	old := run(dir, "rev-parse", "HEAD")
	clone := filepath.Join(t.TempDir(), "clone")
	if out, err := exec.Command("git", "clone", "-q", dir, clone).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	t.Setenv("REMOTE_USER", "anna")
	for body, ok := range map[string]bool{"workflow: simple\n": true, "severities: [critical, high, medium, low, info]\n": false} {
		run(clone, "reset", "-q", "--hard", old)
		os.WriteFile(filepath.Join(clone, ".yars", "config.yaml"), []byte(body), 0o644)
		run(clone, "commit", "-qam", "repair")
		rev := run(clone, "rev-parse", "HEAD")
		run(dir, "fetch", "-q", clone, "+HEAD:refs/test/candidate")
		var out bytes.Buffer
		code := cmdHook([]string{"pre-receive", "--data", dir}, strings.NewReader(old+" "+rev+" refs/heads/main\n"), &out)
		if (code == 0) != ok || (!ok && !strings.Contains(out.String(), "(this server runs the simple workflow) and cannot change")) {
			t.Errorf("repair %q: code %d\n%s", body, code, out.String())
		}
	}
}

// hookPush commits edit in a fresh clone of the data folder dir's main repo
// (eng "") or of engagements/<eng>, as account as, and runs the pre-receive
// hook on pushing it: its exit code and output.
func hookPush(t *testing.T, dir, eng, as string, edit func(clone string)) (int, string) {
	t.Helper()
	repo, args := dir, []string{"pre-receive", "--data", dir}
	if eng != "" {
		repo, args = filepath.Join(dir, "engagements", eng), append(args, "--eng", eng)
	}
	run := func(in string, a ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", in, "-c", "user.name=" + as, "-c", "user.email=" + as + "@yars.local", "-c", "commit.gpgsign=false"}, a...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", a, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	clone := filepath.Join(t.TempDir(), "clone")
	run(repo, "clone", "-q", repo, clone)
	edit(clone)
	run(clone, "commit", "-qam", "change")
	rev := run(clone, "rev-parse", "HEAD")
	run(repo, "fetch", "-q", "--no-recurse-submodules", clone, "+HEAD:refs/test/candidate")
	old, branch := run(repo, "rev-parse", "HEAD"), run(repo, "symbolic-ref", "HEAD")
	t.Setenv("REMOTE_USER", as)
	var out bytes.Buffer
	code := cmdHook(args, strings.NewReader(old+" "+rev+" "+branch+"\n"), &out)
	return code, out.String()
}

// The hook runs a push on the workflow the database records, which is the
// one the running server keeps, not on config.yaml's: after a hand edit on
// the server drops workflow: simple, a draft's rule error still holds back
// Complete, and the push that puts the key back is accepted; on a standard
// folder whose file gained workflow: simple, the push that drops it is.
func TestHookWorkflowFromDatabase(t *testing.T) {
	std, _ := yaml.Marshal(config.Default())
	simple := append([]byte("workflow: simple\n"), std...)
	setConfig := func(body []byte) func(string) {
		return func(c string) { os.WriteFile(filepath.Join(c, ".yars", "config.yaml"), body, 0o644) }
	}

	dir := initSimple(t)
	d := openDB(t, dir)
	if err := d.AddUser(config.User{Username: "anna", Role: "director", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(dir)
	r, _ := gitrepo.Open(dir)
	st := store.New(r, cfg, d)
	a := gitrepo.Author{Name: "anna", Email: "anna@yars.local"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a); err != nil {
		t.Fatal(err)
	}
	ref, err := st.CreateFinding("acme", "SQL injection", a)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(rules.DirFor(dir), 0o755)
	os.WriteFile(filepath.Join(rules.DirFor(dir), "style.yaml"), []byte("- id: no-todo\n  regex_forbid: TODO\n  message: No TODO left\n"), 0o644)
	handEdit(t, dir, std)

	code, out := hookPush(t, dir, "acme", "anna", func(c string) {
		p := filepath.Join(c, "findings", ref.Dir, "finding.md")
		b, _ := os.ReadFile(p)
		f, err := finding.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		f.SetSection("Impact", "TODO later")
		os.WriteFile(p, f.Bytes(), 0o644)
	})
	if code != 0 || !strings.Contains(out, "check no-todo (error; blocks Complete): No TODO left") {
		t.Errorf("a draft's rule error after the hand edit: code %d\n%s", code, out)
	}
	if code, out := hookPush(t, dir, "", "anna", setConfig(simple)); code != 0 {
		t.Errorf("workflow: simple put back after the hand edit: code %d\n%s", code, out)
	}

	sdir := t.TempDir()
	if err := initData(sdir); err != nil {
		t.Fatal(err)
	}
	if err := openDB(t, sdir).AddUser(config.User{Username: "dora", Role: "director", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	handEdit(t, sdir, simple)
	if code, out := hookPush(t, sdir, "", "dora", setConfig(std)); code != 0 {
		t.Errorf("standard folder, the hand edit's workflow: simple dropped: code %d\n%s", code, out)
	}
}

// yars export --mark in the simple workflow: any account marks the exported
// complete findings reported, and a missing --as names no role.
func TestExportMarkSimple(t *testing.T) {
	dir := initSimple(t)
	d := openDB(t, dir)
	if err := d.AddUser(config.User{Username: "ben", Role: "director"}); err != nil {
		t.Fatal(err)
	}
	r, _ := gitrepo.Open(dir)
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(r, cfg, d)
	a := gitrepo.Author{Name: "ben", Email: "ben@yars.local"}
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	ref, err := st.CreateFinding("acme", "SQL injection", a)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "engagements", "acme", "findings", ref.Dir, "finding.md"))
	if err := d.TxFor("acme", func(tx *db.Tx) error {
		return tx.PutState("acme", "F-001", db.State{Status: "complete", ApprovedHash: store.ContentHash(raw)})
	}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "r.html")
	var log bytes.Buffer
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "--mark", "acme"}, &log); code != 2 || err == nil || err.Error() != "--mark needs --as <account>" {
		t.Fatalf("no --as: code %d err %v", code, err)
	}
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "--mark", "--as", "ben", "acme"}, &log); code != 0 || err != nil || !strings.Contains(log.String(), "marked reported F-001") {
		t.Fatalf("code %d err %v: %s", code, err, log.String())
	}
	if s, _ := d.State("acme", "F-001"); s.Status != "reported" {
		t.Fatalf("F-001 is %s", s.Status)
	}
}

// yars init without --simple writes the same config.yaml as before (no
// workflow key), no database setting, and says what it always said.
func TestInitStandardUnchanged(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := cmdInitOut([]string{dir}, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "initialised "+dir+"\n" {
		t.Errorf("output %q", got)
	}
	want, _ := yaml.Marshal(config.Default())
	b, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil || string(b) != string(want) || strings.Contains(string(b), "workflow") {
		t.Fatalf("config.yaml %v:\n%s", err, b)
	}
	if cfg, _ := config.Load(dir); cfg.Simple() {
		t.Fatal("standard init runs the simple workflow")
	}
	if w, err := openDB(t, dir).Setting("workflow"); w != "" || err != nil {
		t.Fatalf("database setting %q %v", w, err)
	}
	// initData, which tests call, is the standard init
	other := t.TempDir()
	if err := initData(other); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(config.ConfigPath(other)); string(b2) != string(want) {
		t.Fatalf("initData config:\n%s", b2)
	}
}
