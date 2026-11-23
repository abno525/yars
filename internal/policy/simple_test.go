package policy

import (
	"errors"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// In the simple workflow every account is a director; anna is the admin.
var simpleUsers = []config.User{
	{Username: "anna", Role: "director", IsAdmin: true},
	{Username: "ben", Role: "director"},
}

func simpleCfg() config.Config {
	c := config.Default()
	c.Workflow = config.WorkflowSimple
	return c
}

// newSimpleFx is a server of the simple workflow, its main repo's
// config.yaml as yars init --simple writes it, with the acme engagement and
// anna's finding F-001; pushes go to acme.
func newSimpleFx(t *testing.T) *fx {
	t.Helper()
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	b, _ := yaml.Marshal(simpleCfg())
	write(r.Dir, ".yars/config.yaml", string(b))
	git(t, r.Dir, "add", ".yars/config.yaml")
	git(t, r.Dir, "commit", "-qm", "init")
	st := store.New(r, simpleCfg(), d)
	a := simpleUsers[0].GitAuthor()
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	ref, err := st.CreateFinding("acme", "SQLi", a)
	if err != nil || ref.Dir != "F-001-sqli" {
		t.Fatalf("%v %s", err, ref.Dir)
	}
	d.AddMembers("acme", "anna", "ben")
	f := &fx{t: t, srv: r, st: st, target: "acme", c: &Checker{Cfg: simpleCfg(), Users: simpleUsers, DB: d}}
	f.reclone()
	return f
}

// putState stores st for F-001 as the workflow would have left it.
func (f *fx) putState(st db.State) {
	f.t.Helper()
	if err := f.st.DB().TxFor("acme", func(tx *db.Tx) error { return tx.PutState("acme", "F-001", st) }); err != nil {
		f.t.Fatal(err)
	}
}

// serverRaw is F-001's finding.md as the server's acme repo has it.
func (f *fx) serverRaw() []byte {
	f.t.Helper()
	r, err := f.st.EngRepo("acme")
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := r.Show("HEAD", fdir+"/finding.md")
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// The workflow is set by yars init: a push to config.yaml that changes it
// is refused, whichever way, and one that keeps it is accepted, also when
// the server's file is broken (the hook then runs on the defaults, on the
// server's workflow).
func TestPushRefusesWorkflowChange(t *testing.T) {
	const simpleNo = ".yars/config.yaml: workflow is set by yars init (this server runs the simple workflow) and cannot change"
	f := newSimpleFx(t).on("")
	for _, body := range []string{
		"sections: [Description, Impact, Steps to Reproduce, Remediation, References, Notes]\n", // the key removed
		"workflow: standard\n",
		"",
	} {
		f.reclone()
		if ps := f.push("anna", func(d string) { write(d, ".yars/config.yaml", body) }); !has(ps, simpleNo) {
			t.Errorf("simple server, config %q: %v", body, ps)
		}
	}
	f.reclone()
	if ps := f.push("anna", func(d string) {
		write(d, ".yars/config.yaml", "workflow: simple\nsections: [Description, Impact, Steps to Reproduce, Remediation, References, Notes]\n")
	}); len(ps) != 0 {
		t.Fatalf("simple server, the key kept, the sections changed: %v", ps)
	}

	// the old file does not load (Checker on the defaults, on the server's
	// workflow, as the hook runs then)
	write(f.srv.Dir, ".yars/config.yaml", "workflow: simple\nseverities: [critical, high]\n")
	git(t, f.srv.Dir, "commit", "-qam", "broken")
	f.c.Cfg, f.c.ConfigErr = simpleCfg(), errors.New("severities: critical, high, medium, low and info are required")
	f.reclone()
	if ps := f.push("anna", func(d string) { write(d, ".yars/config.yaml", "severities: [critical, high, medium, low, info]\n") }); !has(ps, simpleNo) {
		t.Errorf("a broken simple config repaired without the key: %v", ps)
	}
	f.reclone()
	if ps := f.push("anna", func(d string) { write(d, ".yars/config.yaml", "workflow: simple\n") }); len(ps) != 0 {
		t.Errorf("a broken simple config repaired with the key: %v", ps)
	}

	// a standard server: adding the simple workflow is refused
	g := newFx(t).on("")
	if ps := g.push("dora", func(d string) { write(d, ".yars/config.yaml", "workflow: simple\n") }); !has(ps, ".yars/config.yaml: workflow is set by yars init (this server runs the standard workflow) and cannot change") {
		t.Errorf("standard server, simple added: %v", ps)
	}
	g.reclone()
	if ps := g.push("dora", func(d string) { write(d, ".yars/config.yaml", "workflow: standard\n") }); len(ps) != 0 {
		t.Errorf("standard server, the standard key written: %v", ps)
	}
}

// The workflow a pushed config.yaml must name is the one the server runs
// (Cfg), not the one the commit's parent names: in a push of two commits,
// one that drops the key and one that puts it back, only the first is
// refused, naming the server's workflow; and on a server whose config.yaml
// lost the key by a hand edit, the push that puts it back is accepted.
func TestPushWorkflowIsTheServers(t *testing.T) {
	const keep = "sections: [Description, Impact, Steps to Reproduce, Remediation, References, Notes]\n"
	twoCommits := func(f *fx, as string, first, second string) (string, string, []string) {
		t.Helper()
		commit := func(body string) string {
			write(f.clone, ".yars/config.yaml", body)
			git(t, f.clone, "add", "-A")
			git(t, f.clone, "-c", "user.name="+as, "-c", "user.email="+as+"@yars.local", "commit", "-qm", "step")
			return short(t, f.clone, "HEAD")
		}
		a, b := commit(first), commit(second)
		return a, b, f.check(as, git(t, f.clone, "rev-parse", "HEAD"))
	}
	no := func(w string) string {
		return ": workflow is set by yars init (this server runs the " + w + " workflow) and cannot change"
	}

	f := newSimpleFx(t).on("")
	a, b, ps := twoCommits(f, "anna", keep, "workflow: simple\n"+keep)
	if !has(ps, "commit "+a+" .yars/config.yaml"+no("simple")) || has(ps, b) || has(ps, "standard") {
		t.Errorf("simple server, the key dropped then put back: %v", ps)
	}
	g := newFx(t).on("")
	a, b, ps = twoCommits(g, "dora", "workflow: simple\n"+keep, keep)
	if !has(ps, "commit "+a+" .yars/config.yaml"+no("standard")) || has(ps, b) || has(ps, "simple workflow") {
		t.Errorf("standard server, simple added then dropped: %v", ps)
	}

	// a hand edit on the server dropped the key; the server runs simple still
	h := newSimpleFx(t)
	write(h.srv.Dir, ".yars/config.yaml", keep)
	git(t, h.srv.Dir, "commit", "-qam", "hand edit")
	h.on("")
	if ps := h.push("anna", func(d string) { write(d, ".yars/config.yaml", "workflow: simple\n"+keep) }); len(ps) != 0 {
		t.Errorf("the key put back after a hand edit: %v", ps)
	}
	h.reclone()
	if ps := h.push("anna", func(d string) { write(d, ".yars/config.yaml", "severities: [critical, high, medium, low, info]\n") }); !has(ps, ".yars/config.yaml"+no("simple")) {
		t.Errorf("a change that keeps the hand edit's missing key: %v", ps)
	}
}

// In the simple workflow there is nothing to review: a complete finding
// whose content changed after its completion, and a stray verification
// status, read as drafts, as the store reads them.
func TestSimpleStatusDriftIsDraft(t *testing.T) {
	f := newSimpleFx(t)
	raw := f.serverRaw()
	for _, c := range []struct {
		st   db.State
		want string
	}{
		{db.State{Status: "complete", ApprovedHash: "stale"}, "draft"},
		{db.State{Status: "reported", ApprovedHash: "stale"}, "draft"},
		{db.State{Status: "verification", Reviewers: []db.Reviewer{{Name: "ben"}}}, "draft"},
		{db.State{Status: "complete", ApprovedHash: store.ContentHash(raw)}, "complete"},
		{db.State{Status: "reported", ApprovedHash: store.ContentHash(raw)}, "reported"},
		{db.State{Status: "withdrawn"}, "withdrawn"},
	} {
		f.putState(c.st)
		if got := f.c.status("acme", "F-001", raw); got != c.want {
			t.Errorf("%+v: %s, want %s", c.st, got, c.want)
		}
	}
	// the standard workflow reviews a drifted finding again
	f.putState(db.State{Status: "complete", ApprovedHash: "stale"})
	std := &Checker{Cfg: config.Default(), Users: simpleUsers, DB: f.st.DB()}
	if got := std.status("acme", "F-001", raw); got != "verification" {
		t.Errorf("standard, drifted: %s", got)
	}
	// so a drifted finding takes a rule error as a draft does
	f.c.Linter = ruleEngine(t)
	if ps := f.push("ben", func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "TODO later") })
	}); len(ps) != 0 {
		t.Fatalf("a drifted complete finding refused as one in review: %v", ps)
	}
}

// A rule error does not refuse a draft, and the note says what it holds
// back: Complete; on a complete finding it refuses the push.
func TestSimpleRulesMessage(t *testing.T) {
	f := newSimpleFx(t)
	f.c.Linter = ruleEngine(t)
	todo := func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "TODO and FIXME") })
	}
	if ps := f.push("ben", todo); len(ps) != 0 {
		t.Fatalf("draft refused: %v", ps)
	}
	head := short(t, f.clone, "HEAD")
	if !hasLine(f.c.Notes, "commit "+head+" "+fdir+"/finding.md: check no-todo (error; blocks Complete): No TODO left", "") ||
		has(f.c.Notes, "blocks Submit") {
		t.Fatalf("notes %v", f.c.Notes)
	}
	f.putState(db.State{Status: "complete", ApprovedHash: store.ContentHash(f.serverRaw())})
	f.reclone()
	f.c.Notes = nil
	if ps := f.push("ben", todo); !hasLine(ps, "commit "+short(t, f.clone, "HEAD")+" "+fdir+"/finding.md: check no-todo (error): No TODO left", "TODO") {
		t.Fatalf("an error on a complete finding accepted: %v", ps)
	}
}
