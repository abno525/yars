package index

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
	"yars/internal/workflow"
)

var alice = gitrepo.Author{Name: "alice", Email: "a@x"}

// setMeta rewrites a finding's severity directly on disk and commits it (the
// way a local editor would) and sets its status in the database.
func setMeta(t *testing.T, s *store.Store, eng, dir, status, sev string) {
	t.Helper()
	ref, err := s.Finding(eng, dir)
	if err != nil {
		t.Fatal(err)
	}
	ref.F.Meta.Severity = sev
	er, err := s.EngRepo(eng)
	if err != nil {
		t.Fatal(err)
	}
	rel := filepath.Join("findings", dir, "finding.md")
	if err := os.WriteFile(filepath.Join(er.Dir, rel), ref.F.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := er.Commit([]string{rel}, "meta", alice); err != nil {
		t.Fatal(err)
	}
	s.Invalidate(eng) // as the git server does after a push
	setStatus(t, s, eng, ref.F.Meta.ID, status)
}

func setStatus(t *testing.T, s *store.Store, eng, fid, status string) {
	t.Helper()
	if err := s.DB().Tx(func(tx *db.Tx) error { return tx.PutState(eng, fid, db.State{Status: status}) }); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) (*Index, *store.Store) {
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
	s := store.New(r, config.Default(), d)
	for _, e := range []string{"acme", "other"} {
		if err := s.CreateEngagement(store.Engagement{ID: e, Name: e}, alice); err != nil {
			t.Fatal(err)
		}
	}
	data := []struct{ title, status, sev string }{
		{"A", "reported", "low"},
		{"B", "draft", "critical"},
		{"C", "verification", "medium"},
	}
	for _, d := range data {
		f, err := s.CreateFinding("acme", d.title, alice)
		if err != nil {
			t.Fatal(err)
		}
		setMeta(t, s, "acme", f.Dir, d.status, d.sev)
	}
	if _, err := s.CreateFinding("other", "Z", alice); err != nil {
		t.Fatal(err)
	}
	return New(s, r), s
}

func titles(rows []Row) string {
	var t []string
	for _, r := range rows {
		t = append(t, r.Title)
	}
	return strings.Join(t, ",")
}

// Since is the time of the last workflow event; plain messages don't count.
func TestRowSince(t *testing.T) {
	_, s := fixture(t)
	refs, err := s.ListFindings("other")
	if err != nil || len(refs) != 1 {
		t.Fatal(refs, err)
	}
	if r := rowOf("other", refs[0], nil); !r.Since.IsZero() {
		t.Fatalf("since without events %v", r.Since)
	}
	t1 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	msgs := []chat.Message{
		{ID: "a", TS: t1.Add(-time.Hour), Event: "submit"},
		{ID: "b", TS: t1, Event: "clear"},
		{ID: "c", TS: t1.Add(time.Hour), Text: "hi"},
	}
	if r := rowOf("other", refs[0], msgs); !r.Since.Equal(t1) {
		t.Fatalf("since %v", r.Since)
	}
}

// Rows and the engagement list honour a visible set (a user's teams); nil
// shows every engagement.
func TestVisibleSet(t *testing.T) {
	ix, s := fixture(t)
	if rows, _ := ix.Rows(Query{Visible: map[string]bool{"other": true}}); titles(rows) != "Z" {
		t.Fatalf("got %q", titles(rows))
	}
	if rows, _ := ix.Rows(Query{EngID: "acme", Visible: map[string]bool{"other": true}}); len(rows) != 0 {
		t.Fatalf("hidden engagement by id: %q", titles(rows))
	}
	if rows, _ := ix.Rows(Query{Visible: map[string]bool{}}); len(rows) != 0 {
		t.Fatalf("empty set: %q", titles(rows))
	}
	es, _ := ix.EngagementsFor(map[string]bool{"acme": true})
	if len(es) != 1 || es[0].ID != "acme" {
		t.Fatalf("engagements %+v", es)
	}
	if all, _ := ix.EngagementsFor(nil); len(all) != 2 {
		t.Fatalf("all %+v", all)
	}
	// archiving reloads the engagement, which then says so
	s.DB().Archive("acme", "dora")
	if e, ok := ix.Engagement("acme"); !ok || !e.Archived {
		t.Fatalf("archive not seen: %+v", e)
	}
}

// D23: Text keeps the rows whose ID, title or an asset's host or URL holds
// it, in any letter case.
func TestRowsTextMatchesIDTitleAsset(t *testing.T) {
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s := store.New(r, config.Default(), d)
	if err := s.CreateEngagement(store.Engagement{ID: "acme", Name: "acme"}, alice); err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, title := range []string{"SQL injection", "Stored XSS", "Open redirect"} {
		f, err := s.CreateFinding("acme", title, alice)
		if err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, f.Dir)
	}
	if err := s.UpdateAssets("acme", dirs[2], []finding.Asset{{Host: "app.example", URL: "https://app.example/go"}}, "", alice); err != nil {
		t.Fatal(err)
	}
	ix := New(s, r)
	for text, want := range map[string]string{
		"sql":           "SQL injection",
		"SQL INJ":       "SQL injection",
		"f-002":         "Stored XSS",
		"app.example":   "Open redirect",
		"APP.EXAMPLE/G": "Open redirect",
		"zzz":           "",
		"":              "SQL injection,Stored XSS,Open redirect",
	} {
		rows, err := ix.Rows(Query{EngID: "acme", Text: text})
		if err != nil || titles(rows) != want {
			t.Errorf("Text %q: %q %v, want %q", text, titles(rows), err, want)
		}
	}
}

func TestFilterByEngagementAndStatus(t *testing.T) {
	ix, _ := fixture(t)
	rows, err := ix.Rows(Query{EngID: "acme"})
	if err != nil || titles(rows) != "A,B,C" {
		t.Fatalf("got %q %v", titles(rows), err)
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Status: "draft"})
	if titles(rows) != "B" {
		t.Fatalf("got %q", titles(rows))
	}
}

// Withdrawn findings leave the default list and show only under their filter.
func TestWithdrawnOnlyUnderFilter(t *testing.T) {
	ix, s := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme"})
	setStatus(t, s, "acme", rows[1].ID, "withdrawn")
	if rows, _ := ix.Rows(Query{EngID: "acme"}); titles(rows) != "A,C" {
		t.Fatalf("default list %q", titles(rows))
	}
	if rows, _ := ix.Rows(Query{EngID: "acme", Status: "withdrawn"}); titles(rows) != "B" {
		t.Fatalf("withdrawn filter %q", titles(rows))
	}
	if StatusOrder[len(StatusOrder)-1] != "withdrawn" {
		t.Fatalf("status order %v", StatusOrder)
	}
}

// Keep holds rows in the list whatever their status (after a bulk change,
// the rows it moved stay in a status-filtered list); other filters apply.
func TestQueryKeep(t *testing.T) {
	ix, s := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme"})
	b := rows[1]
	setStatus(t, s, "acme", b.ID, "withdrawn")
	keep := map[string]bool{b.Dir: true}
	if got, _ := ix.Rows(Query{EngID: "acme", Shown: "reported", Keep: keep}); titles(got) != "A,B" {
		t.Fatalf("kept in a filtered list %q", titles(got))
	}
	if got, _ := ix.Rows(Query{EngID: "acme", Keep: keep}); titles(got) != "A,B,C" {
		t.Fatalf("kept withdrawn in the default list %q", titles(got))
	}
	if got, _ := ix.Rows(Query{EngID: "acme", Shown: "reported", Severity: "nope", Keep: keep}); len(got) != 0 {
		t.Fatalf("keep skipped another filter %q", titles(got))
	}
}

// A verification finding whose every reviewer signed off shows as signed
// off: its own filter, its own count, sorted between verification and
// complete. The stored status, and a Status query, stay verification.
func TestSignedOffShown(t *testing.T) {
	ix, s := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme"})
	c := rows[2] // C, verification
	f, _ := s.CreateFinding("acme", "D", alice)
	setMeta(t, s, "acme", f.Dir, "verification", "low")
	bob := config.User{Username: "bob", Role: "reviewer"}
	if err := s.SetReviewers("acme", c.Dir, []string{"bob"}, config.User{Username: "alice", Role: "pentester"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition("acme", c.Dir, workflow.Clear, "", bob); err != nil {
		t.Fatal(err)
	}
	rows, _ = ix.Rows(Query{EngID: "acme"})
	shown := map[string]string{}
	for _, r := range rows {
		shown[r.Title] = r.Shown
	}
	if shown["C"] != workflow.SignedOff || shown["D"] != "verification" || shown["A"] != "reported" {
		t.Fatalf("shown %v", shown)
	}
	if rows, _ := ix.Rows(Query{EngID: "acme", Status: "verification"}); titles(rows) != "C,D" {
		t.Fatalf("status query %q", titles(rows))
	}
	if rows, _ := ix.Rows(Query{EngID: "acme", Shown: workflow.SignedOff}); titles(rows) != "C" {
		t.Fatalf("signed off filter %q", titles(rows))
	}
	if rows, _ := ix.Rows(Query{EngID: "acme", Shown: "verification"}); titles(rows) != "D" {
		t.Fatalf("verification filter %q", titles(rows))
	}
	if rows, _ := ix.Rows(Query{EngID: "acme", Sort: "status"}); titles(rows) != "B,D,C,A" {
		t.Fatalf("status sort %q", titles(rows))
	}
	sum, _ := ix.Summary("acme")
	if sum.ByStatus["verification"] != 2 || sum.ByShown["verification"] != 1 || sum.ByShown[workflow.SignedOff] != 1 {
		t.Fatalf("counts %v %v", sum.ByStatus, sum.ByShown)
	}
	var keys []string
	for _, c := range sum.Statuses {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, ",") != "draft,verification,signed-off,complete,reported,withdrawn" || sum.Statuses[2].N != 1 || sum.Statuses[2].Pct != 25 {
		t.Fatalf("statuses %+v", sum.Statuses)
	}
}

func TestSummary(t *testing.T) {
	ix, s := fixture(t)
	f, _ := s.CreateFinding("acme", "D", alice)
	setMeta(t, s, "acme", f.Dir, "complete", "high")
	f, _ = s.CreateFinding("acme", "E", alice)
	setMeta(t, s, "acme", f.Dir, "withdrawn", "critical")
	// A reported/low, B draft/critical, C verification/medium, D complete/high, E withdrawn/critical
	sum, err := ix.Summary("acme")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 4 || sum.Withdrawn != 1 || sum.Done != 2 || sum.Progress != 50 {
		t.Fatalf("summary %+v", sum)
	}
	want := map[string]int{"draft": 1, "verification": 1, "complete": 1, "reported": 1, "withdrawn": 1}
	for k, n := range want {
		if sum.ByStatus[k] != n {
			t.Errorf("status %s: %d want %d", k, sum.ByStatus[k], n)
		}
	}
	if sum.BySeverity["critical"] != 1 || sum.BySeverity["high"] != 1 || sum.BySeverity["low"] != 1 || sum.BySeverity["medium"] != 1 {
		t.Errorf("severity %v", sum.BySeverity)
	}
	if len(sum.Statuses) != 6 || sum.Statuses[0].Key != "draft" || sum.Statuses[5].Key != "withdrawn" || sum.Statuses[5].N != 1 {
		t.Errorf("ordered statuses %+v", sum.Statuses)
	}
	if len(sum.Severities) == 0 || sum.Severities[0].Key != "critical" || sum.Severities[0].N != 1 || sum.Severities[0].Pct != 25 {
		t.Errorf("ordered severities %+v", sum.Severities)
	}
	// cached for the generation, recomputed after a change
	builds := ix.summaryBuilds.Load()
	if again, _ := ix.Summary("acme"); again.Total != 4 || ix.summaryBuilds.Load() != builds {
		t.Fatal("summary not cached for the generation")
	}
	setStatus(t, s, "acme", f.F.Meta.ID, "draft")
	if sum, _ := ix.Summary("acme"); sum.Total != 5 || sum.Withdrawn != 0 || sum.Progress != 40 {
		t.Fatalf("after restore %+v", sum)
	}
	if sum, _ := ix.Summary("other"); sum.Total != 1 || sum.Progress != 0 {
		t.Fatalf("other %+v", sum)
	}
	if sum, _ := ix.Summary("none"); sum.Total != 0 || sum.Progress != 0 {
		t.Fatalf("unknown %+v", sum)
	}
}

func TestSortStatusWorkflowOrder(t *testing.T) {
	ix, _ := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "status"})
	if titles(rows) != "B,C,A" {
		t.Fatalf("got %q", titles(rows))
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Sort: "status", Desc: true})
	if titles(rows) != "A,C,B" {
		t.Fatalf("desc got %q", titles(rows))
	}
}

func TestSortIDDesc(t *testing.T) {
	ix, _ := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "id", Desc: true})
	if titles(rows) != "C,B,A" {
		t.Fatalf("got %q", titles(rows))
	}
}

func TestSortSeverityOrder(t *testing.T) {
	ix, _ := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "severity"})
	if titles(rows) != "B,C,A" {
		t.Fatalf("got %q", titles(rows))
	}
}

// setCVSS writes cvss + severity directly (no derivation), like a local edit.
func setCVSS(t *testing.T, s *store.Store, eng, dir, vec, sev string) {
	t.Helper()
	ref, err := s.Finding(eng, dir)
	if err != nil {
		t.Fatal(err)
	}
	ref.F.Meta.CVSS, ref.F.Meta.Severity = vec, sev
	er, _ := s.EngRepo(eng)
	rel := filepath.Join("findings", dir, "finding.md")
	os.WriteFile(filepath.Join(er.Dir, rel), ref.F.Bytes(), 0o644)
	if err := er.Commit([]string{rel}, "cvss", alice); err != nil {
		t.Fatal(err)
	}
	s.Invalidate(eng)
}

func byTitle(t *testing.T, rows []Row, title string) Row {
	for _, r := range rows {
		if r.Title == title {
			return r
		}
	}
	t.Fatalf("no row %s", title)
	return Row{}
}

func TestRowsDeriveSeverity(t *testing.T) {
	ix, s := fixture(t)
	setCVSS(t, s, "acme", "F-001-a", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "low")
	rows, _ := ix.Rows(Query{EngID: "acme"})
	if r := byTitle(t, rows, "A"); r.Severity != "critical" || r.Score != "9.8" {
		t.Fatalf("row %+v", r)
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Severity: "critical"})
	if titles(rows) != "A,B" {
		t.Fatalf("filter got %q", titles(rows))
	}
}

func TestRowsForeignCVSS(t *testing.T) {
	ix, s := fixture(t)
	setCVSS(t, s, "acme", "F-001-a", "8.1", "medium")
	rows, _ := ix.Rows(Query{EngID: "acme"})
	if r := byTitle(t, rows, "A"); r.Severity != "medium" || r.Score != "" {
		t.Fatalf("row %+v", r)
	}
}

func TestSortByCVSS(t *testing.T) {
	ix, s := fixture(t)
	setCVSS(t, s, "acme", "F-001-a", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "")
	setCVSS(t, s, "acme", "F-003-c", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", "")
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "cvss"})
	if titles(rows) != "B,C,A" {
		t.Fatalf("asc got %q", titles(rows))
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Sort: "cvss", Desc: true})
	if titles(rows) != "A,C,B" {
		t.Fatalf("desc got %q", titles(rows))
	}
}

func TestRowsOpenThreads(t *testing.T) {
	ix, s := fixture(t)
	u := config.User{Username: "bob", Role: "reviewer"}
	t1, _ := s.PostChat("acme", "F-002-b", chat.Message{Text: "one"}, u)
	s.PostChat("acme", "F-002-b", chat.Message{Text: "two"}, u)
	s.PostChat("acme", "F-002-b", chat.Message{Resolves: t1.ID}, u)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "chat", Desc: true})
	if rows[0].Title != "B" || rows[0].OpenThreads != 1 || rows[1].OpenThreads != 0 {
		t.Fatalf("rows %+v", rows)
	}
}

// A workflow change is a database write with no commit; the index must
// still see it.
func TestStateChangeVisibleWithoutCommit(t *testing.T) {
	ix, s := fixture(t)
	if rows, _ := ix.Rows(Query{EngID: "acme", Status: "complete"}); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
	setStatus(t, s, "acme", "F-002", "complete")
	if rows, _ := ix.Rows(Query{EngID: "acme", Status: "complete"}); titles(rows) != "B" {
		t.Fatalf("got %q", titles(rows))
	}
}

func TestExternalCommitVisible(t *testing.T) {
	ix, s := fixture(t)
	if _, err := ix.Rows(Query{EngID: "acme"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.Repo().Dir, "engagements", "acme", "findings", "F-009-ext")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "finding.md"), []byte("---\nid: F-009\ntitle: Ext\nstatus: draft\n---\n"), 0o644)
	er, _ := s.EngRepo("acme")
	for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "ext"}} {
		if out, err := exec.Command("git", append([]string{"-C", er.Dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	s.Invalidate("acme") // the git server does this after a push
	rows, _ := ix.Rows(Query{EngID: "acme"})
	if titles(rows) != "A,B,C,Ext" {
		t.Fatalf("got %q", titles(rows))
	}
}
