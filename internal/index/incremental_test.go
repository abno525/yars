package index

import (
	"fmt"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

var (
	uBob   = config.User{Username: "bob", Role: "reviewer"}
	uAlice = config.User{Username: "alice", Role: "pentester"}
)

func spawns(fn func()) int64 {
	n := gitrepo.Spawned()
	fn()
	return gitrepo.Spawned() - n
}

// Reading the index starts no git process, cold or warm.
func TestRowsStartNoGit(t *testing.T) {
	ix, _ := fixture(t)
	if n := spawns(func() { ix.Rows(Query{}) }); n != 0 {
		t.Fatalf("cold: %d git processes", n)
	}
	if n := spawns(func() { ix.Rows(Query{}); ix.Rows(Query{EngID: "acme"}); ix.Engagements() }); n != 0 {
		t.Fatalf("warm: %d git processes", n)
	}
}

// A chat post or a workflow change through the store updates just that
// finding's row: no engagement is reloaded.
func TestChatAndStateUpdateOneRow(t *testing.T) {
	ix, s := fixture(t)
	ix.Rows(Query{})
	r0 := ix.rebuilds.Load()
	if _, err := s.PostChat("acme", "F-002-b", chat.Message{Text: "q"}, uBob); err != nil {
		t.Fatal(err)
	}
	rows, _ := ix.Rows(Query{EngID: "acme"})
	if r := byTitle(t, rows, "B"); r.OpenThreads != 1 {
		t.Fatalf("open threads %d", r.OpenThreads)
	}
	if err := s.SetReviewers("acme", "F-002-b", []string{"bob"}, uAlice); err != nil {
		t.Fatal(err)
	}
	rows, _ = ix.Rows(Query{EngID: "acme"})
	if r := byTitle(t, rows, "B"); len(r.Reviewers) != 1 || r.Reviewers[0] != "bob" || r.Meta.Reviewers[0] != "bob" {
		t.Fatalf("reviewers %+v", r)
	}
	if err := s.Transition("acme", "F-002-b", workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Status: "verification"})
	if titles(rows) != "B,C" {
		t.Fatalf("verification %q", titles(rows))
	}
	if got := ix.rebuilds.Load() - r0; got != 0 {
		t.Fatalf("%d engagement reloads", got)
	}
}

// A change made elsewhere (another process writing the database, a push)
// reloads only the engagement it touched.
func TestOnlyStaleEngagementReloads(t *testing.T) {
	ix, s := fixture(t)
	ix.Rows(Query{})
	r0 := ix.rebuilds.Load()
	setStatus(t, s, "other", "F-001", "complete")
	if rows, _ := ix.Rows(Query{Status: "complete"}); titles(rows) != "Z" {
		t.Fatalf("complete %q", titles(rows))
	}
	if got := ix.rebuilds.Load() - r0; got != 1 {
		t.Fatalf("%d reloads", got)
	}
	setCVSS(t, s, "acme", "F-001-a", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "")
	if rows, _ := ix.Rows(Query{Severity: "critical"}); titles(rows) != "A,B" {
		t.Fatalf("critical %q", titles(rows))
	}
	if got := ix.rebuilds.Load() - r0; got != 2 {
		t.Fatalf("%d reloads", got)
	}
}

// Concurrent readers after a change share one reload.
func TestConcurrentRefreshSharesReload(t *testing.T) {
	ix, s := fixture(t)
	ix.Rows(Query{})
	setStatus(t, s, "acme", "F-001", "draft")
	r0 := ix.rebuilds.Load()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ix.Rows(Query{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := ix.rebuilds.Load() - r0; got != 1 {
		t.Fatalf("%d reloads", got)
	}
}

// Engagements come from the index, and follow creations.
func TestEngagementsCached(t *testing.T) {
	ix, s := fixture(t)
	es, err := ix.Engagements()
	if err != nil || len(es) != 2 || es[0].ID != "acme" || es[1].ID != "other" {
		t.Fatalf("got %+v %v", es, err)
	}
	if e, ok := ix.Engagement("other"); !ok || e.Name != "other" {
		t.Fatalf("lookup %+v %v", e, ok)
	}
	if err := s.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, alice); err != nil {
		t.Fatal(err)
	}
	if es, _ := ix.Engagements(); len(es) != 3 || es[1].Name != "Beta" {
		t.Fatalf("after create %+v", es)
	}
}

// The generation moves with every change and only then.
func TestGeneration(t *testing.T) {
	ix, s := fixture(t)
	g0, _ := ix.Gen()
	if g, _ := ix.Gen(); g != g0 {
		t.Fatal("moved without a change")
	}
	s.PostChat("acme", "F-001-a", chat.Message{Text: "x"}, uBob)
	g1, _ := ix.Gen()
	if g1 == g0 {
		t.Fatal("chat not seen")
	}
	setStatus(t, s, "acme", "F-001", "draft")
	if g2, _ := ix.Gen(); g2 == g1 {
		t.Fatal("state not seen")
	}
}

// Readers, chat, workflow changes and content edits at once (run with
// -race); the index ends up matching the store.
func TestConcurrentReadersAndWriters(t *testing.T) {
	ix, s := fixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for k := 0; k < 5; k++ {
				ix.Rows(Query{Sort: "severity"})
				ix.Engagements()
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 3; k++ {
				if _, err := s.PostChat("acme", "F-003-c", chat.Message{Text: fmt.Sprint(i, k)}, uBob); err != nil {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			if err := s.UpdateSection("other", "F-001-z", "Impact", fmt.Sprint("v", i), "", alice); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rows, _ := ix.Rows(Query{})
	if r := byTitle(t, rows, "C"); r.OpenThreads != 12 {
		t.Fatalf("open threads %d", r.OpenThreads)
	}
	fresh := New(s, s.Repo())
	want, _ := fresh.Rows(Query{})
	if len(want) != len(rows) {
		t.Fatalf("%d rows, fresh index %d", len(rows), len(want))
	}
	for i := range rows {
		a, b := rows[i], want[i]
		if a.ID != b.ID || a.Status != b.Status || a.OpenThreads != b.OpenThreads || a.Severity != b.Severity {
			t.Fatalf("row %d: %+v vs fresh %+v", i, a, b)
		}
	}
}
