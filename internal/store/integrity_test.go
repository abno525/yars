package store

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/db"
)

func compared(t *testing.T, s *Store) Integrity {
	t.Helper()
	res, err := s.Compare()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Compare counts what the database holds for findings that are not there
// and approvals given for other text, and reports neither as a fault. A
// draft that never got a state row is not reported at all.
func TestCompareCountsWhatIsByDesign(t *testing.T) {
	s, dir, fd := ready(t)
	fid := load(t, s, fd).F.Meta.ID
	if _, err := s.CreateFinding(eng, "A draft without a row", alice); err != nil {
		t.Fatal(err)
	}
	if known, err := s.DB().KnownIDs(eng); err != nil || !reflect.DeepEqual(known, []string{fid}) {
		t.Fatalf("known IDs %v %v: the second finding must have no row", known, err)
	}
	want := Integrity{Engagements: 1, Findings: 2}
	if got := compared(t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("a clean folder: %+v, want %+v", got, want)
	}
	// approved for the text it has: in full, as 16 digits from before the
	// full digest was kept, and with no hash at all
	full := ApprovalHash(rawFile(t, dir, fd))
	for _, h := range []string{full, full[:16], ""} {
		putState(t, s, fd, db.State{Status: "complete", ApprovedHash: h})
		if got := compared(t, s); !reflect.DeepEqual(got, want) {
			t.Fatalf("approved as %q: %+v", h, got)
		}
	}
	// a sign-off for other text is what every edit leaves: not looked at
	putState(t, s, fd, db.State{Status: "verification", Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: "0123456789abcdef"}}})
	if got := compared(t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("a stale sign-off: %+v", got)
	}
	// rows of findings no folder holds: state, a reviewer, chat; and of an
	// engagement that has no folder
	if err := s.DB().Tx(func(tx *db.Tx) error {
		if err := tx.PutState(eng, "F-099", db.State{Status: "verification"}); err != nil {
			return err
		}
		if err := tx.PutState(eng, "F-100", db.State{Reviewers: []db.Reviewer{{Name: "bob"}}}); err != nil {
			return err
		}
		if err := tx.AddMessage(eng, "F-098", chat.Message{ID: "m1", User: "bob", Text: "x"}); err != nil {
			return err
		}
		return tx.PutState("gone", "F-001", db.State{Status: "complete"})
	}); err != nil {
		t.Fatal(err)
	}
	// the approved finding's file changes outside YARS, in a plain commit
	putState(t, s, fd, db.State{Status: "reported", ApprovedHash: full})
	p := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	if err := os.WriteFile(p, append(rawFile(t, dir, fd), []byte("\nmore\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := s.EngRepo(eng)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit([]string{"findings/" + fd + "/finding.md"}, "edit outside YARS", alice); err != nil {
		t.Fatal(err)
	}
	want.NoFinding = []string{eng + "/F-098", eng + "/F-099", eng + "/F-100", "gone/F-001"}
	want.Drifted = []string{eng + "/" + fid}
	got := compared(t, s)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if got.Faults() != 0 {
		t.Fatalf("%d faults: none of this is one", got.Faults())
	}
	// nothing was changed: the rows are all still there
	if known, err := s.DB().KnownIDs(eng); err != nil || len(known) != 4 {
		t.Fatalf("known IDs after the compare: %v %v", known, err)
	}
}

// Two folders with one finding ID, and a finding.md that does not parse, are
// faults; the rows of the unreadable one are not "rows without a finding".
func TestCompareFindsFaults(t *testing.T) {
	s, dir, fd := ready(t)
	fid := load(t, s, fd).F.Meta.ID
	second, err := s.CreateFinding(eng, "Second finding", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB().Tx(func(tx *db.Tx) error {
		return tx.PutState(eng, second.F.Meta.ID, db.State{Status: "complete", ApprovedHash: "0123456789abcdef"})
	}); err != nil {
		t.Fatal(err)
	}
	findings := filepath.Join(dir, "engagements", eng, "findings")
	// the first finding's file once more, in a folder of its own
	twin := filepath.Join(findings, fid+"-twin")
	if err := os.MkdirAll(twin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(twin, "finding.md"), rawFile(t, dir, fd), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(findings, second.Dir, "finding.md"), []byte("no front matter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := Integrity{Engagements: 1, Findings: 3, Duplicate: []string{eng + "/" + fid}, Unreadable: []string{eng + "/" + second.F.Meta.ID}}
	got := compared(t, s)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if got.Faults() != 2 {
		t.Fatalf("%d faults", got.Faults())
	}
}

// Without a database there is nothing to compare.
func TestCompareNeedsDatabase(t *testing.T) {
	s, _ := withEngagement(t)
	s.db = nil
	if _, err := s.Compare(); err != ErrNoDB {
		t.Fatalf("err %v", err)
	}
}
