package store

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/workflow"
)

// rawFile is finding.md as it is on disk.
func rawFile(t *testing.T, dir, fd string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A sign-off and an approval are bound to the full SHA-256 of finding.md,
// not to its first 64 bits: two files made to share those bits are still
// two contents.
func TestApprovalBoundToFullDigest(t *testing.T) {
	s, dir, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawFile(t, dir, fd))
	full := hex.EncodeToString(sum[:])
	if ApprovalHash(rawFile(t, dir, fd)) != full || ContentHash(rawFile(t, dir, fd)) != full[:16] {
		t.Fatalf("ApprovalHash %s, ContentHash %s, sha256 %s", ApprovalHash(rawFile(t, dir, fd)), ContentHash(rawFile(t, dir, fd)), full)
	}
	if st := stateOf(t, s, fd); st.Reviewers[0].ClearedHash != full {
		t.Fatalf("sign-off bound to %q, want the full digest %s", st.Reviewers[0].ClearedHash, full)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(t, s, fd); st.ApprovedHash != full {
		t.Fatalf("approval bound to %q, want the full digest %s", st.ApprovedHash, full)
	}
	if ref := load(t, s, fd); ref.F.Meta.Status != "complete" || !slices.Contains(ref.F.Meta.ClearedBy, "bob") || ref.Full != full || ref.Hash != full[:16] {
		t.Fatalf("read back: %s, cleared by %v, full %s", ref.F.Meta.Status, ref.F.Meta.ClearedBy, ref.Full)
	}
	// a stored digest that shares only the first 64 bits with the content is
	// another content's: the approval and the sign-off do not count
	other := full[:16] + strings.Repeat("0", 46) + "ff"
	if len(other) != 64 || other == full {
		t.Fatalf("test digest %q", other)
	}
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: other, Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: other}}})
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("a digest sharing 64 bits counted: %s, cleared by %v", m.Status, m.ClearedBy)
	}
	// a director's edit through YARS carries the approval, bound in full
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: full})
	if err := s.UpdateSection(eng, fd, "Impact", "Changed by the director.", "", uDora); err != nil {
		t.Fatal(err)
	}
	now := ApprovalHash(rawFile(t, dir, fd))
	if st := stateOf(t, s, fd); st.ApprovedHash != now || now == full || load(t, s, fd).F.Meta.Status != "complete" {
		t.Fatalf("after a director's edit: approval %s, content %s", st.ApprovedHash, now)
	}
	// an edit outside YARS sends it back to verification
	p := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	if err := os.WriteFile(p, append(rawFile(t, dir, fd), []byte("\nmore\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := load(t, s, fd).F.Meta.Status; st != "verification" {
		t.Fatalf("after an edit outside YARS: %s", st)
	}
}

// Approvals and sign-offs stored before the full digest was kept hold its
// first 16 digits: they still count for that content after the upgrade, stop
// counting when the file changes, and are written in full when given again.
func TestShortStoredHashesStillCount(t *testing.T) {
	s, dir, fd := ready(t)
	short := ContentHash(rawFile(t, dir, fd))
	if len(short) != 16 {
		t.Fatalf("short hash %q", short)
	}
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: short, Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: short}}})
	if m := load(t, s, fd).F.Meta; m.Status != "complete" || !slices.Contains(m.ClearedBy, "bob") {
		t.Fatalf("a legacy approval: %s, cleared by %v", m.Status, m.ClearedBy)
	}
	putState(t, s, fd, db.State{Status: "verification", Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: short}}})
	if m := load(t, s, fd).F.Meta; !slices.Contains(m.ClearedBy, "bob") {
		t.Fatalf("a legacy sign-off does not count: %v", m.ClearedBy)
	}
	// approved on that sign-off: the approval is stored in full
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(t, s, fd); st.ApprovedHash != ApprovalHash(rawFile(t, dir, fd)) {
		t.Fatalf("approval %q", st.ApprovedHash)
	}
	// a director's edit carries a legacy approval to the new content, in full
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: short})
	if err := s.UpdateSection(eng, fd, "Impact", "Changed by the director.", "", uDora); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(t, s, fd); st.ApprovedHash != ApprovalHash(rawFile(t, dir, fd)) || load(t, s, fd).F.Meta.Status != "complete" {
		t.Fatalf("after a director's edit: %q", st.ApprovedHash)
	}
	// short is of the content before that edit: for the file as it is now a
	// legacy value does not count
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: short, Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: short}}})
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("a legacy approval of other content: %s, cleared by %v", m.Status, m.ClearedBy)
	}
}

// A rename in Admin, Structure moves the approval and the sign-offs to the
// new content, for rows stored in full and for legacy ones.
func TestRenameMovesFullAndShortHashes(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		s, dir, fd := ready(t)
		if err := s.UpdateSection(eng, fd, "Impact", "Data loss.", "", alice); err != nil {
			t.Fatal(err)
		}
		h := ApprovalHash(rawFile(t, dir, fd))
		if legacy {
			h = h[:16]
		}
		putState(t, s, fd, db.State{Status: "complete", ApprovedHash: h, Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: h}}})
		if _, err := s.RenameNames("section", toBusiness, alice); err != nil {
			t.Fatal(err)
		}
		now := ApprovalHash(rawFile(t, dir, fd))
		st := stateOf(t, s, fd)
		if st.ApprovedHash != now || st.Reviewers[0].ClearedHash != now {
			t.Fatalf("legacy %v: approval %q, sign-off %q, content %s", legacy, st.ApprovedHash, st.Reviewers[0].ClearedHash, now)
		}
		if m := load(t, s, fd).F.Meta; m.Status != "complete" || !slices.Contains(m.ClearedBy, "bob") {
			t.Fatalf("legacy %v: %s, cleared by %v", legacy, m.Status, m.ClearedBy)
		}
	}
}
