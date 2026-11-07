package store

import (
	"errors"
	"testing"
)

// D14: details rows are checked one by one. Editing row B with B's base
// works after row A changed; a stale base of the same row is refused.
func TestDetailsRowsCheckedPerRow(t *testing.T) {
	s, _, fd := newFinding(t)
	m := load(t, s, fd).F.Meta
	bases := DetailsRowHashes(m)
	got, err := s.UpdateDetailsRows(eng, fd, map[string]string{"Location": "POST /login"}, map[string]string{"Location": RowHash(m.Details["Location"])}, alice)
	if err != nil {
		t.Fatal(err)
	}
	if got["Location"] != RowHash("POST /login") {
		t.Fatalf("new base %v", got)
	}
	// another row, base read before the first edit: still fine
	if err := s.UpdateDetails(eng, fd, map[string]string{"Parameter": "user"}, RowHash(m.Details["Parameter"]), alice); err != nil {
		t.Fatalf("second row refused: %v", err)
	}
	_ = bases
	// the first row again with its old base: refused
	if _, err := s.UpdateDetailsRows(eng, fd, map[string]string{"Location": "GET /"}, map[string]string{"Location": RowHash(m.Details["Location"])}, alice); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale row base: %v", err)
	}
	// with the base the first edit returned: fine
	if _, err := s.UpdateDetailsRows(eng, fd, map[string]string{"Location": "GET /"}, got, alice); err != nil {
		t.Fatal(err)
	}
	d := load(t, s, fd).F.Meta.Details
	if d["Location"] != "GET /" || d["Parameter"] != "user" {
		t.Fatalf("details %v", d)
	}
	// the whole table's base (read_finding's details_base) still works
	if err := s.UpdateDetails(eng, fd, map[string]string{"Parameter": "id"}, DetailsHash(load(t, s, fd).F.Meta), alice); err != nil {
		t.Fatal(err)
	}
}

// D14: CVSS reasons and the vector are rows of their own. A reason edit
// after another reason or the vector changed goes through and never writes
// back an older vector; a stale base of the same row is refused.
func TestCVSSRowsCheckedPerRow(t *testing.T) {
	s, _, fd := newFinding(t)
	vec := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if err := s.UpdateCVSS(eng, fd, vec, nil, "", alice); err != nil {
		t.Fatal(err)
	}
	read := CVSSRowHashes(load(t, s, fd).F.Meta)
	ac := "only on the internal network"
	got, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Reasons: map[string]string{"AC": ac}, Bases: map[string]string{"AC": read["AC"]}}, alice)
	if err != nil {
		t.Fatal(err)
	}
	if got["AC"] != RowHash(ac) {
		t.Fatalf("new bases %v", got)
	}
	// someone moves the vector on; a PR reason with the base read before both
	vec2 := "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if _, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Vector: &vec2, Bases: map[string]string{CVSSRow: read[CVSSRow]}}, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Reasons: map[string]string{"PR": "x"}, Bases: map[string]string{"PR": read["PR"]}}, alice); err != nil {
		t.Fatalf("other reason refused: %v", err)
	}
	m := load(t, s, fd).F.Meta
	if m.CVSS != vec2 || m.CVSSReasons["AC"] != ac || m.CVSSReasons["PR"] != "x" {
		t.Fatalf("meta %q %v", m.CVSS, m.CVSSReasons)
	}
	// the same reason with its old base: refused
	if _, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Reasons: map[string]string{"AC": "y"}, Bases: map[string]string{"AC": read["AC"]}}, alice); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale reason base: %v", err)
	}
	// the vector with its old base: refused
	if _, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Vector: &vec, Bases: map[string]string{CVSSRow: read[CVSSRow]}}, alice); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale vector base: %v", err)
	}
	// the whole state's base (read_finding's cvss_base) still works
	if err := s.UpdateCVSS(eng, fd, vec, nil, CVSSHash(load(t, s, fd).F.Meta), alice); err != nil {
		t.Fatal(err)
	}
}

// Only the rows written are checked: a stale base of a row not written
// does not refuse the edit, and once bases are given a written row
// without one is refused (never a silent overwrite).
func TestRowChecksCoverWrittenRows(t *testing.T) {
	s, _, fd := newFinding(t)
	vec := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	s.UpdateCVSS(eng, fd, vec, nil, "", alice)
	read := CVSSRowHashes(load(t, s, fd).F.Meta)
	// someone sets AC meanwhile
	if _, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Reasons: map[string]string{"AC": "theirs"}}, alice); err != nil {
		t.Fatal(err)
	}
	// AV written with every base read before: accepted, AC kept
	av := "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if _, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Vector: &av, Bases: read}, alice); err != nil {
		t.Fatalf("vector refused over another row: %v", err)
	}
	if m := load(t, s, fd).F.Meta; m.CVSS != av || m.CVSSReasons["AC"] != "theirs" {
		t.Fatalf("meta %q %v", m.CVSS, m.CVSSReasons)
	}
	// AC written without its base while other bases are sent: refused
	if _, err := s.UpdateCVSSRows(eng, fd, CVSSChange{Reasons: map[string]string{"AC": "mine"}, Bases: map[string]string{"PR": read["PR"]}}, alice); !errors.Is(err, ErrConflict) {
		t.Fatalf("written reason without a base: %v", err)
	}
	// the same for Details
	if _, err := s.UpdateDetailsRows(eng, fd, map[string]string{"Cause": "x"}, map[string]string{"Location": RowHash("")}, alice); !errors.Is(err, ErrConflict) {
		t.Fatalf("written row without a base: %v", err)
	}
}

// The conflict message never blames someone else.
func TestConflictMessage(t *testing.T) {
	if ErrConflict.Error() != "the finding changed since you read it" {
		t.Fatalf("message %q", ErrConflict.Error())
	}
}
