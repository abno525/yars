package store

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"yars/internal/config"
)

var (
	bPen = config.User{Username: "alice", Role: "pentester"}
	bRev = config.User{Username: "bob", Role: "reviewer"}
	bDir = config.User{Username: "dora", Role: "director", IsAdmin: true}
)

func boardNote(t *testing.T, s *Store, title, host, state string) Note {
	t.Helper()
	n, err := s.CreateNote(eng, title, host, state, "Seen on **"+host+"**.", bPen)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func fieldOf(err error) string {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestCreateNoteChecks(t *testing.T) {
	s, _ := withEngagement(t)
	long := strings.Repeat("x", 201)
	for _, c := range []struct{ title, host, state, text, field string }{
		{"", "", "open", "x", "title"},
		{"two\nlines", "", "open", "x", "title"},
		{long, "", "open", "x", "title"},
		{"ok", "a\nb", "open", "x", "host"},
		{"ok", strings.Repeat("h", 2001), "open", "x", "host"},
		{"ok", "", "confirmed", "x", "state"},
		{"ok", "", "open", "  ", "text"},
		{"ok", "", "open", strings.Repeat("y", 10001), "text"},
	} {
		_, err := s.CreateNote(eng, c.title, c.host, c.state, c.text, bPen)
		if !errors.Is(err, ErrInvalidValue) || fieldOf(err) != c.field {
			t.Errorf("%q/%q/%q: %v (field %q)", c.title, c.host, c.state, err, fieldOf(err))
		}
	}
	n, err := s.CreateNote(eng, "  Verbose stack trace  ", " api.acme.test ", "", "trace", bPen)
	if err != nil || n.Num != 1 || n.Title != "Verbose stack trace" || n.Host != "api.acme.test" || n.State != "open" || n.Author != "alice" {
		t.Fatalf("created %+v %v", n, err)
	}
	if _, err := s.CreateNote("nope", "t", "", "open", "x", bPen); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown engagement: %v", err)
	}
	if _, err := s.Note(eng, 9); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown note: %v", err)
	}
}

func TestNoteStateChecks(t *testing.T) {
	s, _ := withEngagement(t)
	boardNote(t, s, "CORS null origin", "api.acme.test", "open")
	// Set state never dismisses (Dismiss asks why), knows its states and
	// refuses a move to where the note already is
	for _, to := range []string{"dismissed", "bogus", "open"} {
		if err := s.SetNoteState(eng, 1, "open", to, bRev); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("to %s: %v", to, err)
		}
	}
	if err := s.SetNoteState(eng, 1, "analyzing", "confirmed", bRev); !errors.Is(err, ErrBoardStale) {
		t.Fatalf("stale: %v", err)
	}
	if err := s.DismissNote(eng, 1, "open", "  ", bRev); fieldOf(err) != "reason" {
		t.Fatalf("no reason: %v", err)
	}
	if err := s.DismissNote(eng, 1, "open", strings.Repeat("r", 1001), bRev); fieldOf(err) != "reason" {
		t.Fatalf("long reason: %v", err)
	}
	if err := s.DismissNote(eng, 1, "open", "only on /health", bRev); err != nil {
		t.Fatal(err)
	}
	if err := s.DismissNote(eng, 1, "dismissed", "again", bRev); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("dismiss twice: %v", err)
	}
	if err := s.SetNoteState(eng, 1, "dismissed", "open", bPen); err != nil {
		t.Fatal(err)
	}
	// severities come from the configuration
	if err := s.SetNoteSeverity(eng, 1, "catastrophic", bRev); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("bad severity: %v", err)
	}
	if err := s.SetNoteSeverity(eng, 1, "low", bRev); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNoteSeverity(eng, 1, "", bRev); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Note(eng, 1); n.Severity != "" || n.State != "open" || n.DismissReason != "" {
		t.Fatalf("note %+v", n)
	}
}

func TestNoteDuplicateOf(t *testing.T) {
	s, _ := withEngagement(t)
	boardNote(t, s, "one", "a", "open")
	boardNote(t, s, "two", "b", "open")
	f, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	other := "2026-12-beta"
	if err := s.CreateEngagement(Engagement{ID: other, Name: "Beta"}, alice); err != nil {
		t.Fatal(err)
	}
	s.CreateNote(other, "theirs", "", "open", "x", bPen)
	s.CreateNote(other, "theirs 2", "", "open", "x", bPen)
	s.CreateNote(other, "theirs 3", "", "open", "x", bPen)
	for _, bad := range []string{"L-001", "L-3", "F-9", "X-1", "L-", "L-001; DROP", "1"} {
		if _, err := s.SetNoteDup(eng, 1, bad, bRev); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("dup %q: %v", bad, err)
		}
	}
	got, err := s.SetNoteDup(eng, 1, "l-2", bRev)
	if err != nil || got != "L-002" {
		t.Fatalf("dup of L-002: %q %v", got, err)
	}
	// no A→B→A
	if _, err := s.SetNoteDup(eng, 2, "L-1", bRev); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("cycle: %v", err)
	}
	if got, err := s.SetNoteDup(eng, 2, f.F.Meta.ID, bRev); err != nil || got != "F-001" {
		t.Fatalf("dup of a finding: %q %v", got, err)
	}
	if got, err := s.SetNoteDup(eng, 1, "", bRev); err != nil || got != "" {
		t.Fatalf("clear: %q %v", got, err)
	}
}

func TestMakeFinding(t *testing.T) {
	s, _ := withEngagement(t)
	boardNote(t, s, "Reflected XSS in q", "https://app.acme.test/search", "open")
	if _, err := s.MakeFinding(eng, 1, bRev); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("from open: %v", err)
	}
	s.SetNoteState(eng, 1, "open", "confirmed", bRev)
	s.SetNoteSeverity(eng, 1, "high", bRev)
	ref, err := s.MakeFinding(eng, 1, bRev)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ = s.Finding(eng, ref.Dir)
	m := ref.F.Meta
	if m.Title != "Reflected XSS in q" || m.Author != "bob" || m.Severity != "high" || m.Status != "draft" {
		t.Fatalf("meta %+v", m)
	}
	if len(m.Assets) != 1 || m.Assets[0].URL != "https://app.acme.test/search" {
		t.Fatalf("assets %+v", m.Assets)
	}
	sec := "Description"
	if !slices.Contains(s.Config().Sections, sec) {
		sec = s.Config().Sections[0]
	}
	if body, _ := ref.F.Section(sec); !strings.Contains(body, "Seen on **https://app.acme.test/search**.") {
		t.Fatalf("%s: %q", sec, body)
	}
	if n, _ := s.Note(eng, 1); n.Finding != m.ID {
		t.Fatalf("link %+v", n)
	}
	// read only from now on
	if err := s.PostNote(eng, 1, "late", bPen); !errors.Is(err, ErrBoardLocked) {
		t.Fatalf("post on a finding: %v", err)
	}
	if _, err := s.MakeFinding(eng, 1, bRev); !errors.Is(err, ErrBoardLocked) {
		t.Fatalf("second Make finding: %v", err)
	}
}

func TestMakeFindingFallbackSectionAndHost(t *testing.T) {
	s, _ := withEngagement(t)
	c := s.Config()
	c.Sections = []string{"Summary", "Impact"}
	s.SetConfig(c)
	boardNote(t, s, "Subdomains", "app.acme.test/search", "info")
	ref, err := s.MakeFinding(eng, 1, bPen)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := ref.F.Section("Summary"); !strings.Contains(body, "Seen on") {
		t.Fatalf("summary %q", body)
	}
	if a := ref.F.Meta.Assets; len(a) != 1 || a[0].Host != "app.acme.test/search" {
		t.Fatalf("assets %+v", a)
	}
}

func TestMakeFindingOnce(t *testing.T) {
	s, _ := withEngagement(t)
	boardNote(t, s, "S3 listing", "bucket", "open")
	s.SetNoteState(eng, 1, "open", "confirmed", bRev)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, errs[i] = s.MakeFinding(eng, 1, bRev) }(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		}
	}
	refs, _ := s.ListFindings(eng)
	if ok != 1 || len(refs) != 1 {
		t.Fatalf("%d made, %d findings: %v", ok, len(refs), errs)
	}
}

func TestBoardArchivedStore(t *testing.T) {
	s, _ := withEngagement(t)
	boardNote(t, s, "x", "h", "info")
	if err := s.Archive(eng, bDir); err != nil {
		t.Fatal(err)
	}
	_, cerr := s.CreateNote(eng, "t", "", "open", "x", bPen)
	_, merr := s.MakeFinding(eng, 1, bPen)
	for name, err := range map[string]error{
		"create": cerr, "make": merr,
		"post":  s.PostNote(eng, 1, "x", bPen),
		"state": s.SetNoteState(eng, 1, "info", "open", bPen),
	} {
		if !errors.Is(err, ErrArchived) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n, _ := s.Note(eng, 1); n.Pending || n.Finding != "" {
		t.Fatalf("archived note claimed %+v", n)
	}
}

func TestUnseenVisible(t *testing.T) {
	s, _ := withEngagement(t)
	s.DB().AddMembers(eng, "alice", "bob")
	boardNote(t, s, "x", "h", "open")
	if u, _ := s.UnseenNotes(bRev, 50); len(u) != 1 {
		t.Fatalf("bob %+v", u)
	}
	// off the team: nothing of that engagement
	if err := s.RemoveMember(eng, "bob", bDir); err != nil {
		t.Fatal(err)
	}
	s.SeeNote(eng, 1, bRev) // a stale tab still reads it
	s.PostNote(eng, 1, "more", bPen)
	if u, _ := s.UnseenNotes(bRev, 50); len(u) != 0 {
		t.Fatalf("removed member sees %+v", u)
	}
}
