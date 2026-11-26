package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
)

// Dismiss is DismissWhy with a reason of the test's and the quote's one
// place: the store itself asks for a reason (pre1 2.33).
func (s *Store) Dismiss(engID, dir, rule, quote string, u config.User) error {
	return s.DismissWhy(engID, dir, rule, "", quote, "fine here", u)
}

// checkAudit returns the audit log's dismiss and restore rows, newest first.
func checkAudit(t *testing.T, s *Store) []db.AuditEntry {
	t.Helper()
	l, err := s.DB().AuditLog(50)
	if err != nil {
		t.Fatal(err)
	}
	var out []db.AuditEntry
	for _, a := range l {
		if strings.HasPrefix(a.Action, "check.") {
			out = append(out, a)
		}
	}
	return out
}

// The store itself asks for the reason of a dismissal, and both a dismissal
// and a restore leave a row in the audit log: who, the finding, the rule,
// its level and place, and the reason. The quote is not in it: it is
// finding text, and for a secrets rule the secret (pre1 2.33).
func TestDismissNeedsReasonAndIsAudited(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	checked(t, s, fd)
	fid := load(t, s, fd).F.Meta.ID
	for _, reason := range []string{"", "  \n"} {
		err := s.DismissWhy(eng, fd, "no-sql", "title", "SQL", reason, uBob)
		if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "Reason is required") {
			t.Fatalf("reason %q: %v", reason, err)
		}
	}
	if ds, _ := s.Dismissals(eng, fid); len(ds) != 0 {
		t.Fatalf("dismissed without a reason: %+v", ds)
	}
	if l := checkAudit(t, s); len(l) != 0 {
		t.Fatalf("a refused dismissal is audited: %+v", l)
	}
	// someone who may not dismiss leaves no row either
	if err := s.DismissWhy(eng, fd, "no-sql", "title", "SQL", "I say so", uAlice); !denied(err) {
		t.Fatalf("an error by a pentester: %v", err)
	}
	if l := checkAudit(t, s); len(l) != 0 {
		t.Fatalf("a denied dismissal is audited: %+v", l)
	}

	const why = "SQL is in the client's glossary"
	if err := s.DismissWhy(eng, fd, "no-sql", "title", "SQL", "  "+why+" ", uBob); err != nil {
		t.Fatal(err)
	}
	l := checkAudit(t, s)
	if len(l) != 1 || l[0].Actor != "bob" || l[0].Action != "check.dismiss" || l[0].Target != eng+"/"+fid {
		t.Fatalf("audit after a dismissal: %+v", l)
	}
	if l[0].Detail != "no-sql · error · title · "+why {
		t.Fatalf("detail %q", l[0].Detail)
	}

	// a restore: one row, naming who had dismissed it and why
	if err := s.Undismiss(eng, fd, "no-sql", "title", "SQL", uDora); err != nil {
		t.Fatal(err)
	}
	l = checkAudit(t, s)
	if len(l) != 2 || l[0].Actor != "dora" || l[0].Action != "check.restore" || l[0].Target != eng+"/"+fid {
		t.Fatalf("audit after a restore: %+v", l)
	}
	if l[0].Detail != "no-sql · error · title · dismissed by bob: "+why {
		t.Fatalf("detail %q", l[0].Detail)
	}
	// nothing to restore: no row
	if err := s.Undismiss(eng, fd, "no-sql", "title", "SQL", uDora); err != nil {
		t.Fatal(err)
	}
	if l := checkAudit(t, s); len(l) != 2 {
		t.Fatalf("a restore of nothing is audited: %+v", l)
	}
}

// The quote of a dismissed result never reaches the audit log.
func TestDismissAuditHasNoQuote(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	s.UpdateSection(eng, fd, "Impact", "a foo here", "", alice)
	checked(t, s, fd)
	if err := s.DismissWhy(eng, fd, "no-foo", "section:Impact", "foo", "house style", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Undismiss(eng, fd, "no-foo", "section:Impact", "foo", uAlice); err != nil {
		t.Fatal(err)
	}
	l := checkAudit(t, s)
	if len(l) != 2 {
		t.Fatalf("audit %+v", l)
	}
	for _, a := range l {
		if strings.Contains(strings.ReplaceAll(a.Detail, "no-foo", ""), "foo") || !strings.HasPrefix(a.Detail, "no-foo · warning · section:Impact") {
			t.Errorf("%s detail %q", a.Action, a.Detail)
		}
	}
}
