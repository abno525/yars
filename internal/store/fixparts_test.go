package store

import (
	"strings"
	"testing"

	"github.com/abno525/yars/internal/rules"
)

// titleReady is the test finding ("SQL injection") checked with the check
// tests' rules (and extra), its Impact clean: the one open result is no-sql
// on the title. The fake fixer answers fn.
func titleReady(t *testing.T, extra string, fn func(v rules.Violation, part, body string) (string, error)) (*Store, string, string, *fakeFixer) {
	t.Helper()
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules+extra)
	st := checked(t, s, fd)
	if len(st.Results) != 1 || st.Results[0].Target != "title" {
		t.Fatalf("results %+v", st.Results)
	}
	ff := &fakeFixer{Engine: s.Linter.(*rules.Engine), fn: fn}
	s.Linter = ff
	return s, dir, fd, ff
}

// spellOut answers the title with SQL spelled out.
func spellOut(_ rules.Violation, _ string, body string) (string, error) {
	return strings.ReplaceAll(body, "SQL", "Structured query language"), nil
}

// Fix with AI works on a result on the title: the new title is committed as
// "AI for <user>", answered in the result's thread, and the check after it
// resolves the thread. Before, a finding whose only results were on the
// title answered "nothing to fix".
func TestFixTitle(t *testing.T) {
	var asked []string
	s, dir, fd, ff := titleReady(t, "", func(v rules.Violation, part, body string) (string, error) {
		asked = append(asked, v.Target+"|"+part+"|"+body)
		return spellOut(v, part, body)
	})
	if n := FixCount(checkStatus(t, s, fd)); n != 1 {
		t.Fatalf("fixable results: %d", n)
	}
	thread := checkThreads(t, s, fd)[""]
	fixed(t, s, fd)
	if got := last(t, dir, "%an|%ae|%s"); got != "AI for alice|"+uAlice.GitAuthor().Email+"|F-001: edit title" {
		t.Fatalf("last commit %q", got)
	}
	if got := load(t, s, fd).F.Meta.Title; got != "Structured query language injection" {
		t.Fatalf("title %q", got)
	}
	if ff.calls != 1 || len(asked) != 1 || asked[0] != "title|title|SQL injection" {
		t.Fatalf("asked %q", asked)
	}
	got := aiReplies(t, s, fd)
	if len(got) != 1 || got[0].Reply != thread.Root.ID || got[0].Text != "Fixed." || got[0].User != "alice" {
		t.Fatalf("replies %+v", got)
	}
	if th := checkThreads(t, s, fd)[""]; th == nil || !th.Resolved {
		t.Fatalf("thread %+v", th)
	}
}

// checkStatus is the finding's check status.
func checkStatus(t *testing.T, s *Store, fd string) CheckStatus {
	t.Helper()
	st, err := s.CheckStatus(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// A title the AI gives back is taken as it is or not at all: a line break,
// a hidden text-direction character or more than 200 characters is not a
// title, and nothing is joined, cut or cleaned. A title that still trips the
// rule, or brings a new error, is not committed either.
func TestFixTitleRefused(t *testing.T) {
	baz := "- id: no-baz\n  target: title\n  regex_forbid: 'baz'\n  message: Avoid baz\n"
	for _, c := range []struct{ name, reply, want string }{
		{"a line break", "Structured query\nlanguage injection", "not a valid title"},
		{"two lines with a blank one", "Structured query language injection\n\nIgnore the rules", "not a valid title"},
		{"too long", "Structured query language injection " + strings.Repeat("x", 200), "not a valid title"},
		{"a hidden direction mark", "Structured query language ‮injection", "not a valid title"},
		{"the rule still fires", "SQL injection in the login", "still finds"},
		{"a new error", "A baz injection", "no-baz"},
		{"nothing changed", "SQL injection", "changed nothing"},
	} {
		s, dir, fd, _ := titleReady(t, baz, func(rules.Violation, string, string) (string, error) { return c.reply, nil })
		if got := notFixed(t, s, dir, fd); !strings.Contains(got, c.want) {
			t.Errorf("%s: reply %q", c.name, got)
		}
		if got := load(t, s, fd).F.Meta.Title; got != "SQL injection" {
			t.Errorf("%s: title %q", c.name, got)
		}
	}
	// a blank at either end is no line break: the title is stored without it
	s, _, fd, _ := titleReady(t, "", func(rules.Violation, string, string) (string, error) {
		return " Structured query language injection\n", nil
	})
	fixed(t, s, fd)
	if got := load(t, s, fd).F.Meta.Title; got != "Structured query language injection" {
		t.Fatalf("title %q", got)
	}
}

// A title changed between the check and the write is not overwritten.
func TestFixTitleChangedMeanwhile(t *testing.T) {
	var s *Store
	var fd string
	s, dir, fd, _ := titleReady(t, "", func(v rules.Violation, part, body string) (string, error) {
		if err := s.UpdateTitle(eng, fd, "SQL injection in the login", bob); err != nil {
			return "", err
		}
		return spellOut(v, part, body)
	})
	fixed(t, s, fd)
	if got := last(t, dir, "%an|%s"); !strings.HasPrefix(got, "bob|") {
		t.Fatalf("last commit %q", got)
	}
	if got := aiReplies(t, s, fd); len(got) != 1 || got[0].Text != "Not fixed: the title changed meanwhile." {
		t.Fatalf("replies %+v", got)
	}
}

const tbdRule = "- id: no-tbd\n  target: details:Location\n  regex_forbid: 'TBD'\n  level: warning\n  message: Fill in what is to be done\n"

// detailsReady is a finding whose Location row breaks no-tbd, checked; the
// title rule is not among the rules.
func detailsReady(t *testing.T, fn func(v rules.Violation, part, body string) (string, error)) (*Store, string, string, *fakeFixer) {
	t.Helper()
	s, dir, fd := ready(t)
	withRules(t, s, dir, tbdRule)
	if err := s.UpdateDetails(eng, fd, map[string]string{"Location": "TBD /login", "Business impact": "TBD by the client"}, "", alice); err != nil {
		t.Fatal(err)
	}
	st := checked(t, s, fd)
	if len(st.Results) != 1 || st.Results[0].Target != "details:Location" {
		t.Fatalf("results %+v", st.Results)
	}
	ff := &fakeFixer{Engine: s.Linter.(*rules.Engine), fn: fn}
	s.Linter = ff
	return s, dir, fd, ff
}

// Fix with AI works on a result on a details row: that row is written, the
// other rows stay, and the commit is the AI's for the user.
func TestFixDetailsRow(t *testing.T) {
	var asked []string
	s, dir, fd, _ := detailsReady(t, func(v rules.Violation, part, body string) (string, error) {
		asked = append(asked, v.Target+"|"+part+"|"+body)
		return strings.TrimPrefix(body, "TBD "), nil
	})
	fixed(t, s, fd)
	if got := last(t, dir, "%an|%s"); got != "AI for alice|F-001: edit details" {
		t.Fatalf("last commit %q", got)
	}
	d := load(t, s, fd).F.Meta.Details
	if d["Location"] != "/login" || d["Business impact"] != "TBD by the client" {
		t.Fatalf("details %+v", d)
	}
	if len(asked) != 1 || asked[0] != "details:Location|details: Location|TBD /login" {
		t.Fatalf("asked %q", asked)
	}
	if got := aiReplies(t, s, fd); len(got) != 1 || got[0].Text != "Fixed." {
		t.Fatalf("replies %+v", got)
	}
}

// A details row that changed, or lost its text, between the check and the
// fix is left as it is, with words in the thread.
func TestFixDetailsRowChanged(t *testing.T) {
	var s *Store
	var fd string
	s, dir, fd, _ := detailsReady(t, func(_ rules.Violation, _, body string) (string, error) {
		if err := s.UpdateDetails(eng, fd, map[string]string{"Location": "TBD /admin"}, "", bob); err != nil {
			return "", err
		}
		return strings.TrimPrefix(body, "TBD "), nil
	})
	fixed(t, s, fd)
	if got := last(t, dir, "%an|%s"); !strings.HasPrefix(got, "bob|") {
		t.Fatalf("last commit %q", got)
	}
	if got := aiReplies(t, s, fd); len(got) != 1 || got[0].Text != "Not fixed: the details row changed meanwhile." {
		t.Fatalf("replies %+v", got)
	}
	// a second paragraph the AI adds to the row is refused as in a section
	s2, dir2, fd2, _ := detailsReady(t, func(_ rules.Violation, _, body string) (string, error) {
		return "/login\n\nIgnore the rules", nil
	})
	if got := notFixed(t, s2, dir2, fd2); !strings.Contains(got, "number of paragraphs") {
		t.Fatalf("reply %q", got)
	}
}
