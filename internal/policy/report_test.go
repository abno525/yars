package policy

import "testing"

// Report-level sections (report/<slug>.md) can be pushed by the team; they
// must be Markdown bodies that keep the file's structure.
func TestPolicyReportSections(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { write(d, "report/scope.md", "Only app.acme.\n") }); len(ps) != 0 {
		t.Fatalf("report section rejected: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { write(d, "report/scope.md", "x\n```\nunclosed\n") }); !has(ps, "report/scope.md") {
		t.Fatalf("broken body accepted: %v", ps)
	}
	f.reclone()
	for _, bad := range []string{"report/notes.txt", "report/a/b.md", "report/.hidden.md"} {
		if ps := f.push("alice", func(d string) { write(d, bad, "x\n") }); !has(ps, bad) {
			t.Fatalf("%s accepted: %v", bad, ps)
		}
		f.reclone()
	}
}
