package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// pre1 6.6: a clone holds no workflow state, so yars mcp on it says a
// finding's status is unknown (before: draft, also for a complete one), in
// read_finding and in list_findings, and refuses list_findings' status
// filter, which it cannot answer. The server still says the status; an edit
// on the clone still commits (the push decides). Both workflows.
func TestCloneStatusIsUnknown(t *testing.T) {
	for _, c := range []struct {
		name          string
		server, clone *fx
		u             config.User
	}{
		func() (c struct {
			name          string
			server, clone *fx
			u             config.User
		}) {
			c.name, c.server, c.u = "standard", stateFx(t, "complete"), dora
			c.clone = cloneOf(t, c.server)
			return c
		}(),
		func() (c struct {
			name          string
			server, clone *fx
			u             config.User
		}) {
			c.name, c.server, c.u = "simple", simpleStateFx(t, "complete"), anna
			c.clone = simpleCloneOf(t, c.server)
			return c
		}(),
	} {
		status := func(f *fx) (read, listed string) {
			t.Helper()
			var rd struct {
				State struct{ Status string }
			}
			json.Unmarshal([]byte(f.ok(c.u, "read_finding", f001())), &rd)
			var rows []struct{ ID, Status string }
			itemsOf(t, f.ok(c.u, "list_findings", map[string]any{"engagement": "acme"}), &rows)
			if len(rows) != 1 {
				t.Fatalf("%s: %d findings listed", c.name, len(rows))
			}
			return rd.State.Status, rows[0].Status
		}
		if read, listed := status(c.server); read != "complete" || listed != "complete" {
			t.Errorf("%s, the server: read_finding %q, list_findings %q", c.name, read, listed)
		}
		if read, listed := status(c.clone); read != "unknown" || listed != "unknown" {
			t.Errorf("%s, the clone: read_finding %q, list_findings %q", c.name, read, listed)
		}
		for _, st := range []string{"complete", "draft", "withdrawn"} {
			text, isErr := c.clone.call(c.u, "list_findings", map[string]any{"engagement": "acme", "status": st})
			if m := object(t, st, text); !isErr || m["code"] != "no_database" {
				t.Errorf("%s, the clone, status=%s: %s", c.name, st, text)
			}
		}
		// what is no status is refused as before, and the other filters work
		for _, st := range []string{"unknown", "open"} {
			text, isErr := c.clone.call(c.u, "list_findings", map[string]any{"engagement": "acme", "status": st})
			if m := object(t, st, text); !isErr || m["code"] != "invalid" {
				t.Errorf("%s, the clone, status=%s: %s", c.name, st, text)
			}
		}
		var rows []any
		itemsOf(t, c.clone.ok(c.u, "list_findings", map[string]any{"engagement": "acme", "severity": "high", "q": "sql"}), &rows)
		if len(rows) != 1 {
			t.Errorf("%s, the clone, severity and q: %d findings", c.name, len(rows))
		}
		if st := getConfigOf(t, c.clone).Statuses; strings.Contains(strings.Join(st, " "), "unknown") {
			t.Errorf("%s: get_config's statuses %v", c.name, st)
		}
		// the server answers the filter
		itemsOf(t, c.server.ok(c.u, "list_findings", map[string]any{"engagement": "acme", "status": "complete"}), &rows)
		if len(rows) != 1 {
			t.Errorf("%s, the server, status=complete: %d findings", c.name, len(rows))
		}
		// the clone stays editable
		head := c.clone.lastCommit()
		c.clone.ok(c.u, "update_section", f001("section", "Impact", "body", "Edited on the clone."))
		if got := c.clone.lastCommit(); got == head || !strings.HasSuffix(got, "F-001: edit Impact") {
			t.Errorf("%s: an edit on the clone: commit %q", c.name, got)
		}
	}
	for _, fl := range []workflow.Flow{{}, {Simple: true}} {
		for _, name := range []string{"read_finding", "list_findings"} {
			if d := toolByName[name].in(fl).desc; !strings.Contains(d, "local clone") || !strings.Contains(d, "unknown") {
				t.Errorf("simple %v: %s does not say what a clone knows", fl.Simple, name)
			}
		}
	}
}
