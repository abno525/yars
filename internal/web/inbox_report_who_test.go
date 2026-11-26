package web

import (
	"testing"

	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/workflow"
)

// A complete finding with no approve event (a migration, a seed) names no
// approver: the cell is the muted dash of an empty value, not a bare
// "approved".
func TestInboxReportNoApprover(t *testing.T) {
	r := index.Row{EngID: "acme", Dir: fdir, ID: "F-001", Title: "SQL injection", Meta: &finding.Meta{Status: "complete"}}
	ir := findingRow(workflow.InboxReport, wDora, r, "Acme")
	if ir.Who != "" || ir.What != "" {
		t.Fatalf("who %q what %q", ir.Who, ir.What)
	}
	tplHas(t, "inbox.html", `{{if not (or .Who .What)}}<span class="muted">—</span>{{end}}`)
	r.Events = []index.Event{{Action: string(workflow.Approve), User: "dora"}}
	if ir := findingRow(workflow.InboxReport, wDora, r, "Acme"); ir.Who != "dora" || ir.What != "approved" {
		t.Fatalf("with the event: who %q what %q", ir.Who, ir.What)
	}
}
