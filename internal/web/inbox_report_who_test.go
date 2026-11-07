package web

import (
	"testing"

	"yars/internal/finding"
	"yars/internal/index"
	"yars/internal/workflow"
)

// A complete finding with no approve event (a migration, a seed) names no
// approver: the cell is a dash, not a bare "approved".
func TestInboxReportNoApprover(t *testing.T) {
	r := index.Row{EngID: "acme", Dir: fdir, ID: "F-001", Title: "SQL injection", Meta: &finding.Meta{Status: "complete"}}
	ir := findingRow(workflow.InboxReport, wDora, r, "Acme")
	if ir.Who != "" || ir.What != "—" {
		t.Fatalf("who %q what %q", ir.Who, ir.What)
	}
	r.Events = []index.Event{{Action: string(workflow.Approve), User: "dora"}}
	if ir := findingRow(workflow.InboxReport, wDora, r, "Acme"); ir.Who != "dora" || ir.What != "approved" {
		t.Fatalf("with the event: who %q what %q", ir.Who, ir.What)
	}
}
