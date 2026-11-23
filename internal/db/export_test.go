package db

import (
	"path/filepath"
	"testing"
)

func TestExportHistory(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "y.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if schemaVersion < 7 {
		t.Fatalf("schema %d", schemaVersion)
	}
	id1, err := d.AddExport(ExportRecord{By: "pen1", Eng: "acme", Destination: "jira", Findings: `[{"id":"F-001"}]`, OK: true, URL: "https://j/browse/P-1", SentAs: "pen1"})
	if err != nil || id1 == 0 {
		t.Fatal(id1, err)
	}
	id2, _ := d.AddExport(ExportRecord{By: "dir1", Eng: "acme", Destination: "pdf", Findings: `[]`, Error: "pandoc failed"})
	d.AddExport(ExportRecord{By: "dir1", Eng: "other", Destination: "pdf", Findings: `[]`, OK: true})
	l, err := d.Exports("acme", 10)
	if err != nil || len(l) != 2 || l[0].ID != id2 || l[1].ID != id1 {
		t.Fatalf("%+v %v", l, err)
	}
	r := l[1]
	if r.TS == "" || r.By != "pen1" || !r.OK || r.URL != "https://j/browse/P-1" || r.SentAs != "pen1" || r.Findings != `[{"id":"F-001"}]` || r.Destination != "jira" {
		t.Fatalf("%+v", r)
	}
	if l[0].OK || l[0].Error != "pandoc failed" {
		t.Fatalf("%+v", l[0])
	}
	got, ok, err := d.Export(id1)
	if err != nil || !ok || got.Eng != "acme" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if _, ok, _ := d.Export(9999); ok {
		t.Fatal("found missing")
	}
	if l, _ := d.Exports("acme", 1); len(l) != 1 {
		t.Fatal("limit")
	}
}

// A finding's page or issue is remembered per destination and engagement;
// a later send replaces it.
func TestExportRemote(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "y.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if schemaVersion < 9 {
		t.Fatalf("schema %d", schemaVersion)
	}
	if _, ok, err := d.ExportRemote("jira", "acme", "F-001"); ok || err != nil {
		t.Fatalf("found before send: %v", err)
	}
	r := ExportRemote{Destination: "jira", Eng: "acme", Finding: "F-001", Target: "https://j/PEN", RemoteID: "PEN-1", URL: "https://j/browse/PEN-1"}
	if err := d.SetExportRemote(r); err != nil {
		t.Fatal(err)
	}
	d.SetExportRemote(ExportRemote{Destination: "jira", Eng: "other", Finding: "F-001", RemoteID: "PEN-9"})
	r.RemoteID, r.Version = "PEN-2", 3
	if err := d.SetExportRemote(r); err != nil {
		t.Fatal(err)
	}
	got, ok, err := d.ExportRemote("jira", "acme", "F-001")
	if err != nil || !ok || got.RemoteID != "PEN-2" || got.Version != 3 || got.Target != "https://j/PEN" || got.URL != "https://j/browse/PEN-1" || got.Updated == "" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if _, ok, _ := d.ExportRemote("confluence", "acme", "F-001"); ok {
		t.Fatal("other destination")
	}
}
