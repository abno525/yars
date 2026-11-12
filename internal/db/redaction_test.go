package db

import "testing"

// D28: a redaction is noted until its originals are purged; a later
// redaction notes it again.
func TestNoteRedactionClearsPurged(t *testing.T) {
	d, _ := open(t)
	if err := d.NoteRedaction("acme", "F-001", "shot.png", "alice"); err != nil {
		t.Fatal(err)
	}
	if u, err := d.Unpurged("acme", "F-001"); err != nil || !u["shot.png"] || len(u) != 1 {
		t.Fatalf("unpurged %v %v", u, err)
	}
	if u, _ := d.Unpurged("acme", "F-002"); len(u) != 0 {
		t.Fatalf("another finding %v", u)
	}
	if err := d.MarkPurged("acme", "F-001", "shot.png", []string{"b1", "b2"}); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.Unpurged("acme", "F-001"); len(u) != 0 {
		t.Fatalf("still unpurged %v", u)
	}
	if b, err := d.PurgedBlobs("acme"); err != nil || len(b) != 2 || b["b1"] != "shot.png" || b["b2"] != "shot.png" {
		t.Fatalf("purged blobs %v %v", b, err)
	}
	if b, _ := d.PurgedBlobs("other"); len(b) != 0 {
		t.Fatalf("another engagement %v", b)
	}
	// redacted again after the purge: the new original is in history again
	if err := d.NoteRedaction("acme", "F-001", "shot.png", "bob"); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.Unpurged("acme", "F-001"); !u["shot.png"] {
		t.Fatalf("a redaction after the purge is not noted: %v", u)
	}
	// marking purged twice keeps the blobs once
	if err := d.MarkPurged("acme", "F-001", "shot.png", []string{"b1"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := d.PurgedBlobs("acme"); len(b) != 2 {
		t.Fatalf("purged blobs after a second purge %v", b)
	}
	// blobs remembered ahead of a purge: only the new ones are reported, and
	// those can be dropped again (the purge failed)
	added, err := d.AddPurgedBlobs("acme", "shot.png", []string{"b1", "b3"})
	if err != nil || len(added) != 1 || added[0] != "b3" {
		t.Fatalf("added %v %v", added, err)
	}
	if err := d.DropPurgedBlobs("acme", added); err != nil {
		t.Fatal(err)
	}
	if b, _ := d.PurgedBlobs("acme"); len(b) != 2 || b["b3"] != "" {
		t.Fatalf("after the drop %v", b)
	}
	// an engagement made again under the same id inherits neither
	if err := d.Tx(func(tx *Tx) error { return tx.Purge("acme") }); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.Unpurged("acme", "F-001"); len(u) != 0 {
		t.Fatalf("marks survive the engagement: %v", u)
	}
	if b, _ := d.PurgedBlobs("acme"); len(b) != 0 {
		t.Fatalf("purged blobs survive the engagement: %v", b)
	}
}
