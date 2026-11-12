package store

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"yars/internal/finding"
	"yars/internal/workflow"
)

func pngBytes(t *testing.T, c color.Color) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	for x := 0; x < 4; x++ {
		for y := 0; y < 4; y++ {
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestUpdateAssets(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding(eng, "XSS", alice)
	ref, _ := s.Finding(eng, f.Dir)
	base := AssetsHash(ref.F.Meta)
	list := []finding.Asset{{Host: "app.example", Port: "443"}, {URL: "https://app.example/search", Note: "q"}, {}}
	if err := s.UpdateAssets(eng, f.Dir, list, base, m17Pen); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%an|%s"); got != "alice|F-001: edit assets" {
		t.Fatalf("commit %q", got)
	}
	ref, _ = s.Finding(eng, f.Dir)
	if len(ref.F.Meta.Assets) != 2 || ref.F.Meta.Assets[0].Port != "443" || ref.F.Meta.Assets[1].Note != "q" {
		t.Fatalf("assets %+v", ref.F.Meta.Assets)
	}
	// a stale base is a conflict
	if err := s.UpdateAssets(eng, f.Dir, nil, base, m17Pen); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale base: %v", err)
	}
	for _, bad := range [][]finding.Asset{
		{{Note: "only a note"}},
		{{Host: "a.example", Port: "http"}},
		{{Host: "a.example", Port: "70000"}},
		{{Host: "a\nb"}},
		{{URL: "not a url"}},
	} {
		if err := s.UpdateAssets(eng, f.Dir, bad, "", m17Pen); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	// emptying removes the key
	if err := s.UpdateAssets(eng, f.Dir, nil, AssetsHash(ref.F.Meta), m17Pen); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "engagements", eng, "findings", f.Dir, "finding.md"))
	if strings.Contains(string(b), "assets") {
		t.Fatalf("assets left:\n%s", b)
	}
}

// hasOriginal is whether the finding's attachment name is marked.
func hasOriginal(t *testing.T, s *Store, dir, name string) bool {
	t.Helper()
	as, err := s.Attachments(eng, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.Name == name {
			return a.HasOriginal
		}
	}
	t.Fatalf("no attachment %s in %+v", name, as)
	return false
}

// D28: a redaction of a committed image leaves its original in history,
// and Attachments says so.
func TestRedactRecordsRow(t *testing.T) {
	s, _ := withEngagement(t)
	f, _ := s.CreateFinding(eng, "XSS", alice)
	name, err := s.AddAttachment(eng, f.Dir, "shot.png", pngBytes(t, color.White), m17Pen)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.AddAttachment(eng, f.Dir, "other.png", pngBytes(t, color.White), m17Pen)
	if err := s.ReplaceAttachment(eng, f.Dir, name, pngBytes(t, color.Black), m17Pen); err != nil {
		t.Fatal(err)
	}
	if !hasOriginal(t, s, f.Dir, name) || hasOriginal(t, s, f.Dir, other) {
		t.Fatal("the mark is not on the redacted image only")
	}
	if u, _ := s.DB().Unpurged(eng, "F-001"); !u[name] {
		t.Fatalf("no row under the finding's id: %v", u)
	}
}

// D28, Review focus 5: an image redacted in the browser before its first
// upload has no original on the server: no mark.
func TestFirstUploadHasNoMark(t *testing.T) {
	s, _ := withEngagement(t)
	f, _ := s.CreateFinding(eng, "XSS", alice)
	name, err := s.AddAttachment(eng, f.Dir, "shot.png", pngBytes(t, color.Black), m17Pen)
	if err != nil {
		t.Fatal(err)
	}
	if hasOriginal(t, s, f.Dir, name) {
		t.Fatal("a first upload is marked")
	}
}

func TestAttachments(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding(eng, "XSS", alice)
	img := pngBytes(t, color.White)
	name, err := s.AddAttachment(eng, f.Dir, "../My Shot (1).png", img, m17Pen)
	if err != nil {
		t.Fatal(err)
	}
	if name != "My-Shot-1-.png" {
		t.Fatalf("name %q", name)
	}
	if got := last(t, dir, "%an|%s"); got != "alice|F-001: attach "+name {
		t.Fatalf("commit %q", got)
	}
	// the same name again gets a suffix
	name2, err := s.AddAttachment(eng, f.Dir, "My Shot (1).png", img, m17Pen)
	if err != nil || name2 != "My-Shot-1--2.png" {
		t.Fatalf("second %q %v", name2, err)
	}
	if _, err := s.AddAttachment(eng, f.Dir, "req.txt", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), m17Pen); err != nil {
		t.Fatal(err)
	}
	// not image/* or text/*
	if _, err := s.AddAttachment(eng, f.Dir, "a.zip", []byte("PK\x03\x04aaaa"), m17Pen); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("zip: %v", err)
	}
	if _, err := s.AddAttachment(eng, f.Dir, "big.txt", bytes.Repeat([]byte("a"), MaxAttachment+1), m17Pen); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("big: %v", err)
	}
	as, err := s.Attachments(eng, f.Dir)
	if err != nil || len(as) != 3 || as[0].Name != "My-Shot-1--2.png" || !as[0].Image || as[2].Name != "req.txt" || as[2].Image || as[2].Size == 0 {
		t.Fatalf("list %+v %v", as, err)
	}
	// redact: the new image replaces the file in a new commit
	black := pngBytes(t, color.Black)
	if err := s.ReplaceAttachment(eng, f.Dir, name, black, m17Pen); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%s"); got != "F-001: redact "+name {
		t.Fatalf("commit %q", got)
	}
	if b, _ := s.ReadAttachment(eng, f.Dir, "attachments/"+name); !bytes.Equal(b, black) {
		t.Fatal("not replaced")
	}
	if err := s.ReplaceAttachment(eng, f.Dir, "req.txt", black, m17Pen); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("redact text: %v", err)
	}
	if err := s.ReplaceAttachment(eng, f.Dir, name, []byte("text"), m17Pen); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("replace with text: %v", err)
	}
	if err := s.ReplaceAttachment(eng, f.Dir, "nope.png", black, m17Pen); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	// a locked finding refuses a pentester
	if err := s.Transition(eng, f.Dir, workflow.Withdraw, "dup", m17Dir); err != nil {
		t.Fatal(err)
	}
	var d *workflow.Denied
	if _, err := s.AddAttachment(eng, f.Dir, "x.txt", []byte("x"), m17Pen); !errors.As(err, &d) {
		t.Fatalf("locked: %v", err)
	}
}

// Dot runs collapse in upload names, and a name with ".." already in the
// folder (a git push) is listed and readable alike.
func TestAttachmentDotNames(t *testing.T) {
	for in, want := range map[string]string{"shot..png": "shot.png", "a...b..c.txt": "a.b.c.txt", "..png": "png"} {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding(eng, "XSS", alice)
	name, err := s.AddAttachment(eng, f.Dir, "shot..png", pngBytes(t, color.White), m17Pen)
	if err != nil || name != "shot.png" {
		t.Fatalf("add %q %v", name, err)
	}
	att := filepath.Join(dir, "engagements", eng, "findings", f.Dir, "attachments")
	os.WriteFile(filepath.Join(att, "x..y.txt"), []byte("pushed"), 0o644)
	as, _ := s.Attachments(eng, f.Dir)
	for _, a := range as {
		if _, err := s.ReadAttachment(eng, f.Dir, "attachments/"+a.Name); err != nil {
			t.Errorf("listed %s unreadable: %v", a.Name, err)
		}
	}
	if len(as) != 2 {
		t.Fatalf("list %+v", as)
	}
}

// Merge copies every listed attachment, a pushed one over the web read cap
// or with ".." in its name included.
func TestMergeCopiesPushedAttachments(t *testing.T) {
	s, dir := withEngagement(t)
	dst, _ := s.CreateFinding(eng, "Dst", alice)
	src, _ := s.CreateFinding(eng, "Src", alice)
	s.UpdateSection(eng, src.Dir, "Impact", "See it.", "", alice)
	att := filepath.Join(dir, "engagements", eng, "findings", src.Dir, "attachments")
	os.MkdirAll(att, 0o755)
	big := bytes.Repeat([]byte("a"), 21<<20)
	os.WriteFile(filepath.Join(att, "big.txt"), big, 0o644)
	os.WriteFile(filepath.Join(att, "x..y.txt"), []byte("dots"), 0o644)
	if err := s.Merge(eng, src.Dir, dst.Dir, m17Dir); err != nil {
		t.Fatal(err)
	}
	dat := filepath.Join(dir, "engagements", eng, "findings", dst.Dir, "attachments")
	if b, err := os.ReadFile(filepath.Join(dat, "big.txt")); err != nil || len(b) != len(big) {
		t.Fatalf("big copy %d %v", len(b), err)
	}
	if b, err := os.ReadFile(filepath.Join(dat, "x..y.txt")); err != nil || string(b) != "dots" {
		t.Fatalf("dots copy %q %v", b, err)
	}
}

// A renamed attachment's links change only where they name exactly it:
// a.png is renamed, a.png.txt is not.
func TestMergeRewritesExactLinks(t *testing.T) {
	s, _ := withEngagement(t)
	dst, _ := s.CreateFinding(eng, "Dst", alice)
	src, _ := s.CreateFinding(eng, "Src", alice)
	s.AddAttachment(eng, dst.Dir, "a.png", pngBytes(t, color.White), alice)
	s.AddAttachment(eng, src.Dir, "a.png", pngBytes(t, color.Black), alice)
	s.AddAttachment(eng, src.Dir, "a.png.txt", []byte("log"), alice)
	s.UpdateSection(eng, src.Dir, "Impact", "![a](attachments/a.png) [log](attachments/a.png.txt) see attachments/a.png.", "", alice)
	if err := s.Merge(eng, src.Dir, dst.Dir, m17Dir); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Finding(eng, dst.Dir)
	impact, _ := d.F.Section("Impact")
	want := "![a](attachments/F-002-a.png) [log](attachments/a.png.txt) see attachments/F-002-a.png."
	if !strings.Contains(impact, want) {
		t.Fatalf("impact %q", impact)
	}
}

// A merge that fails after the source was withdrawn puts the source's
// state back; two merges of one source at once: one wins.
func TestMergeAtomic(t *testing.T) {
	s, dir := withEngagement(t)
	dst, _ := s.CreateFinding(eng, "Dst", alice)
	src, _ := s.CreateFinding(eng, "Src", alice)
	s.UpdateSection(eng, src.Dir, "Impact", "Src text.", "", alice)
	// an unclosed fence in dst makes the merged text invalid
	fp := filepath.Join(dir, "engagements", eng, "findings", dst.Dir, "finding.md")
	b, _ := os.ReadFile(fp)
	os.WriteFile(fp, []byte(strings.Replace(string(b), "## Impact\n", "## Impact\n\n```\nopen fence\n", 1)), 0o644)
	if err := s.Merge(eng, src.Dir, dst.Dir, m17Dir); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("merge into broken dst: %v", err)
	}
	sr, _ := s.Finding(eng, src.Dir)
	if sr.F.Meta.Status != "draft" || sr.F.Meta.Withdrawn != nil {
		t.Fatalf("source after failed merge %q %+v", sr.F.Meta.Status, sr.F.Meta.Withdrawn)
	}
	os.WriteFile(fp, b, 0o644)

	a, _ := s.CreateFinding(eng, "A", alice)
	c, _ := s.CreateFinding(eng, "C", alice)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, to := range []string{a.Dir, c.Dir} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Merge(eng, src.Dir, to, m17Dir)
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("two merges of one source: %v / %v", errs[0], errs[1])
	}
	n := 0
	for _, to := range []string{a.Dir, c.Dir} {
		f, _ := s.Finding(eng, to)
		if imp, _ := f.F.Section("Impact"); strings.Contains(imp, "Merged from") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("source merged into %d findings", n)
	}
}

// A director's merge into a complete finding keeps it complete: the
// approval moves to the merged content, as with any director edit.
func TestMergeKeepsApproval(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	src, err := s.CreateFinding(eng, "Second", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, src.Dir, "Impact", "More impact.", "", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Merge(eng, src.Dir, fd, uDora); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Finding(eng, fd)
	if impact, _ := d.F.Section("Impact"); !strings.Contains(impact, "More impact.") {
		t.Fatalf("not merged: %q", impact)
	}
	if d.F.Meta.Status != "complete" {
		t.Fatalf("status after merge %q, want complete", d.F.Meta.Status)
	}
}

func TestMerge(t *testing.T) {
	s, dir := withEngagement(t)
	dst, _ := s.CreateFinding(eng, "SQL injection in login", alice)
	src, _ := s.CreateFinding(eng, "SQL injection in export", alice)
	s.UpdateSection(eng, dst.Dir, "Impact", "Read the DB.", "", alice)
	s.UpdateSection(eng, src.Dir, "Impact", "Also export.\n\n![x](attachments/shot.png)", "", alice)
	s.UpdateSection(eng, src.Dir, "Remediation", "Bind params.", "", alice)
	s.UpdateAssets(eng, dst.Dir, []finding.Asset{{Host: "app.example"}}, "", alice)
	s.UpdateAssets(eng, src.Dir, []finding.Asset{{Host: "APP.example"}, {URL: "https://app.example/export"}}, "", alice)
	img := pngBytes(t, color.White)
	s.AddAttachment(eng, dst.Dir, "shot.png", img, alice)
	s.AddAttachment(eng, src.Dir, "shot.png", pngBytes(t, color.Black), alice)

	if err := s.Merge(eng, src.Dir, src.Dir, m17Dir); err == nil {
		t.Fatal("merged into itself")
	}
	if err := s.Merge(eng, src.Dir, dst.Dir, m17Dir); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%an|%s"); got != "dora|F-001: merge F-002" {
		t.Fatalf("commit %q", got)
	}
	d, _ := s.Finding(eng, dst.Dir)
	impact, _ := d.F.Section("Impact")
	if !strings.Contains(impact, "Read the DB.\n\n### Merged from F-002\n\nAlso export.") || !strings.Contains(impact, "attachments/F-002-shot.png") {
		t.Fatalf("impact %q", impact)
	}
	if rem, _ := d.F.Section("Remediation"); !strings.Contains(rem, "### Merged from F-002\n\nBind params.") {
		t.Fatalf("remediation %q", rem)
	}
	if desc, _ := d.F.Section("Description"); strings.Contains(desc, "Merged") {
		t.Fatalf("empty section merged: %q", desc)
	}
	if len(d.F.Meta.Assets) != 2 || d.F.Meta.Assets[1].URL != "https://app.example/export" {
		t.Fatalf("assets %+v", d.F.Meta.Assets)
	}
	if b, err := s.ReadAttachment(eng, dst.Dir, "attachments/F-002-shot.png"); err != nil || !bytes.Equal(b, pngBytes(t, color.Black)) {
		t.Fatalf("attachment copy %v", err)
	}
	if b, _ := s.ReadAttachment(eng, dst.Dir, "attachments/shot.png"); !bytes.Equal(b, img) {
		t.Fatal("target attachment overwritten")
	}
	sr, _ := s.Finding(eng, src.Dir)
	if sr.F.Meta.Status != workflow.Withdrawn || sr.F.Meta.Withdrawn == nil || sr.F.Meta.Withdrawn.Reason != "merged into F-001" {
		t.Fatalf("source %+v %+v", sr.F.Meta.Status, sr.F.Meta.Withdrawn)
	}
	msgs, _ := s.Chat(eng, dst.Dir)
	if len(msgs) == 0 || msgs[len(msgs)-1].Event != EventMerge || msgs[len(msgs)-1].Text != "F-002" {
		t.Fatalf("target events %+v", msgs)
	}
	smsgs, _ := s.Chat(eng, src.Dir)
	if len(smsgs) == 0 || smsgs[len(smsgs)-1].Event != "withdraw" {
		t.Fatalf("source events %+v", smsgs)
	}
	// a withdrawn finding can't be merged again
	if err := s.Merge(eng, src.Dir, dst.Dir, m17Dir); err == nil {
		t.Fatal("merged a withdrawn finding")
	}
	// only a director
	other, _ := s.CreateFinding(eng, "Third", alice)
	var den *workflow.Denied
	if err := s.Merge(eng, other.Dir, dst.Dir, m17Pen); !errors.As(err, &den) {
		t.Fatalf("pentester: %v", err)
	}
}
