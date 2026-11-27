package store

import (
	"image/color"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/workflow"
)

// stopAfterCommit runs fn and stops it right after its commit is made,
// before the database write that follows it: what a killed server leaves.
func stopAfterCommit(t *testing.T, s *Store, fn func()) {
	t.Helper()
	type stopped struct{}
	s.afterCommit = func() { panic(stopped{}) }
	defer func() {
		s.afterCommit = nil
		r := recover()
		if _, ok := r.(stopped); !ok {
			t.Fatalf("the write was not stopped after its commit (%v)", r)
		}
	}()
	fn()
}

// restarted is a new store on the same data folder and database, as the
// next start opens one, logging to a recorder.
func restarted(t *testing.T, s *Store) (*Store, *logs.Recorder) {
	t.Helper()
	s2 := New(s.repo, s.Config(), s.db)
	lg, out := logs.NewRecorder()
	s2.Logger = lg
	return s2, out
}

func recovered(t *testing.T, s *Store) Integrity {
	t.Helper()
	res, err := s.Recover()
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func repairs(t *testing.T, s *Store) []db.AuditEntry {
	t.Helper()
	l, _, err := s.DB().AuditQuery(db.AuditFilter{Action: "system.repair", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

const repairedMsg = "start: a database write that a stop cut off was made"

// A director's edit of an approved finding commits and then carries the
// approval. A stop in between leaves the new text without its approval: the
// finding reads as in verification. The next start carries it, and says so
// in an audit row and a log line that name the finding by its ID.
func TestRecoverCarriesApprovalAfterStop(t *testing.T) {
	s, dir, fd := ready(t)
	fid := load(t, s, fd).F.Meta.ID
	old := ApprovalHash(rawFile(t, dir, fd))
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: old})
	stopAfterCommit(t, s, func() {
		s.UpdateSection(eng, fd, "Impact", "Changed by the director.", "", uDora)
	})
	now := ApprovalHash(rawFile(t, dir, fd))
	s2, out := restarted(t, s)
	// the leftover: the commit is there, the approval is for the old text
	if m := load(t, s2, fd).F.Meta; now == old || m.Status != "verification" {
		t.Fatalf("after the stop: %s (text changed: %v)", m.Status, now != old)
	}
	res := recovered(t, s2)
	if m := load(t, s2, fd).F.Meta; m.Status != "complete" {
		t.Fatalf("after the start: %s, want complete", m.Status)
	}
	if st := stateOf(t, s2, fd); st.ApprovedHash != now {
		t.Fatalf("approval bound to %q, want the committed text %s", st.ApprovedHash, now)
	}
	if !reflect.DeepEqual(res.Replayed, []string{eng + "/" + fid}) || len(res.Unreplayed) != 0 {
		t.Fatalf("result %+v", res)
	}
	l := repairs(t, s2)
	if len(l) != 1 || l[0].Actor != "yars" || l[0].Target != eng+"/"+fid || l[0].Detail != "approval carried to the committed text" {
		t.Fatalf("audit %+v", l)
	}
	recs := out.With(repairedMsg)
	if len(recs) != 1 || recs[0].Str("eng") != eng || recs[0].Str("finding") != fid || recs[0].Str("kind") != "carry" {
		t.Fatalf("log:\n%s", out.Text())
	}
	if strings.Contains(out.Text(), strings.TrimPrefix(fd, fid+"-")) {
		t.Fatalf("the log names the folder:\n%s", out.Text())
	}
	// a second start finds nothing to do
	s3, out3 := restarted(t, s)
	if res := recovered(t, s3); len(res.Replayed) != 0 || len(res.Unreplayed) != 0 {
		t.Fatalf("second start: %+v", res)
	}
	if len(repairs(t, s3)) != 1 || len(out3.Records()) != 0 {
		t.Fatalf("second start: %d audit rows, log:\n%s", len(repairs(t, s3)), out3.Text())
	}
	if ins, err := s.DB().Intents(); err != nil || len(ins) != 0 {
		t.Fatalf("journal after the start: %+v %v", ins, err)
	}
}

// A write that ends leaves no journal row, and neither does an edit that
// carries nothing (an author's edit of a draft).
func TestJournalIsEmptyAfterAWrite(t *testing.T) {
	s, dir, fd := ready(t)
	if err := s.UpdateSection(eng, fd, "Impact", "A draft's text.", "", uAlice); err != nil {
		t.Fatal(err)
	}
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: ApprovalHash(rawFile(t, dir, fd))})
	// the row is there between the commit and the write it stands for
	seen := 0
	s.afterCommit = func() {
		ins, err := s.DB().Intents()
		if err != nil || len(ins) != 1 || ins[0].Kind != db.IntentCarry || ins[0].Eng != eng || ins[0].New == ins[0].Old {
			t.Errorf("journal between commit and write: %+v %v", ins, err)
		}
		seen++
	}
	if err := s.UpdateSection(eng, fd, "Impact", "Changed by the director.", "", uDora); err != nil {
		t.Fatal(err)
	}
	s.afterCommit = nil
	if _, err := s.RenameNames("section", toBusiness, alice); err != nil {
		t.Fatal(err)
	}
	if ins, err := s.DB().Intents(); err != nil || len(ins) != 0 || seen != 1 {
		t.Fatalf("journal after the writes: %+v %v (seen %d)", ins, err, seen)
	}
	if load(t, s, fd).F.Meta.Status != "complete" {
		t.Fatal("the approval was not carried")
	}
}

// A structure rename commits each finding and then moves its approval,
// sign-offs and chat sections. A stop after the first finding's commit: the
// next start moves them for that finding, and leaves the findings the rename
// had not reached as they are.
func TestRecoverFinishesRenameAfterStop(t *testing.T) {
	s, dir, fd := ready(t)
	fid := load(t, s, fd).F.Meta.ID
	if err := s.UpdateSection(eng, fd, "Impact", "Data loss.", "", alice); err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateFinding(eng, "Second finding", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, second.Dir, "Impact", "Other data.", "", alice); err != nil {
		t.Fatal(err)
	}
	secondRaw := rawFile(t, dir, second.Dir)
	if _, err := s.PostChat(eng, fd, chat.Message{Text: "which data?", Section: "Impact"}, uBob); err != nil {
		t.Fatal(err)
	}
	old := ApprovalHash(rawFile(t, dir, fd))
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: old, Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: old}}})
	stopAfterCommit(t, s, func() { s.RenameNames("section", toBusiness, alice) })
	now := ApprovalHash(rawFile(t, dir, fd))
	s2, out := restarted(t, s)
	if m := load(t, s2, fd).F.Meta; now == old || m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("after the stop: %s, cleared by %v", m.Status, m.ClearedBy)
	}
	res := recovered(t, s2)
	st := stateOf(t, s2, fd)
	if st.ApprovedHash != now || st.Reviewers[0].ClearedHash != now {
		t.Fatalf("approval %q, sign-off %q, want %s", st.ApprovedHash, st.Reviewers[0].ClearedHash, now)
	}
	if m := load(t, s2, fd).F.Meta; m.Status != "complete" || !slices.Contains(m.ClearedBy, "bob") {
		t.Fatalf("after the start: %s, cleared by %v", m.Status, m.ClearedBy)
	}
	if msgs, _ := s2.Chat(eng, fd); len(msgs) != 1 || msgs[0].Section != "Business impact" {
		t.Fatalf("chat %+v", msgs)
	}
	if !reflect.DeepEqual(res.Replayed, []string{eng + "/" + fid}) || len(res.Unreplayed) != 0 {
		t.Fatalf("result %+v", res)
	}
	if l := repairs(t, s2); len(l) != 1 || l[0].Target != eng+"/"+fid || l[0].Detail != "approval, sign-offs and check run moved to the renamed text" {
		t.Fatalf("audit %+v", l)
	}
	if recs := out.With(repairedMsg); len(recs) != 1 || recs[0].Str("kind") != "rename" {
		t.Fatalf("log:\n%s", out.Text())
	}
	if strings.Contains(out.Text(), "Impact") {
		t.Fatalf("the log names a section:\n%s", out.Text())
	}
	// the finding the rename had not reached is not touched
	if string(rawFile(t, dir, second.Dir)) != string(secondRaw) {
		t.Fatal("the start changed a finding the rename had not reached")
	}
}

// What the start must not repair: nothing in the journal proves a stop.
func TestRecoverLeavesWhatItCannotProve(t *testing.T) {
	s, dir, fd := ready(t)
	fid := load(t, s, fd).F.Meta.ID
	old := ApprovalHash(rawFile(t, dir, fd))
	p := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	edit := func(more string) string {
		t.Helper()
		if err := os.WriteFile(p, append(rawFile(t, dir, fd), []byte(more)...), 0o644); err != nil {
			t.Fatal(err)
		}
		return ApprovalHash(rawFile(t, dir, fd))
	}
	unchanged := func(name string, res Integrity, s2 *Store, wantUnreplayed int) {
		t.Helper()
		if st := stateOf(t, s2, fd); st.ApprovedHash != old {
			t.Fatalf("%s: the approval moved to %q", name, st.ApprovedHash)
		}
		if len(res.Replayed) != 0 || len(res.Unreplayed) != wantUnreplayed || len(repairs(t, s2)) != 0 {
			t.Fatalf("%s: result %+v, %d audit rows", name, res, len(repairs(t, s2)))
		}
		if ins, err := s.DB().Intents(); err != nil || len(ins) != 0 {
			t.Fatalf("%s: journal %+v %v", name, ins, err)
		}
	}
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: old})

	// an approval for the text before an edit, and no journal row: the
	// designed drift (an approval that raced an edit, a push)
	now := edit("\nmore\n")
	s2, out := restarted(t, s)
	unchanged("no row", recovered(t, s2), s2, 0)
	if load(t, s2, fd).F.Meta.Status != "verification" || len(out.Records()) != 0 {
		t.Fatalf("no row: %s, log:\n%s", load(t, s2, fd).F.Meta.Status, out.Text())
	}

	// a row whose new digest is not the file's: left, said once, and gone
	if err := s.DB().PutIntent(db.Intent{Eng: eng, Fid: fid, Kind: db.IntentCarry, Old: old, New: strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	s2, out = restarted(t, s)
	res := recovered(t, s2)
	unchanged("another digest", res, s2, 1)
	if !reflect.DeepEqual(res.Unreplayed, []string{eng + "/" + fid}) {
		t.Fatalf("another digest: %+v", res)
	}
	recs := out.With("start: a journal row matches nothing and is dropped; nothing was changed")
	if len(recs) != 1 || recs[0].Str("eng") != eng || recs[0].Str("finding") != fid {
		t.Fatalf("another digest: log:\n%s", out.Text())
	}

	// a row whose commit never landed (the file has the old digest): gone,
	// without a word
	if err := s.DB().PutIntent(db.Intent{Eng: eng, Fid: fid, Kind: db.IntentCarry, Old: now, New: strings.Repeat("cd", 32)}); err != nil {
		t.Fatal(err)
	}
	s2, out = restarted(t, s)
	unchanged("no commit", recovered(t, s2), s2, 0)
	if len(out.Records()) != 0 {
		t.Fatalf("no commit: log:\n%s", out.Text())
	}

	// a row for the file as it is, while the approval is no longer the one
	// for the old text (the finding was taken back meanwhile): the live
	// write would carry nothing, and so does the start
	putState(t, s, fd, db.State{Status: "draft"})
	if err := s.DB().PutIntent(db.Intent{Eng: eng, Fid: fid, Kind: db.IntentCarry, Old: old, New: now}); err != nil {
		t.Fatal(err)
	}
	s2, _ = restarted(t, s)
	if res := recovered(t, s2); len(res.Replayed) != 0 || len(repairs(t, s2)) != 0 || stateOf(t, s2, fd).Status != "draft" {
		t.Fatalf("state moved on: %+v, %s", res, stateOf(t, s2, fd).Status)
	}

	// rows that name nothing readable: an unknown kind, an engagement that is
	// not there, a value that is no JSON
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: old})
	for _, in := range []db.Intent{
		{Eng: eng, Fid: fid, Kind: "purge", Old: old, New: now},
		{Eng: "gone", Fid: "F-001", Kind: db.IntentCarry, Old: old, New: now},
		{Eng: eng, Fid: "../../x", Kind: db.IntentCarry, Old: old, New: now},
	} {
		if err := s.DB().PutIntent(in); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DB().SetSetting("intent:"+eng+"/F-777", "not json"); err != nil {
		t.Fatal(err)
	}
	s2, out = restarted(t, s)
	res = recovered(t, s2)
	unchanged("unreadable rows", res, s2, 4)
	if strings.Contains(out.Text(), "..") {
		t.Fatalf("the log holds a row's own words:\n%s", out.Text())
	}
}

// An attachment added to a finding in verification voids its sign-offs. The
// sign-offs go before the commit: a stop right after the commit leaves none
// standing for a file the reviewers never saw.
func TestAttachmentStopLeavesNoSignOff(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if c := load(t, s, fd).F.Meta.ClearedBy; !slices.Contains(c, "bob") {
		t.Fatalf("not signed off: %v", c)
	}
	stopAfterCommit(t, s, func() {
		s.AddAttachment(eng, fd, "shot.png", pngBytes(t, color.White), uAlice)
	})
	s2, _ := restarted(t, s)
	if atts, err := s2.Attachments(eng, fd); err != nil || len(atts) != 1 {
		t.Fatalf("the attachment's commit is not there: %v %v", atts, err)
	}
	if c := load(t, s2, fd).F.Meta.ClearedBy; len(c) != 0 {
		t.Fatalf("after the stop the sign-off of %v still counts for a file they never saw", c)
	}
}

// An attachment change whose commit fails puts the sign-offs back.
func TestAttachmentFailedCommitKeepsSignOff(t *testing.T) {
	s, dir, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	// git cannot write its index: the commit fails
	lock := filepath.Join(dir, "engagements", eng, ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.AddAttachment(eng, fd, "shot.png", pngBytes(t, color.White), uAlice)
	os.Remove(lock)
	if err == nil {
		t.Fatal("the commit went through with the index locked")
	}
	if atts, _ := s.Attachments(eng, fd); len(atts) != 0 {
		t.Fatalf("attachments after a failed commit: %v", atts)
	}
	if c := load(t, s, fd).F.Meta.ClearedBy; !slices.Contains(c, "bob") {
		t.Fatalf("the sign-off is gone after a commit that failed: %v", c)
	}
}
