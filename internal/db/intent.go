package db

import (
	"encoding/json"
	"slices"
	"strings"
)

// The journal of writes that follow a commit. A finding's commit and the
// database write that belongs to it are two steps; a stop between them
// leaves the commit without the write, and nothing in git proves afterwards
// that this is what happened. So the write is put down first: an Intent,
// stored under the engagement's lock before the commit and removed in the
// transaction that makes the write. A row that is still there at the next
// start is a write a stop cut off (store.Recover).
//
// The rows live in server_settings under "intent:<eng>/<fid>": one per
// finding, since a finding's commits are made one at a time.

const intentPrefix = "intent:"

// Intent kinds.
const (
	IntentCarry  = "carry"  // a director's edit of an approved finding: the approval follows the text
	IntentRename = "rename" // a structure rename: approval, sign-offs, check run and chat sections follow
)

// Intent is one journaled write: for finding Fid of engagement Eng, whose
// finding.md goes from the digest Old to the digest New (store.ApprovalHash)
// in the commit that follows.
type Intent struct {
	Eng  string `json:"-"`
	Fid  string `json:"-"`
	Kind string `json:"kind"`
	Old  string `json:"old"`
	New  string `json:"new"`
	// Sections is a section rename's old names and what each became (their
	// chat threads follow).
	Sections map[string]string `json:"sections,omitempty"`

	key string // the row's key as stored (Intents)
}

func intentKey(eng, fid string) string { return intentPrefix + eng + "/" + fid }

// PutIntent stores in, in place of an earlier row of the same finding.
func (d *DB) PutIntent(in Intent) error {
	js, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return d.SetSetting(intentKey(in.Eng, in.Fid), string(js))
}

// DropIntent removes the journal row of a finding (none is no error).
func (d *DB) DropIntent(eng, fid string) error {
	return d.SetSetting(intentKey(eng, fid), "")
}

// DropIntentRow removes a row Intents listed, whatever its key reads as.
func (d *DB) DropIntentRow(in Intent) error {
	if in.key == "" {
		return d.DropIntent(in.Eng, in.Fid)
	}
	return d.SetSetting(in.key, "")
}

// DropIntent removes the journal row of a finding inside the transaction
// that makes the write it stands for.
func (tx *Tx) DropIntent(eng, fid string) error {
	_, err := tx.Exec("DELETE FROM server_settings WHERE key = ?", intentKey(eng, fid))
	return err
}

// Changed is the number of rows this transaction's connection has written
// so far (SQLite's total_changes): the difference of two readings says
// whether the statements between them changed anything.
func (tx *Tx) Changed() (int64, error) {
	var n int64
	err := tx.QueryRow("SELECT total_changes()").Scan(&n)
	return n, err
}

// Intents lists the journal, by engagement and finding. A row whose value
// does not parse is listed with an empty Kind, so the reader can report and
// remove it.
func (d *DB) Intents() ([]Intent, error) {
	rows, err := d.Settings(intentPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]Intent, 0, len(rows))
	for k, v := range rows {
		var in Intent
		if json.Unmarshal([]byte(v), &in) != nil {
			in = Intent{}
		}
		// an engagement ID holds no slash, so the first one ends it
		in.Eng, in.Fid, _ = strings.Cut(strings.TrimPrefix(k, intentPrefix), "/")
		in.key = k
		out = append(out, in)
	}
	slices.SortFunc(out, func(a, b Intent) int {
		if c := strings.Compare(a.Eng, b.Eng); c != 0 {
			return c
		}
		return strings.Compare(a.Fid, b.Fid)
	})
	return out, nil
}
