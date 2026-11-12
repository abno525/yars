package db

// D28: an image redacted after its original was committed keeps the
// original in the engagement's git history until a director purges it.

// NoteRedaction records that name of finding fid was redacted by by (after
// its commit); a purge noted before is cleared, as the new original is in
// history again.
func (d *DB) NoteRedaction(eng, fid, name, by string) error {
	_, err := d.Exec(`INSERT INTO redactions(eng, fid, name, at, by_user) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(eng, fid, name) DO UPDATE SET at = excluded.at, by_user = excluded.by_user, purged_at = ''`,
		eng, fid, name, d.stamp(), by)
	return err
}

// Unpurged names the attachments of finding fid whose originals are still in
// history.
func (d *DB) Unpurged(eng, fid string) (map[string]bool, error) {
	rows, err := d.Query("SELECT name FROM redactions WHERE eng = ? AND fid = ? AND purged_at = ''", eng, fid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// MarkPurged records that the originals of name were purged and remembers
// their blob ids, so a push cannot bring them back.
func (d *DB) MarkPurged(eng, fid, name string, blobs []string) error {
	return d.Tx(func(tx *Tx) error {
		now := tx.stamp()
		if _, err := tx.Exec(`INSERT INTO redactions(eng, fid, name, at, by_user, purged_at) VALUES (?, ?, ?, ?, '', ?)
			ON CONFLICT(eng, fid, name) DO UPDATE SET purged_at = excluded.purged_at`, eng, fid, name, now, now); err != nil {
			return err
		}
		for _, b := range blobs {
			if _, err := tx.Exec("INSERT OR IGNORE INTO purged_blobs(eng, blob, name, at) VALUES (?, ?, ?, ?)", eng, b, name, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// PurgedBlobs maps the purged blob ids of an engagement to their file names.
func (d *DB) PurgedBlobs(eng string) (map[string]string, error) {
	rows, err := d.Query("SELECT blob, name FROM purged_blobs WHERE eng = ?", eng)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var b, n string
		if err := rows.Scan(&b, &n); err != nil {
			return nil, err
		}
		out[b] = n
	}
	return out, rows.Err()
}
