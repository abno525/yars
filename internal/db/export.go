package db

import (
	"database/sql"
	"errors"
)

// ExportRecord is one export: a download or a send to a destination.
// Findings is JSON (the web's per-finding results); SentAs names whose keys
// sent it ("pen1, server"; "" for files).
type ExportRecord struct {
	ID                       int64
	TS, By, Eng, Destination string
	Findings                 string
	OK                       bool
	Error, URL, SentAs       string
}

// AddExport records an export and returns its id.
func (d *DB) AddExport(r ExportRecord) (int64, error) {
	if r.Findings == "" {
		r.Findings = "[]"
	}
	res, err := d.Exec(`INSERT INTO export_history(ts, by_user, eng, destination, findings, ok, error, url, sent_as)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, d.stamp(), r.By, r.Eng, r.Destination, r.Findings, r.OK, r.Error, r.URL, r.SentAs)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const exportCols = "id, ts, by_user, eng, destination, findings, ok, error, url, sent_as"

func scanExport(s interface{ Scan(...any) error }) (ExportRecord, error) {
	var r ExportRecord
	err := s.Scan(&r.ID, &r.TS, &r.By, &r.Eng, &r.Destination, &r.Findings, &r.OK, &r.Error, &r.URL, &r.SentAs)
	return r, err
}

// Exports lists an engagement's newest limit exports, newest first.
func (d *DB) Exports(eng string, limit int) ([]ExportRecord, error) {
	rows, err := d.Query("SELECT "+exportCols+" FROM export_history WHERE eng = ? ORDER BY id DESC LIMIT ?", eng, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExportRecord
	for rows.Next() {
		r, err := scanExport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Export returns one export by id.
func (d *DB) Export(id int64) (ExportRecord, bool, error) {
	r, err := scanExport(d.QueryRow("SELECT "+exportCols+" FROM export_history WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}
