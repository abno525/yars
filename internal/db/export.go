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

// ExportRemote is the page or issue a finding became at a destination:
// Target is the service address and project or space it lives in, RemoteID
// the Jira issue key or Confluence page id, Version the page version.
type ExportRemote struct {
	Destination, Eng, Finding string
	Target, RemoteID          string
	Version                   int
	URL, Updated              string
}

// SetExportRemote remembers (or replaces) a finding's page or issue.
func (d *DB) SetExportRemote(r ExportRemote) error {
	_, err := d.Exec(`INSERT INTO export_remote(destination, eng, finding, target, remote_id, version, url, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(destination, eng, finding) DO UPDATE SET target = excluded.target, remote_id = excluded.remote_id,
			version = excluded.version, url = excluded.url, updated = excluded.updated`,
		r.Destination, r.Eng, r.Finding, r.Target, r.RemoteID, r.Version, r.URL, d.stamp())
	return err
}

// ExportRemote returns a finding's remembered page or issue.
func (d *DB) ExportRemote(dest, eng, finding string) (ExportRemote, bool, error) {
	r := ExportRemote{Destination: dest, Eng: eng, Finding: finding}
	err := d.QueryRow(`SELECT target, remote_id, version, url, updated FROM export_remote WHERE destination = ? AND eng = ? AND finding = ?`,
		dest, eng, finding).Scan(&r.Target, &r.RemoteID, &r.Version, &r.URL, &r.Updated)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

// SwapExportFindings replaces an export's findings JSON when it is still
// old; false when another request changed it first.
func (d *DB) SwapExportFindings(id int64, old, new string) (bool, error) {
	res, err := d.Exec("UPDATE export_history SET findings = ? WHERE id = ? AND findings = ?", new, id, old)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Export returns one export by id.
func (d *DB) Export(id int64) (ExportRecord, bool, error) {
	r, err := scanExport(d.QueryRow("SELECT "+exportCols+" FROM export_history WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}
