package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
)

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// ViolationHash identifies one place a rule found something, for dismissals,
// stored results and comments: the target (section, row, title) and the
// quote, so that a dismissal covers that one result row only (the same
// wording elsewhere still counts).
func ViolationHash(target, quote string) string {
	if quote == "" {
		return shortHash("\x00" + target)
	}
	return shortHash(target + "\x00" + quote)
}

// LegacyHash is how dismissals made before they were per row were keyed:
// by the quote alone (one covered the quote in every place).
func LegacyHash(quote string) string { return shortHash(quote) }

// Lookup finds the dismissal of the violation (rule, target, quote) in ds:
// its own, or one made before dismissals were per row (rule and quote only),
// which still covers it.
func Lookup(ds map[string]Dismissal, rule, target, quote string) (Dismissal, bool) {
	if d, ok := ds[DismissKey(rule, ViolationHash(target, quote))]; ok {
		return d, true
	}
	if quote != "" {
		if d, ok := ds[DismissKey(rule, LegacyHash(quote))]; ok {
			return d, true
		}
	}
	return Dismissal{}, false
}

// perRowDismissals (schema v14) keys the stored check results by target and
// quote (ViolationHash) instead of by quote alone, and gives each dismissal
// made before a copy for every place a run found its quote, so the old
// dismissals keep covering what they covered. A dismissal no run ever
// stored a result for stays as it is (Lookup still finds it).
func perRowDismissals(tx *sql.Tx) error {
	type res struct {
		id                         int64
		eng, fid, rule, target, qt string
	}
	rows, err := tx.Query(`SELECT r.rowid, c.eng, c.fid, r.rule, r.target, r.quote FROM check_results r
		JOIN check_runs c ON c.id = r.run_id WHERE r.quote != ''`)
	if err != nil {
		return err
	}
	var all []res
	for rows.Next() {
		var x res
		if err := rows.Scan(&x.id, &x.eng, &x.fid, &x.rule, &x.target, &x.qt); err != nil {
			rows.Close()
			return err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range all {
		if _, err := tx.Exec("UPDATE check_results SET quote_hash = ? WHERE rowid = ?", ViolationHash(x.target, x.qt), x.id); err != nil {
			return err
		}
		// a copy of an old dismissal of the quote for this place
		if _, err := tx.Exec(`INSERT OR IGNORE INTO dismissals(eng, fid, rule, quote_hash, level, by_user, at, reason)
			SELECT eng, fid, rule, ?, level, by_user, at, reason FROM dismissals WHERE eng = ? AND fid = ? AND rule = ? AND quote_hash = ?`,
			ViolationHash(x.target, x.qt), x.eng, x.fid, x.rule, LegacyHash(x.qt)); err != nil {
			return err
		}
	}
	return nil
}
