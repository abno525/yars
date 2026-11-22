package db

import (
	"database/sql"
	"errors"
)

// RuleCacheMax bounds rule_cache: storing past it drops the oldest rows.
const RuleCacheMax = 50000

// RuleResult returns the result of a script or AI rule stored under key
// (rules.ResultStore); ok is false when there is none.
func (d *DB) RuleResult(key string) (result string, ok bool, err error) {
	err = d.QueryRow("SELECT result FROM rule_cache WHERE key = ?", key).Scan(&result)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return result, err == nil, err
}

// PutRuleResult stores the result (JSON) of a script or AI rule under key;
// kind is ai or script. The table keeps the RuleCacheMax newest rows.
func (d *DB) PutRuleResult(key, kind, result string) error {
	return d.putRuleResult(key, kind, result, RuleCacheMax)
}

// putRuleResult is PutRuleResult keeping the keep newest rows. A row stored
// later has a higher rowid (one more than the highest, as nothing deletes
// the newest row), so the rows within keep of the highest are the newest;
// a key stored again counts as new. (Not d.Tx: a stored result is no
// change the pages follow.)
func (d *DB) putRuleResult(key, kind, result string, keep int) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT OR REPLACE INTO rule_cache(key, kind, result, created) VALUES (?, ?, ?, ?)", key, kind, result, d.now().Unix()); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM rule_cache WHERE rowid <= (SELECT max(rowid) FROM rule_cache) - ?", keep); err != nil {
		return err
	}
	return tx.Commit()
}
