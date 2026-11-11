package db

import "time"

// AIUsage is one call to the AI provider as stored (D24).
type AIUsage struct {
	TS, User, Purpose, Provider, Model, Eng, Fid, Rule string
	In, Out, MS                                        int
	OK                                                 bool
}

// AddAIUsage stores one call; an empty TS is now.
func (d *DB) AddAIUsage(u AIUsage) error {
	if u.TS == "" {
		u.TS = d.stamp()
	}
	ok := 0
	if u.OK {
		ok = 1
	}
	_, err := d.Exec(`INSERT INTO ai_usage(ts, username, purpose, provider, model, eng, fid, rule, tokens_in, tokens_out, ms, ok)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, u.TS, u.User, u.Purpose, u.Provider, u.Model, u.Eng, u.Fid, u.Rule, u.In, u.Out, u.MS, ok)
	return err
}

// AITotal is the calls and tokens of one user ("" = everyone).
type AITotal struct {
	User           string
	Calls, In, Out int
}

// AITotals sums the calls since a time: the total first, then one row per
// user by calls (most first, then by name).
func (d *DB) AITotals(since time.Time) ([]AITotal, error) {
	cut := since.UTC().Format(time.RFC3339)
	var all AITotal
	if err := d.QueryRow("SELECT count(*), coalesce(sum(tokens_in), 0), coalesce(sum(tokens_out), 0) FROM ai_usage WHERE ts >= ?", cut).Scan(&all.Calls, &all.In, &all.Out); err != nil {
		return nil, err
	}
	out := []AITotal{all}
	rows, err := d.Query(`SELECT username, count(*) AS n, sum(tokens_in), sum(tokens_out) FROM ai_usage WHERE ts >= ?
		GROUP BY username ORDER BY n DESC, username`, cut)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t AITotal
		if err := rows.Scan(&t.User, &t.Calls, &t.In, &t.Out); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AI price settings: per million tokens, decimal text ("" = no price).
const AIPriceInKey, AIPriceOutKey = "ai.price_in", "ai.price_out"
