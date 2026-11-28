package db

import (
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/secret"
)

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

// AITokens sums the tokens of the calls since a time (one query: it is asked
// before a provider call while a spend limit is set).
func (d *DB) AITokens(since time.Time) (in, out int, err error) {
	err = d.QueryRow("SELECT coalesce(sum(tokens_in), 0), coalesce(sum(tokens_out), 0) FROM ai_usage WHERE ts >= ?",
		since.UTC().Format(time.RFC3339)).Scan(&in, &out)
	return in, out, err
}

// AI price settings: per million tokens, decimal text ("" = no price).
const AIPriceInKey, AIPriceOutKey = "ai.price_in", "ai.price_out"

// AILimitKey is the AI spend limit: the most the calls of the last
// AILimitDays days may cost at the prices, decimal text ("" = no limit).
const AILimitKey = "ai.limit"

// AILimitDays is the period the AI spend limit counts; usage rows are kept
// at least that long (Prune).
const AILimitDays = 30

// The AI settings saved on Admin › AI (server_settings); the key is stored
// encrypted with the data folder's secret key.
const (
	AIProviderKey = "ai.provider"
	AIBaseKey     = "ai.base_url"
	AIModelKey    = "ai.model"
	AIKeyKey      = "ai.key"
)

// AIStored reads the AI settings saved on Admin › AI and decrypts the key
// ("" values: not set there, or not readable). open gives the box of the
// data folder's secret key; it is asked only when a key is stored. The
// server and yars lint read the settings through this.
func (d *DB) AIStored(open func() (*secret.Box, error)) (config.AIConfig, string) {
	all, err := d.Settings("ai.")
	if err != nil {
		return config.AIConfig{}, ""
	}
	c := config.AIConfig{Provider: all[AIProviderKey], BaseURL: all[AIBaseKey], Model: all[AIModelKey]}
	key := ""
	if enc := all[AIKeyKey]; enc != "" {
		if box, err := open(); err == nil {
			key, _ = box.Decrypt(enc)
		}
	}
	return c, key
}
