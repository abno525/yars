package web

import (
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
)

// aiUsageView is Admin › System's AI usage panel (D24): the last 7 and 30
// days, and the last 30 days per user.
type aiUsageView struct {
	Periods []aiPeriod
	Users   []aiUserRow
}

type aiPeriod struct {
	Label          string // "7 days"
	Calls, In, Out int
	Cost           string // two decimals, "—" without a price
}

type aiUserRow struct {
	User           string // "—" for calls without a user
	Calls, In, Out int
	Cost           string
}

// aiPrice is a price setting: per million tokens, up to four decimals.
var aiPrice = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,4})?$`)

// aiCost prices in and out tokens with the admin's prices ("—" when neither
// is set; an unset one counts as 0).
func aiCost(in, out int, priceIn, priceOut string) string {
	if priceIn == "" && priceOut == "" {
		return "—"
	}
	return strconv.FormatFloat(aiSpent(in, out, priceIn, priceOut), 'f', 2, 64)
}

// aiSpent is what in and out tokens cost at the admin's prices (an unset
// one counts as 0): the one sum the usage panel and the spend limit share.
func aiSpent(in, out int, priceIn, priceOut string) float64 {
	pi, _ := strconv.ParseFloat(priceIn, 64)
	po, _ := strconv.ParseFloat(priceOut, 64)
	return float64(in)/1e6*pi + float64(out)/1e6*po
}

// aiLimit is the AI spend limit as it stands: whether one is set, what the
// calls of the last db.AILimitDays days cost, and whether that reaches it.
type aiLimit struct {
	Set          bool
	Limit, Spent float64
	Reached      bool
}

// aiLimitAt reads the limit and the spend at now: one read of the settings
// and one sum. A stored value that is no number is no limit (the save
// refuses one).
func aiLimitAt(d *db.DB, now time.Time) (aiLimit, error) {
	set, err := d.Settings("ai.")
	if err != nil {
		return aiLimit{}, err
	}
	raw := set[db.AILimitKey]
	if !aiPrice.MatchString(raw) {
		return aiLimit{}, nil
	}
	st := aiLimit{Set: true}
	st.Limit, _ = strconv.ParseFloat(raw, 64)
	in, out, err := d.AITokens(now.AddDate(0, 0, -db.AILimitDays))
	if err != nil {
		return aiLimit{}, err
	}
	st.Spent = aiSpent(in, out, set[db.AIPriceInKey], set[db.AIPriceOutKey])
	st.Reached = st.Spent >= st.Limit
	return st, nil
}

// aiOverLimit is the runner's question before a provider call for a rule or
// a fix (Runner.OverLimit). The warn line is written when a call first
// finds the limit reached, and again only after it was not reached in
// between: one line for a check's AI rules, not one each. A sum that cannot
// be read counts as reached: AI rules fail open, so nothing is held, and
// nothing is spent blind.
func (s *Server) aiOverLimit(d *db.DB) func() bool {
	var said atomic.Bool
	return func() bool {
		st, err := aiLimitAt(d, time.Now())
		if err != nil {
			s.log().Error("ai: the spend limit cannot be read; AI rules are skipped", "err", err)
			return true
		}
		if !st.Reached {
			said.Store(false)
			return false
		}
		if !said.Swap(true) {
			s.log().Warn("ai: the spend limit is reached; AI rules are skipped", "spent", st.Spent, "limit", st.Limit, "days", db.AILimitDays)
		}
		return true
	}
}

// aiUsageFor fills the AI usage panel.
func (s *Server) aiUsageFor(d *db.DB) (aiUsageView, error) {
	var v aiUsageView
	pin, err := d.Setting(db.AIPriceInKey)
	if err != nil {
		return v, err
	}
	pout, err := d.Setting(db.AIPriceOutKey)
	if err != nil {
		return v, err
	}
	now := time.Now()
	var month []db.AITotal
	for _, days := range []int{7, 30} {
		ts, err := d.AITotals(now.AddDate(0, 0, -days))
		if err != nil {
			return v, err
		}
		all := ts[0]
		v.Periods = append(v.Periods, aiPeriod{Label: strconv.Itoa(days) + " days", Calls: all.Calls, In: all.In, Out: all.Out, Cost: aiCost(all.In, all.Out, pin, pout)})
		month = ts
	}
	for _, u := range month[1:] {
		name := u.User
		if name == "" {
			name = "—"
		}
		v.Users = append(v.Users, aiUserRow{User: name, Calls: u.Calls, In: u.In, Out: u.Out, Cost: aiCost(u.In, u.Out, pin, pout)})
	}
	return v, nil
}

// recordAI stores one provider call (Runner.OnUsage).
func (s *Server) recordAI(d *db.DB) func(rules.Usage) {
	return func(u rules.Usage) {
		err := d.AddAIUsage(db.AIUsage{User: u.User, Purpose: u.Purpose, Provider: u.Provider, Model: u.Model, Eng: u.Eng, Fid: u.Fid, Rule: u.Rule,
			In: u.In, Out: u.Out, MS: int(u.Took / time.Millisecond), OK: u.OK})
		if err != nil {
			s.log().Error("ai usage: a call is not recorded", "user", u.User, "eng", u.Eng, "finding", u.Fid, "err", err)
		}
	}
}
