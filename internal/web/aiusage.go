package web

import (
	"log"
	"regexp"
	"strconv"
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
	pi, _ := strconv.ParseFloat(priceIn, 64)
	po, _ := strconv.ParseFloat(priceOut, 64)
	return strconv.FormatFloat(float64(in)/1e6*pi+float64(out)/1e6*po, 'f', 2, 64)
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
func recordAI(d *db.DB) func(rules.Usage) {
	return func(u rules.Usage) {
		err := d.AddAIUsage(db.AIUsage{User: u.User, Purpose: u.Purpose, Provider: u.Provider, Model: u.Model, Eng: u.Eng, Fid: u.Fid, Rule: u.Rule,
			In: u.In, Out: u.Out, MS: int(u.Took / time.Millisecond), OK: u.OK})
		if err != nil {
			log.Printf("ai usage: %v", err)
		}
	}
}
