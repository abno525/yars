package web

import (
	"slices"
	"strconv"
	"time"

	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

// barSeg is one part of a stacked bar: X and W are percentages of the bar.
type barSeg struct {
	Key  string
	N    int
	X, W string
}

// barView is a stacked bar (only the parts with findings) and its legend
// (every key, zeros included, so the legend never shifts).
type barView struct {
	Segs, Legend []barSeg
}

func barOf(counts []index.Count) barView {
	var v barView
	total := 0
	for _, c := range counts {
		total += c.N
	}
	cum := 0
	for _, c := range counts {
		s := barSeg{Key: c.Key, N: c.N}
		v.Legend = append(v.Legend, s)
		if c.N == 0 || total == 0 {
			continue
		}
		s.X = pctStr(cum, total)
		s.W = pctStr(c.N, total)
		cum += c.N
		v.Segs = append(v.Segs, s)
	}
	return v
}

func pctStr(n, of int) string { return strconv.FormatFloat(float64(n)*100/float64(of), 'f', 3, 64) }

// boardBars are the board's progress (by status) and severity bars.
type boardBars struct {
	Progress, Severity barView
	Reported, Total    int
}

func barsOf(s index.Summary) boardBars {
	var st []index.Count
	for _, c := range s.Statuses {
		if workflow.Active(c.Key) {
			st = append(st, c)
		}
	}
	return boardBars{Progress: barOf(st), Severity: barOf(s.Severities), Reported: s.ByStatus["reported"], Total: s.Total}
}

// overviewBars are barsOf with unscored drafts as the severity bar's last
// segment, "none" (R10: the Overview shows them; the findings list's bars
// stay as they are).
func overviewBars(s index.Summary) boardBars {
	b := barsOf(s)
	b.Severity = barOf(append(slices.Clone(s.Severities), index.Count{Key: "none", N: s.Unscored}))
	return b
}

// engRow is one engagement on the home table.
type engRow struct {
	store.Engagement
	Bars boardBars
}

func (s *Server) engRows(engs []store.Engagement) ([]engRow, error) {
	out := make([]engRow, 0, len(engs))
	for _, e := range engs {
		sum, err := s.Index.Summary(e.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, engRow{Engagement: e, Bars: barsOf(sum)})
	}
	return out, nil
}

// scoreText shows a CVSS score; a finding without a valid vector has none
// ("—", not 0.0: a real score of 0.0 shows as such).
func scoreText(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// cleared says whether reviewer name's clearance on the row is current.
func cleared(r index.Row, name string) bool {
	return r.Meta != nil && slices.Contains(r.Meta.ClearedBy, name)
}

// age is a short time since t: "12 m", "3 h", "2 d" ("—" when unknown).
func age(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Hour:
		return strconv.Itoa(max(int(d/time.Minute), 1)) + " m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " h"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + " d"
	}
}
