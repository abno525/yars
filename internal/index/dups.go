package index

import (
	"sort"
	"strings"
	"unicode"

	"yars/internal/finding"
	"yars/internal/workflow"
)

// Grams is a set of trigrams.
type Grams map[string]struct{}

// Trigrams splits s into lower-case words (letters and digits) and returns
// the trigrams of each word padded with two spaces in front and one behind,
// as PostgreSQL's pg_trgm does.
func Trigrams(s string) Grams {
	g := Grams{}
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for _, w := range words {
		r := []rune("  " + w + " ")
		for i := 0; i+3 <= len(r); i++ {
			g[string(r[i:i+3])] = struct{}{}
		}
	}
	return g
}

// assetGrams are the trigrams of a finding's hosts and URLs.
func assetGrams(as []finding.Asset) Grams {
	var b strings.Builder
	for _, a := range as {
		b.WriteString(a.Host + " " + a.URL + " ")
	}
	return Trigrams(b.String())
}

// Similarity is the Jaccard index of two trigram sets (0 when both are
// empty).
func Similarity(a, b Grams) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	n := 0
	for g := range a {
		if _, ok := b[g]; ok {
			n++
		}
	}
	return float64(n) / float64(len(a)+len(b)-n)
}

// DupThreshold is the similarity from which a finding counts as a
// possible duplicate; DupMax is how many are shown.
const (
	DupThreshold = 0.6
	DupMax       = 5
)

// Match is a possible duplicate: a row and how similar it is (Pct 0–100).
type Match struct {
	Row
	Score float64
	Pct   int
}

// score compares a title (and assets) with a row: the title similarity,
// or, when both have assets, the better of that and the mean of the title
// and asset similarities.
func score(tg, ag Grams, r Row) float64 {
	t := Similarity(tg, r.tgrams)
	if len(ag) > 0 && len(r.agrams) > 0 {
		if m := (t + Similarity(ag, r.agrams)) / 2; m > t {
			return m
		}
	}
	return t
}

// Similar lists the findings of engagement eng (not withdrawn, not the
// finding exclude) whose title and assets resemble title and assets: at
// least DupThreshold similar, the DupMax best, best first.
func (ix *Index) Similar(eng, title string, assets []finding.Asset, exclude string) ([]Match, error) {
	if err := ix.refresh(); err != nil {
		return nil, err
	}
	tg, ag := Trigrams(title), assetGrams(assets)
	if len(tg) == 0 && len(ag) == 0 {
		return nil, nil
	}
	ix.mu.RLock()
	e := ix.engs[eng]
	ix.mu.RUnlock()
	if e == nil {
		return nil, nil
	}
	var out []Match
	for _, r := range e.rows {
		if r.ID == exclude || !workflow.Active(r.Status) {
			continue
		}
		if sc := score(tg, ag, r); sc >= DupThreshold {
			out = append(out, Match{Row: r, Score: sc, Pct: int(sc*100 + 0.5)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Dir < out[j].Dir
	})
	if len(out) > DupMax {
		out = out[:DupMax]
	}
	return out, nil
}
