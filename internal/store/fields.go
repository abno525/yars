package store

import (
	"fmt"
	"sort"
	"strings"

	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/finding"
)

func sortedPairs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\x00" + m[k] + "\x00")
	}
	return b.String()
}

// CVSSHash identifies the CVSS state (vector + reasons) for optimistic concurrency.
func CVSSHash(m finding.Meta) string {
	return BodyHash(m.CVSS + "\x00" + sortedPairs(m.CVSSReasons))
}

// DetailsHash identifies the details table state for optimistic concurrency.
func DetailsHash(m finding.Meta) string { return BodyHash(sortedPairs(m.Details)) }

// UpdateCVSS sets the CVSS vector (canonicalised) and derived severity, and
// merges reasons (empty value deletes, absent keys are kept while their
// metric keeps its value: reasonsAfter). An empty vector clears CVSS with
// its reasons and keeps the last severity as a manual value.
func (s *Store) UpdateCVSS(engID, dir, vector string, reasons map[string]string, base string, a Actor) error {
	_, err := s.UpdateCVSSRows(engID, dir, CVSSChange{Vector: &vector, Reasons: reasons, Table: base}, a)
	return err
}

// CVSSRow is the key of the vector among CVSSChange.Bases (the reasons are
// keyed by metric).
const CVSSRow = "cvss"

// CVSSChange is an edit of the CVSS rows: the vector (nil keeps it, read
// inside the change) and reasons by metric (empty deletes). Each row with a
// base in Bases (RowHash of the value read) is refused only if that row
// changed since; Table, the whole state's base (CVSSHash), passes them all
// while nothing changed.
type CVSSChange struct {
	Vector  *string
	Reasons map[string]string
	Bases   map[string]string
	Table   string
}

// CVSSRowHashes are the bases of the vector (CVSSRow) and of each reason.
// A reason's base covers its metric's value too: the reason explains that
// value, so an edit of it is refused once the metric changed.
func CVSSRowHashes(m finding.Meta) map[string]string {
	out := map[string]string{CVSSRow: RowHash(m.CVSS)}
	for _, mt := range cvss.Metrics {
		out[mt.Key] = RowHash(reasonRow(m, mt.Key))
	}
	return out
}

// reasonRow is what a reason's base is of: its metric's value and the
// reason.
func reasonRow(m finding.Meta, key string) string {
	val := ""
	if v, err := cvss.ParsePartial(m.CVSS); err == nil {
		val = v[key]
	}
	return val + "\x00" + m.CVSSReasons[key]
}

// ReasonHash is the base of a reason with its metric at value (as
// CVSSRowHashes gives it).
func ReasonHash(value, reason string) string {
	return RowHash(value + "\x00" + strings.TrimSpace(reason))
}

// UpdateCVSSRows applies ch (see UpdateCVSS) and returns the new bases of
// every CVSS row.
func (s *Store) UpdateCVSSRows(engID, dir string, ch CVSSChange, a Actor) (map[string]string, error) {
	var v cvss.Vector
	if ch.Vector != nil && strings.TrimSpace(*ch.Vector) != "" {
		var err error
		if v, err = cvss.Parse(*ch.Vector); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidValue, err)
		}
		// stored canonical, in the configured version (as a push must be)
		if _, err := CheckCVSS(s.Config(), v.String()); err != nil {
			return nil, err
		}
	}
	reasons := ch.Reasons
	var out map[string]string
	err := s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		m := f.Meta
		if ch.Table == "" || CVSSHash(m) != ch.Table {
			// exactly the rows written, each against its own base; once
			// any base is given, a written row without one is refused
			checked := ch.Table != "" || len(ch.Bases) > 0
			stale := func(k, cur string) bool {
				b, ok := ch.Bases[k]
				if !ok {
					return checked
				}
				return b != "" && RowHash(cur) != b
			}
			if ch.Vector != nil && stale(CVSSRow, m.CVSS) {
				return "", ErrConflict
			}
			for k := range reasons {
				if stale(k, reasonRow(m, k)) {
					return "", ErrConflict
				}
			}
		}
		if ch.Vector == nil {
			// the vector as it is now (a reason edit never writes back an
			// older one)
			var err error
			if v, err = cvss.Parse(m.CVSS); err != nil {
				return "", fmt.Errorf("%w: set a CVSS vector first", ErrInvalidValue)
			}
		}
		msg, err := writeCVSS(f, m, v, reasons)
		if err == nil {
			nm := m
			nm.CVSS, nm.CVSSReasons = "", reasonsAfter(m, v, reasons)
			if v != nil {
				nm.CVSS = v.String()
			}
			out = CVSSRowHashes(nm)
		}
		return msg, err
	})
	return out, err
}

// reasonsAfter is the reasons of m once vector v (nil clears it) and
// reasons are written. A reason explains one value of its metric: when v
// changes that value and reasons brings no text for the metric, the stored
// reason goes, and a cleared vector keeps none.
func reasonsAfter(m finding.Meta, v cvss.Vector, reasons map[string]string) map[string]string {
	if v == nil {
		return map[string]string{}
	}
	merged := mergeReasons(m.CVSSReasons, reasons)
	was, err := cvss.ParsePartial(m.CVSS)
	if err != nil {
		was = cvss.Vector{}
	}
	for k := range m.CVSSReasons {
		if was[k] != v[k] && strings.TrimSpace(reasons[k]) == "" {
			delete(merged, k)
		}
	}
	return merged
}

// mergeReasons is old with reasons applied (an empty one deletes).
func mergeReasons(old, reasons map[string]string) map[string]string {
	merged := map[string]string{}
	for k, r := range old {
		merged[k] = r
	}
	for k, r := range reasons {
		if r = strings.TrimSpace(r); r == "" {
			delete(merged, k)
		} else {
			merged[k] = r
		}
	}
	return merged
}

// writeCVSS sets vector v (nil clears it) and the reasons that go with it
// (reasonsAfter) in f, whose meta was m.
func writeCVSS(f *finding.Finding, m finding.Meta, v cvss.Vector, reasons map[string]string) (string, error) {
	{
		if v == nil {
			// the reasons explain values that are gone
			if len(m.CVSSReasons) > 0 {
				if err := f.SetMeta("cvss_reasons", nil); err != nil {
					return "", err
				}
			}
			if m.CVSS == "" {
				return "clear CVSS", nil
			}
			if err := f.SetMeta("severity", cvss.Derive(m.CVSS, m.Severity)); err != nil {
				return "", err
			}
			return "clear CVSS", f.SetMeta("cvss", nil)
		}
		score, _ := cvss.Score(v)
		merged := reasonsAfter(m, v, reasons)
		if err := f.SetMeta("severity", cvss.Rating(score)); err != nil {
			return "", err
		}
		if err := f.SetMeta("cvss", v.String()); err != nil {
			return "", err
		}
		var rv any
		if len(merged) > 0 {
			keys := make([]string, 0, len(cvss.Metrics))
			for _, mt := range cvss.Metrics {
				keys = append(keys, mt.Key)
			}
			rv = finding.OrderedMap(keys, merged)
		}
		if err := f.SetMeta("cvss_reasons", rv); err != nil {
			return "", err
		}
		if m.CVSS == v.String() {
			// the vector stays: name the reasons that changed
			var changed []string
			for _, mt := range cvss.Metrics {
				if merged[mt.Key] != m.CVSSReasons[mt.Key] {
					changed = append(changed, mt.Key)
				}
			}
			switch len(changed) {
			case 0:
			case 1:
				return "edit CVSS reason " + changed[0], nil
			default:
				return "edit CVSS reasons " + strings.Join(changed, ", "), nil
			}
		}
		return "set CVSS " + cvss.FormatScore(score), nil
	}
}

// SeverityHash identifies the stored severity for optimistic concurrency.
func SeverityHash(m finding.Meta) string { return BodyHash(m.Severity) }

// UpdateSeverity sets a manual severity; refused when a valid vector exists.
// A non-empty base must match SeverityHash of the current meta.
func (s *Store) UpdateSeverity(engID, dir, sev, base string, a Actor) error {
	if sev == "" {
		return fmt.Errorf("%w: choose a severity", ErrInvalidValue)
	}
	if err := CheckSeverity(s.Config(), sev, ""); err != nil {
		return err
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		if base != "" && SeverityHash(f.Meta) != base {
			return "", ErrConflict
		}
		if _, err := cvss.Parse(f.Meta.CVSS); err == nil {
			return "", fmt.Errorf("%w: severity is derived from the CVSS vector", ErrInvalidValue)
		}
		return "set severity " + sev, f.SetMeta("severity", sev)
	})
}

// RowHash identifies one value (a details row, the CVSS vector, one CVSS
// reason) for optimistic concurrency per row.
func RowHash(value string) string { return BodyHash("\x00row\x00" + value) }

// DetailsRowHashes are the bases of each details row (RowHash).
func DetailsRowHashes(m finding.Meta) map[string]string {
	out := map[string]string{}
	for k, v := range m.Details {
		out[k] = RowHash(v)
	}
	return out
}

// UpdateDetails replaces the given details rows (other existing rows kept).
// A non-empty base is the whole table's (DetailsHash), or for a single row
// that row's own (RowHash).
func (s *Store) UpdateDetails(engID, dir string, values map[string]string, base string, a Actor) error {
	_, err := s.UpdateDetailsBase(engID, dir, values, base, a)
	return err
}

// UpdateDetailsBase is UpdateDetails returning the new base (RowHash) of
// each written row.
func (s *Store) UpdateDetailsBase(engID, dir string, values map[string]string, base string, a Actor) (map[string]string, error) {
	if base == "" {
		return s.UpdateDetailsRows(engID, dir, values, nil, a)
	}
	var out map[string]string
	err := s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		ok := DetailsHash(f.Meta) == base
		if len(values) == 1 {
			for k := range values {
				ok = ok || RowHash(f.Meta.Details[k]) == base
			}
		}
		if !ok {
			return "", ErrConflict
		}
		msg, err := s.writeDetails(f, values)
		out = map[string]string{}
		for k := range values {
			out[k] = RowHash(f.Meta.Details[k])
		}
		return msg, err
	})
	return out, err
}

// UpdateDetailsRows replaces the given details rows, each checked on its
// own: a row with a base (RowHash of the value it was read with) is refused
// with ErrConflict only when that row changed since; with no bases at all
// nothing is checked, but once bases are given a written row without one
// is refused. Other rows are kept. It returns each written row's new base.
func (s *Store) UpdateDetailsRows(engID, dir string, values, bases map[string]string, a Actor) (map[string]string, error) {
	var out map[string]string
	err := s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		for k := range values {
			b, ok := bases[k]
			// once any base is given, a written row without one is refused
			if (!ok && len(bases) > 0) || (b != "" && RowHash(f.Meta.Details[k]) != b) {
				return "", ErrConflict
			}
		}
		msg, err := s.writeDetails(f, values)
		out = map[string]string{}
		for k := range values {
			out[k] = RowHash(f.Meta.Details[k])
		}
		return msg, err
	})
	return out, err
}

// CleanRow is a details value as stored: no trailing blanks on a line, no
// blank lines around it.
func CleanRow(v string) string {
	lines := strings.Split(strings.ReplaceAll(v, "\r\n", "\n"), "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

func (s *Store) writeDetails(f *finding.Finding, values map[string]string) (string, error) {
	merged := map[string]string{}
	for k, v := range f.Meta.Details {
		merged[k] = v
	}
	for k, v := range values {
		merged[k] = CleanRow(v)
	}
	if err := f.SetMeta("details", finding.OrderedMap(s.Config().DetailsRows, merged)); err != nil {
		return "", err
	}
	f.Meta.Details = merged
	return "edit details", nil
}
