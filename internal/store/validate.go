package store

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/finding"
)

// The content rules below are shared by the website (the store's writes)
// and git pushes (package policy): what the website can't save, a push
// can't carry. Each returns an ErrInvalidValue error in plain words.

// ValidTitle accepts a title as stored: one line of 1–200 characters with
// no spaces at either end and no hidden text-direction characters (the
// website strips those with CleanTitle before it saves).
func ValidTitle(title string) error {
	if err := CheckTitle(title); err != nil {
		return err
	}
	if CleanTitle(title) != title {
		return fmt.Errorf("%w: the title has spaces at either end or hidden text-direction characters", ErrInvalidValue)
	}
	return nil
}

// CheckCVSS accepts a CVSS vector as stored: none, or a complete base
// vector of the configured CVSS version in its canonical form (what the
// website writes).
func CheckCVSS(cfg config.Config, vector string) (cvss.Vector, error) {
	if vector == "" {
		return nil, nil
	}
	v, err := cvss.Parse(vector)
	if err != nil {
		return nil, fmt.Errorf("%w: CVSS vector %s: %v", ErrInvalidValue, vector, err)
	}
	if want := v.String(); vector != want || !strings.HasPrefix(want, "CVSS:"+cfg.CVSS.Version+"/") {
		return nil, fmt.Errorf("%w: CVSS vector %s is not written as this server's CVSS %s vector; write %s", ErrInvalidValue, vector, cfg.CVSS.Version, want)
	}
	return v, nil
}

// CheckSeverity accepts a severity as stored with the vector: one of the
// configured severities ("" too, without a vector), and with a valid vector
// the vector's rating (the website derives it).
func CheckSeverity(cfg config.Config, sev, vector string) error {
	if sev != "" && !slices.Contains(cfg.Severities, sev) {
		return fmt.Errorf("%w: unknown severity %s (configured: %s)", ErrInvalidValue, sev, strings.Join(cfg.Severities, ", "))
	}
	v, err := cvss.Parse(vector)
	if vector == "" || err != nil {
		return nil
	}
	score, _ := cvss.Score(v)
	if r := cvss.Rating(score); sev != r {
		shown := sev
		if shown == "" {
			shown = "(none)"
		}
		return fmt.Errorf("%w: severity %s does not match the CVSS vector (score %s is %s); set severity: %s", ErrInvalidValue, shown, cvss.FormatScore(score), r, r)
	}
	return nil
}

// CheckAssets accepts an asset list as stored: every row passes
// CleanAssets (rows left empty are harmless).
func CheckAssets(list []finding.Asset) error {
	_, err := CleanAssets(list)
	return err
}

// SectionProblems checks a finding's (or template's) section bodies, and
// that no section name is used twice: only the first one can be shown or
// edited, yet both would ship in exports.
func SectionProblems(f *finding.Finding) []string {
	var ps []string
	seen := map[string]bool{}
	for _, s := range f.Sections {
		if err := finding.ValidateBody(s.Body); err != nil {
			ps = append(ps, "section "+s.Name+": "+err.Error())
		}
		if seen[s.Name] {
			ps = append(ps, "section "+s.Name+" appears twice; merge them into one")
		}
		seen[s.Name] = true
	}
	return ps
}

// FindingProblems checks a finding file's content against the rules the
// website saves by: workflow keys, title, CVSS, severity, assets and
// sections. With old (the previous version of the file), only the parts
// that changed are checked, so an edit of one part is never refused for a
// problem another part already had.
func FindingProblems(cfg config.Config, f, old *finding.Finding) []string {
	var ps []string
	add := func(err error) {
		if err != nil {
			ps = append(ps, strings.TrimPrefix(err.Error(), ErrInvalidValue.Error()+": "))
		}
	}
	if l, ok := f.Legacy(); ok {
		ps = append(ps, "workflow state is managed in YARS, not in the file; remove "+strings.Join(l.Keys, ", ")+" from the front matter")
	}
	n := f.Meta
	var o finding.Meta
	if old != nil {
		o = old.Meta
	}
	if old == nil || n.Title != o.Title {
		add(ValidTitle(n.Title))
	}
	cvssChanged := old == nil || n.CVSS != o.CVSS
	if cvssChanged {
		_, err := CheckCVSS(cfg, n.CVSS)
		add(err)
	}
	if cvssChanged || n.Severity != o.Severity {
		add(CheckSeverity(cfg, n.Severity, n.CVSS))
	}
	if old == nil || !reflect.DeepEqual(n.Assets, o.Assets) {
		add(CheckAssets(n.Assets))
	}
	for _, p := range SectionProblems(f) {
		if old != nil && !sectionProblemNew(p, old) {
			continue
		}
		ps = append(ps, p)
	}
	return ps
}

// sectionProblemNew reports whether the old version did not have problem p.
func sectionProblemNew(p string, old *finding.Finding) bool {
	return !slices.Contains(SectionProblems(old), p)
}

// CheckEngagement accepts an engagement.yaml's values: a one-line name,
// a one-line client, dates as YYYY-MM-DD with the end not before the start,
// type pentest or retest (a retest names its source engagement). With prev
// (the engagement as it was), type and source must stay: they are fixed
// when the engagement is created.
func CheckEngagement(prev *Engagement, e Engagement) error {
	name, client := strings.TrimSpace(e.Name), strings.TrimSpace(e.Client)
	switch {
	case name == "" || strings.ContainsAny(name, "\r\n"):
		return fmt.Errorf("%w: name is required (one line)", ErrInvalidValue)
	case strings.ContainsAny(client, "\r\n"):
		return fmt.Errorf("%w: client must be one line", ErrInvalidValue)
	case !validDate(e.Start) || !validDate(e.End):
		return fmt.Errorf("%w: dates are YYYY-MM-DD", ErrInvalidValue)
	case e.Start != "" && e.End != "" && e.End < e.Start:
		return fmt.Errorf("%w: the end is before the start", ErrInvalidValue)
	}
	if prev != nil {
		if e.Type != prev.Type {
			return fmt.Errorf("%w: type is fixed when the engagement is created; keep type: %s", ErrInvalidValue, orNone(prev.Type))
		}
		if e.Source != prev.Source {
			return fmt.Errorf("%w: source is fixed when the engagement is created; keep source: %s", ErrInvalidValue, orNone(prev.Source))
		}
		return nil
	}
	switch {
	case e.Type != "pentest" && e.Type != "retest":
		return fmt.Errorf("%w: type must be pentest or retest", ErrInvalidValue)
	case e.Type == "retest" && !ValidID(e.Source):
		return fmt.Errorf("%w: a retest names its source engagement", ErrInvalidValue)
	case e.Type == "pentest" && e.Source != "":
		return fmt.Errorf("%w: only a retest has a source", ErrInvalidValue)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return `""`
	}
	return s
}

// CheckAttachment accepts a file in a finding's attachments/ folder: a
// plain name directly in the folder, at most MaxAttachment bytes, an image
// or text (as the website accepts uploads), and not executable.
func CheckAttachment(name string, data []byte, executable bool) error {
	if !attachmentRe.MatchString("attachments/" + name) {
		return fmt.Errorf("%w: attachment names are letters, digits, . _ - directly in attachments/ (no folders)", ErrInvalidValue)
	}
	if executable {
		return fmt.Errorf("%w: attachments cannot be executable (chmod -x)", ErrInvalidValue)
	}
	return checkAttachment(data)
}
