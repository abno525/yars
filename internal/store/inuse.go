package store

import (
	"fmt"
	"slices"
	"strings"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// NameUse is a section, severity or details row name a new configuration
// drops while findings still use it: those findings' "engagement/F-001".
type NameUse struct {
	List, Name string // List: "section", "severity" or "details row"
	Findings   []string
}

// maxNameUses is how many users a refusal names per dropped name.
const maxNameUses = 10

// String is the refusal for a dropped name still in use, for the website
// (Admin › Structure) and a push alike.
func (u NameUse) String() string {
	list, more := u.Findings, ""
	if len(list) > maxNameUses {
		list, more = list[:maxNameUses], fmt.Sprintf(" (+%d more)", len(u.Findings)-maxNameUses)
	}
	return fmt.Sprintf("%s %q is still used by: %s%s. Change those %s first, then remove the name.",
		u.List, u.Name, strings.Join(list, ", "), more, usersOf(u.Findings))
}

// usersOf names what a name's users are to change: findings, templates
// ("template x.md") or both.
func usersOf(list []string) string {
	tpl := slices.ContainsFunc(list, func(x string) bool { return strings.HasPrefix(x, "template ") })
	fnd := slices.ContainsFunc(list, func(x string) bool { return !strings.HasPrefix(x, "template ") })
	switch {
	case tpl && fnd:
		return "findings and templates"
	case tpl:
		return "templates"
	}
	return "findings"
}

// DroppedInUse lists the names old has and now lacks in its sections,
// severities and details rows that a finding of any engagement (archived
// and withdrawn ones too) still uses: a section with text, its severity, a
// details row with a value. A name that only moved, or no finding uses, is
// not listed. extra are further users by label (templates: "template
// x.md"), listed after the findings in label order.
func (s *Store) DroppedInUse(old, now config.Config, extra map[string]*finding.Finding) ([]NameUse, error) {
	labels := make([]string, 0, len(extra))
	for l := range extra {
		labels = append(labels, l)
	}
	slices.Sort(labels)
	type list struct {
		name     string
		was, now []string
		uses     func(f *finding.Finding, n string) bool
	}
	lists := []list{
		{"section", old.Sections, now.Sections, func(f *finding.Finding, n string) bool {
			return slices.ContainsFunc(f.Sections, func(x finding.Section) bool { return x.Name == n && strings.TrimSpace(x.Body) != "" })
		}},
		{"severity", old.Severities, now.Severities, func(f *finding.Finding, n string) bool { return f.Meta.Severity == n }},
		{"details row", old.DetailsRows, now.DetailsRows, func(f *finding.Finding, n string) bool {
			return strings.TrimSpace(f.Meta.Details[n]) != ""
		}},
	}
	var out []NameUse
	var refs []FindingRef // read once, when a name is dropped
	read := false
	for _, l := range lists {
		for _, n := range l.was {
			if slices.Contains(l.now, n) {
				continue
			}
			if !read {
				engs, err := s.ListEngagements()
				if err != nil {
					return nil, err
				}
				for _, e := range engs {
					rs, err := s.ListFindings(e.ID)
					if err != nil {
						return nil, err
					}
					refs = append(refs, rs...)
				}
				read = true
			}
			u := NameUse{List: l.name, Name: n}
			for _, r := range refs {
				if l.uses(r.F, n) {
					u.Findings = append(u.Findings, r.EngID+"/"+r.F.Meta.ID)
				}
			}
			for _, lb := range labels {
				if l.uses(extra[lb], n) {
					u.Findings = append(u.Findings, lb)
				}
			}
			if len(u.Findings) > 0 {
				out = append(out, u)
			}
		}
	}
	return out, nil
}
