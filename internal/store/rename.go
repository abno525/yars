package store

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strings"

	"yars/internal/cvss"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
)

// RenameNames renames sections, details rows and severities (list:
// "section", "details row", "severity"; old → new) inside every finding of
// every engagement (archived ones too) and inside every template. A finding
// is one commit "F-001: rename section Impact to Business impact", made
// without a finding.updated event. Approvals, sign-offs and the latest check
// run move to the renamed content; chat comments on a renamed section follow
// it. It returns the findings it changed ("eng/F-001") and, on a failure,
// the error with what was done so far.
func (s *Store) RenameNames(list string, renames map[string]string, a gitrepo.Author) (changed []string, err error) {
	if len(renames) == 0 {
		return nil, nil
	}
	olds := make([]string, 0, len(renames))
	for o, n := range renames {
		if o != n {
			olds = append(olds, o)
		}
	}
	sort.Strings(olds)
	if len(olds) == 0 {
		return nil, nil
	}
	var pairs []string
	for _, o := range olds {
		pairs = append(pairs, o+" to "+renames[o])
	}
	msg := "rename " + list + " " + strings.Join(pairs, ", ")
	apply, err := renamer(list, olds, renames, s.Config().DetailsRows)
	if err != nil {
		return nil, err
	}
	ids, err := s.EngagementIDs()
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, err := s.Engagement(id); err != nil {
			continue // not an engagement repository (as RenameReportSections)
		}
		refs, err := s.ListFindings(id)
		if err != nil {
			return changed, fmt.Errorf("engagements/%s: %w", id, err)
		}
		for _, r := range refs {
			fid := r.F.Meta.ID
			then := func(ref FindingRef, oldHash, newHash string) error {
				if s.db == nil {
					return nil
				}
				return s.db.TxFor(id, func(tx *db.Tx) error {
					if err := tx.MoveHash(id, fid, oldHash, newHash); err != nil {
						return err
					}
					if list != "section" {
						return nil
					}
					for _, o := range olds {
						if err := tx.RenameChatSection(id, fid, o, renames[o]); err != nil {
							return err
						}
					}
					return nil
				})
			}
			ev, err := s.mutateLockedIn(id, r.Dir, a, func(f *finding.Finding) (string, error) {
				return msg, apply(f)
			}, then, true)
			if ev.Kind != "" {
				changed = append(changed, id+"/"+fid)
			}
			if err != nil {
				return changed, fmt.Errorf("engagements/%s %s: %w", id, fid, err)
			}
		}
	}
	if err := s.renameInTemplates(msg, apply, a); err != nil {
		return changed, fmt.Errorf("templates: %w", err)
	}
	return changed, nil
}

// renamer is the edit RenameNames makes to one finding or template.
func renamer(list string, olds []string, renames map[string]string, detailsOrder []string) (func(*finding.Finding) error, error) {
	switch list {
	case "section":
		return func(f *finding.Finding) error {
			for _, o := range olds {
				n := renames[o]
				i := slices.IndexFunc(f.Sections, func(x finding.Section) bool { return x.Name == o })
				if i < 0 {
					continue
				}
				if j := slices.IndexFunc(f.Sections, func(x finding.Section) bool { return x.Name == n }); j >= 0 {
					if strings.TrimSpace(f.Sections[j].Body) != "" {
						return fmt.Errorf("%w: %s has text under both %s and %s", ErrInvalidValue, f.Meta.ID, o, n)
					}
					f.Sections = slices.Delete(f.Sections, j, j+1)
					if j < i {
						i--
					}
				}
				f.Sections[i].Name = n
			}
			return nil
		}, nil
	case "details row":
		return func(f *finding.Finding) error {
			merged := map[string]string{}
			moved := false
			for k, v := range f.Meta.Details {
				merged[k] = v
			}
			for _, o := range olds {
				v, ok := merged[o]
				if !ok {
					continue
				}
				n := renames[o]
				if strings.TrimSpace(merged[n]) != "" && strings.TrimSpace(v) != "" {
					return fmt.Errorf("%w: %s has values under both %s and %s", ErrInvalidValue, f.Meta.ID, o, n)
				}
				delete(merged, o)
				if strings.TrimSpace(merged[n]) == "" {
					merged[n] = v
				}
				moved = true
			}
			if !moved {
				return nil
			}
			return f.SetMeta("details", finding.OrderedMap(detailsOrder, merged))
		}, nil
	case "severity":
		return func(f *finding.Finding) error {
			n, ok := renames[f.Meta.Severity]
			if !ok {
				return nil
			}
			// a CVSS rating is derived from the vector: those names are locked
			if _, err := cvss.Parse(f.Meta.CVSS); err == nil {
				return nil
			}
			return f.SetMeta("severity", n)
		}, nil
	}
	return nil, fmt.Errorf("%w: no list %q to rename in", ErrInvalidValue, list)
}

// renameInTemplates applies a rename to every template, in one commit of
// the main repo ("templates: rename …").
func (s *Store) renameInTemplates(msg string, apply func(*finding.Finding) error, a gitrepo.Author) error {
	tpls, err := s.Templates()
	if err != nil {
		return err
	}
	if len(tpls) == 0 {
		return nil
	}
	return s.EditSettings("templates: "+msg, a, func(read func(string) ([]byte, error)) ([]SettingsFile, error) {
		var out []SettingsFile
		for _, t := range tpls {
			p := templatePath(t.Slug)
			b, err := read(p)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			f, err := finding.Parse(b)
			if err != nil {
				continue // an unreadable template is left as it is
			}
			if err := apply(f); err != nil {
				return nil, fmt.Errorf("template %s: %w", t.Slug, err)
			}
			if after := f.Bytes(); string(after) != string(b) {
				out = append(out, SettingsFile{Path: p, Data: after})
			}
		}
		return out, nil
	}, nil)
}
