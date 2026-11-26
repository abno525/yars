package store

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/workflow"
)

// ReportFile is the file name (without .md) of a report-level section:
// its slug, unless the slug would lose too much to tell names apart (no
// Latin letter or digit, or longer than 40 characters), which adds a hash
// of the name. Names that differ only in punctuation ("Scope", "Scope.")
// still share one; Admin › Structure refuses such pairs.
func ReportFile(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	full := strings.Trim(b.String(), "-")
	switch h := BodyHash(name)[:8]; {
	case full == "":
		return "section-" + h
	case len(full) > 40:
		return strings.Trim(full[:31], "-") + "-" + h
	}
	return full
}

// reportPath is where a report-level section lives in the engagement
// repo: report/<ReportFile>.md, the Markdown body only.
func reportPath(eng, name string) string {
	return path.Join(engDir(eng), "report", ReportFile(name)+".md")
}

// ReportSection reads a report-level section of an engagement ("" when it
// was never written).
func (s *Store) ReportSection(eng, name string) (string, error) {
	if _, err := s.Engagement(eng); err != nil {
		return "", err
	}
	b, err := s.readFile(reportPath(eng, name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return string(b), err
}

// UpdateReportSection replaces a report-level section and commits it in
// the engagement's repo. A non-empty base must be BodyHash of the stored
// body, else ErrConflict.
func (s *Store) UpdateReportSection(eng, name, body, base string, a gitrepo.Author) error {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, "\r\n") {
		return fmt.Errorf("%w: invalid section name %q", ErrInvalidBody, name)
	}
	if err := finding.ValidateBody(body); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBody, err)
	}
	if _, err := s.Engagement(eng); err != nil {
		return err
	}
	l := s.engLock(eng)
	l.Lock()
	defer l.Unlock()
	if err := s.writable(eng); err != nil { // under the lock, as Archive
		return err
	}
	rel := reportPath(eng, name)
	prev, err := s.readFile(rel)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if base != "" && BodyHash(string(prev)) != base {
		return ErrConflict
	}
	next := strings.Trim(strings.ReplaceAll(body, "\r\n", "\n"), "\n") + "\n"
	if string(prev) == next {
		return nil
	}
	if err := s.root.MkdirAll(path.Dir(rel), 0o700); err != nil {
		return err
	}
	if err := s.writeFile(rel, []byte(next)); err != nil {
		return err
	}
	return s.commit(map[string][]byte{rel: prev}, "report: edit "+name, a, "")
}

// RenameReportSections moves report-level text to the new names of renamed
// sections (old → new) in every engagement, archived ones included, so the
// Report tab and exports keep showing it. Text already under a new name is
// never overwritten. One commit per section moved.
func (s *Store) RenameReportSections(renames map[string]string, a gitrepo.Author) error {
	olds := make([]string, 0, len(renames))
	for o := range renames {
		olds = append(olds, o)
	}
	sort.Strings(olds)
	ids, err := s.EngagementIDs()
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		if _, err := s.Engagement(id); err != nil {
			continue
		}
		l := s.engLock(id)
		l.Lock()
		for _, o := range olds {
			n := renames[o]
			from, to := reportPath(id, o), reportPath(id, n)
			if from == to {
				continue
			}
			b, err := s.readFile(from)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err == nil {
				if _, serr := s.root.Lstat(to); serr == nil {
					continue // the new name has text of its own
				}
				if err = s.writeFile(to, b); err == nil {
					if err = s.root.Remove(from); err == nil {
						err = s.commit(map[string][]byte{from: b, to: nil}, "report: rename "+o+" to "+n, a, "")
					} else {
						s.root.Remove(to)
					}
				}
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("engagement %s: %w", id, err))
			}
		}
		l.Unlock()
	}
	return errors.Join(errs...)
}

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func validDate(d string) bool {
	if d == "" {
		return true
	}
	_, err := time.Parse("2006-01-02", d)
	return dateRe.MatchString(d) && err == nil
}

// UpdateEngagement saves an engagement's name, client and dates (directors)
// in its engagement.yaml, with one commit. Id, type and source stay.
func (s *Store) UpdateEngagement(e Engagement, u config.User) error {
	if !workflow.AtLeast(u, "director") {
		return &workflow.Denied{Reason: "only a director can change the engagement"}
	}
	e.Name, e.Client = strings.TrimSpace(e.Name), strings.TrimSpace(e.Client)
	cur, err := s.Engagement(e.ID)
	if err != nil {
		return err
	}
	e.Type, e.Source = cur.Type, cur.Source // fixed at creation
	if err := CheckEngagement(&cur, e); err != nil {
		return err
	}
	l := s.engLock(e.ID)
	l.Lock()
	defer l.Unlock()
	if err := s.writable(e.ID); err != nil { // under the lock, as Archive
		return err
	}
	cur.Name, cur.Client, cur.Start, cur.End = e.Name, e.Client, e.Start, e.End
	rel := path.Join(engDir(e.ID), "engagement.yaml")
	prev, err := s.readFile(rel)
	if err != nil {
		return err
	}
	b, err := yaml.Marshal(cur)
	if err != nil {
		return err
	}
	if string(b) == string(prev) {
		return nil
	}
	if err := s.writeFile(rel, b); err != nil {
		return err
	}
	return s.commit(map[string][]byte{rel: prev}, "engagement "+e.ID+": settings", u.GitAuthor(), "")
}
