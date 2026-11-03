// Package store maps the data repo layout to engagements and findings.
// Every write is a single git commit. All file access goes through an
// os.Root so symlinks cannot reach outside the repository.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/finding"
	"yars/internal/gitrepo"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("section was changed by someone else")
	ErrInvalidBody = errors.New("invalid section body")
	// ErrInvalidValue marks a rejected front-matter value (CVSS vector, severity).
	ErrInvalidValue = errors.New("invalid value")
)

type Engagement struct {
	ID     string `yaml:"-"`
	Name   string `yaml:"name"`
	Client string `yaml:"client"`
	Type   string `yaml:"type"`
	Source string `yaml:"source,omitempty"`
	Start  string `yaml:"start,omitempty"`
	End    string `yaml:"end,omitempty"`
}

type FindingRef struct {
	EngID, Dir string
	F          *finding.Finding
}

type Store struct {
	repo    *gitrepo.Repo
	cfg     config.Config
	root    *os.Root
	rootErr error
	mu      sync.Mutex
}

func New(r *gitrepo.Repo, cfg config.Config) *Store {
	root, err := os.OpenRoot(r.Dir)
	return &Store{repo: r, cfg: cfg, root: root, rootErr: err}
}

func (s *Store) Config() config.Config { return s.cfg }
func (s *Store) Repo() *gitrepo.Repo   { return s.repo }

var idRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ValidID accepts path-safe names; leading dots (".", "..", ".git") are rejected.
func ValidID(id string) bool { return idRe.MatchString(id) && !strings.HasPrefix(id, ".") }

// BodyHash identifies a section body version for optimistic concurrency.
func BodyHash(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:8])
}

func engDir(id string) string { return path.Join("engagements", id) }
func findingPath(eng, dir string) string {
	return path.Join("engagements", eng, "findings", dir, "finding.md")
}

func (s *Store) readDir(p string) ([]fs.DirEntry, error) {
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	return fs.ReadDir(s.root.FS(), p)
}

func (s *Store) readFile(p string) ([]byte, error) {
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	return s.root.ReadFile(p)
}

func (s *Store) writeFile(p string, b []byte) error {
	if s.rootErr != nil {
		return s.rootErr
	}
	return s.root.WriteFile(p, b, 0o644)
}

func (s *Store) ListEngagements() ([]Engagement, error) {
	ents, err := s.readDir("engagements")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Engagement
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		eng, err := s.Engagement(e.Name())
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				log.Printf("skip engagement %s: %v", e.Name(), err)
			}
			continue
		}
		out = append(out, eng)
	}
	return out, nil
}

func (s *Store) Engagement(id string) (Engagement, error) {
	if !ValidID(id) {
		return Engagement{}, ErrNotFound
	}
	b, err := s.readFile(path.Join(engDir(id), "engagement.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, err
	}
	var e Engagement
	if err := yaml.Unmarshal(b, &e); err != nil {
		return Engagement{}, fmt.Errorf("engagement %s: %w", id, err)
	}
	e.ID = id
	return e, nil
}

// commit commits paths; on failure it restores each path's previous content
// (nil = file did not exist) so the tree is left clean.
func (s *Store) commit(prev map[string][]byte, msg string, a gitrepo.Author, cleanupDir string) error {
	var paths []string
	for p := range prev {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	err := s.repo.Commit(paths, msg, a)
	if err == nil {
		return nil
	}
	s.repo.Unstage(paths)
	for _, p := range paths {
		if prev[p] == nil {
			s.root.Remove(p)
		} else {
			s.writeFile(p, prev[p])
		}
	}
	if cleanupDir != "" {
		s.root.RemoveAll(cleanupDir)
	}
	return err
}

func (s *Store) CreateEngagement(e Engagement, a gitrepo.Author) error {
	if !ValidID(e.ID) {
		return fmt.Errorf("invalid engagement id %q", e.ID)
	}
	if s.rootErr != nil {
		return s.rootErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := engDir(e.ID)
	if _, err := s.root.Lstat(dir); err == nil {
		return fmt.Errorf("engagement %s already exists", e.ID)
	}
	if e.Type == "" {
		e.Type = "pentest"
	}
	b, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	if err := s.root.MkdirAll(path.Join(dir, "findings"), 0o755); err != nil {
		return err
	}
	rel := path.Join(dir, "engagement.yaml")
	if err := s.writeFile(rel, b); err != nil {
		s.root.RemoveAll(dir)
		return err
	}
	return s.commit(map[string][]byte{rel: nil}, "engagement "+e.ID+": create", a, dir)
}

// ListFindings returns parseable findings of an engagement, sorted by dir.
// Unparseable finding files are logged and skipped so one bad local edit
// cannot hide the whole table.
func (s *Store) ListFindings(engID string) ([]FindingRef, error) {
	if _, err := s.Engagement(engID); err != nil {
		return nil, err
	}
	ents, err := s.readDir(path.Join(engDir(engID), "findings"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []FindingRef
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		ref, err := s.Finding(engID, e.Name())
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				log.Printf("skip %s/%s: %v", engID, e.Name(), err)
			}
			continue
		}
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
}

func (s *Store) Finding(engID, dir string) (FindingRef, error) {
	if !ValidID(engID) || !ValidID(dir) {
		return FindingRef{}, ErrNotFound
	}
	b, err := s.readFile(findingPath(engID, dir))
	if errors.Is(err, fs.ErrNotExist) {
		return FindingRef{}, ErrNotFound
	}
	if err != nil {
		return FindingRef{}, err
	}
	f, err := finding.Parse(b)
	if err != nil {
		return FindingRef{}, fmt.Errorf("%s/%s: %w", engID, dir, err)
	}
	return FindingRef{EngID: engID, Dir: dir, F: f}, nil
}

var numRe = regexp.MustCompile(`^F-(\d+)`)

func Slug(title string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(title) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	if out == "" {
		out = "finding"
	}
	return out
}

func (s *Store) CreateFinding(engID, title string, a gitrepo.Author) (FindingRef, error) {
	if _, err := s.Engagement(engID); err != nil {
		return FindingRef{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fdir := path.Join(engDir(engID), "findings")
	ents, _ := s.readDir(fdir)
	max := 0
	for _, e := range ents {
		if m := numRe.FindStringSubmatch(e.Name()); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > max {
				max = n
			}
		}
	}
	id := fmt.Sprintf("F-%03d", max+1)
	dir := id + "-" + Slug(title)
	f := finding.New(id, strings.TrimSpace(title), a.Name, s.cfg.Sections)
	if err := s.root.MkdirAll(path.Join(fdir, dir), 0o755); err != nil {
		return FindingRef{}, err
	}
	rel := findingPath(engID, dir)
	if err := s.writeFile(rel, f.Bytes()); err != nil {
		return FindingRef{}, err
	}
	if err := s.commit(map[string][]byte{rel: nil}, id+": create", a, path.Join(fdir, dir)); err != nil {
		return FindingRef{}, err
	}
	return FindingRef{EngID: engID, Dir: dir, F: f}, nil
}

// UpdateSection replaces one section's body and commits. If base is non-empty
// it must equal BodyHash of the section's current body, else ErrConflict.
func (s *Store) UpdateSection(engID, dir, section, body, base string, a gitrepo.Author) error {
	if err := finding.ValidateBody(body); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBody, err)
	}
	return s.mutate(engID, dir, a, func(f *finding.Finding) (string, error) {
		if base != "" {
			cur, _ := f.Section(section)
			if BodyHash(cur) != base {
				return "", ErrConflict
			}
		}
		f.SetSection(section, body)
		return "edit " + section, nil
	})
}

// mutate loads a finding, applies fn, and commits the result as one commit
// "<ID>: <msg>". No commit is made when the file is unchanged.
func (s *Store) mutate(engID, dir string, a gitrepo.Author, fn func(f *finding.Finding) (string, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	before := ref.F.Bytes()
	msg, err := fn(ref.F)
	if err != nil {
		return err
	}
	after := ref.F.Bytes()
	if string(before) == string(after) {
		return nil
	}
	rel := findingPath(engID, dir)
	orig, err := s.readFile(rel)
	if err != nil {
		return err
	}
	if err := s.writeFile(rel, after); err != nil {
		return err
	}
	return s.commit(map[string][]byte{rel: orig}, ref.F.Meta.ID+": "+msg, a, "")
}

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
// merges reasons (empty value deletes, absent keys are kept). An empty
// vector clears CVSS and keeps the last severity as a manual value.
func (s *Store) UpdateCVSS(engID, dir, vector string, reasons map[string]string, base string, a gitrepo.Author) error {
	var v cvss.Vector
	if strings.TrimSpace(vector) != "" {
		var err error
		if v, err = cvss.Parse(vector); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidValue, err)
		}
	}
	return s.mutate(engID, dir, a, func(f *finding.Finding) (string, error) {
		m := f.Meta
		if base != "" && CVSSHash(m) != base {
			return "", ErrConflict
		}
		if v == nil {
			if m.CVSS == "" {
				return "clear CVSS", nil
			}
			if err := f.SetMeta("severity", cvss.Derive(m.CVSS, m.Severity)); err != nil {
				return "", err
			}
			return "clear CVSS", f.SetMeta("cvss", nil)
		}
		score, _ := cvss.Score(v)
		merged := map[string]string{}
		for k, r := range m.CVSSReasons {
			merged[k] = r
		}
		for k, r := range reasons {
			if r = strings.TrimSpace(r); r == "" {
				delete(merged, k)
			} else {
				merged[k] = r
			}
		}
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
		return "set CVSS " + cvss.FormatScore(score), nil
	})
}

// SeverityHash identifies the stored severity for optimistic concurrency.
func SeverityHash(m finding.Meta) string { return BodyHash(m.Severity) }

// UpdateSeverity sets a manual severity; refused when a valid vector exists.
// A non-empty base must match SeverityHash of the current meta.
func (s *Store) UpdateSeverity(engID, dir, sev, base string, a gitrepo.Author) error {
	if !slices.Contains(s.cfg.Severities, sev) {
		return fmt.Errorf("%w: unknown severity %q", ErrInvalidValue, sev)
	}
	return s.mutate(engID, dir, a, func(f *finding.Finding) (string, error) {
		if base != "" && SeverityHash(f.Meta) != base {
			return "", ErrConflict
		}
		if _, err := cvss.Parse(f.Meta.CVSS); err == nil {
			return "", fmt.Errorf("%w: severity is derived from the CVSS vector", ErrInvalidValue)
		}
		return "set severity " + sev, f.SetMeta("severity", sev)
	})
}

// UpdateDetails replaces the given details rows (other existing rows kept).
func (s *Store) UpdateDetails(engID, dir string, values map[string]string, base string, a gitrepo.Author) error {
	return s.mutate(engID, dir, a, func(f *finding.Finding) (string, error) {
		if base != "" && DetailsHash(f.Meta) != base {
			return "", ErrConflict
		}
		merged := map[string]string{}
		for k, v := range f.Meta.Details {
			merged[k] = v
		}
		for k, v := range values {
			lines := strings.Split(strings.ReplaceAll(v, "\r\n", "\n"), "\n")
			for i := range lines {
				lines[i] = strings.TrimRight(lines[i], " \t")
			}
			merged[k] = strings.Trim(strings.Join(lines, "\n"), "\n")
		}
		return "edit details", f.SetMeta("details", finding.OrderedMap(s.cfg.DetailsRows, merged))
	})
}
