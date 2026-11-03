// Package store maps the data repo layout to engagements and findings.
// Every write is a single git commit.
package store

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/gitrepo"
)

var ErrNotFound = errors.New("not found")

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
	repo *gitrepo.Repo
	cfg  config.Config
	mu   sync.Mutex
}

func New(r *gitrepo.Repo, cfg config.Config) *Store { return &Store{repo: r, cfg: cfg} }

func (s *Store) Config() config.Config { return s.cfg }
func (s *Store) Repo() *gitrepo.Repo   { return s.repo }

var idRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func ValidID(id string) bool { return idRe.MatchString(id) && id != "." && id != ".." }

func (s *Store) engDir(id string) string { return filepath.Join(s.repo.Dir, "engagements", id) }

func (s *Store) ListEngagements() ([]Engagement, error) {
	ents, err := os.ReadDir(filepath.Join(s.repo.Dir, "engagements"))
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
	b, err := os.ReadFile(filepath.Join(s.engDir(id), "engagement.yaml"))
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

func (s *Store) CreateEngagement(e Engagement, a gitrepo.Author) error {
	if !ValidID(e.ID) {
		return fmt.Errorf("invalid engagement id %q", e.ID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := s.engDir(e.ID)
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("engagement %s already exists", e.ID)
	}
	if e.Type == "" {
		e.Type = "pentest"
	}
	b, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "findings"), 0o755); err != nil {
		return err
	}
	rel := filepath.Join("engagements", e.ID, "engagement.yaml")
	if err := os.WriteFile(filepath.Join(s.repo.Dir, rel), b, 0o644); err != nil {
		return err
	}
	return s.repo.Commit([]string{rel}, "engagement "+e.ID+": create", a)
}

// ListFindings returns parseable findings of an engagement, sorted by dir.
// Unparseable finding files are logged and skipped so one bad local edit
// cannot hide the whole table.
func (s *Store) ListFindings(engID string) ([]FindingRef, error) {
	if _, err := s.Engagement(engID); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(filepath.Join(s.engDir(engID), "findings"))
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

func (s *Store) findingPath(engID, dir string) string {
	return filepath.Join(s.engDir(engID), "findings", dir, "finding.md")
}

func (s *Store) Finding(engID, dir string) (FindingRef, error) {
	if !ValidID(engID) || !ValidID(dir) {
		return FindingRef{}, ErrNotFound
	}
	b, err := os.ReadFile(s.findingPath(engID, dir))
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
	fdir := filepath.Join(s.engDir(engID), "findings")
	ents, _ := os.ReadDir(fdir)
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
	if err := os.MkdirAll(filepath.Join(fdir, dir), 0o755); err != nil {
		return FindingRef{}, err
	}
	if err := os.WriteFile(s.findingPath(engID, dir), f.Bytes(), 0o644); err != nil {
		return FindingRef{}, err
	}
	rel := filepath.Join("engagements", engID, "findings", dir, "finding.md")
	if err := s.repo.Commit([]string{rel}, id+": create", a); err != nil {
		return FindingRef{}, err
	}
	return FindingRef{EngID: engID, Dir: dir, F: f}, nil
}

func (s *Store) UpdateSection(engID, dir, section, body string, a gitrepo.Author) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	before := ref.F.Bytes()
	ref.F.SetSection(section, body)
	after := ref.F.Bytes()
	if string(before) == string(after) {
		return nil
	}
	if err := os.WriteFile(s.findingPath(engID, dir), after, 0o644); err != nil {
		return err
	}
	rel := filepath.Join("engagements", engID, "findings", dir, "finding.md")
	return s.repo.Commit([]string{rel}, ref.F.Meta.ID+": edit "+section, a)
}
