// Package history reads a finding's past versions from git and compares
// them section by section. Reading starts git (two processes), so the
// result is cached per repository HEAD.
package history

import (
	"strings"
	"time"

	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/lru"
)

// Version is the file as one commit left it (Raw nil: deleted there).
type Version struct {
	Hash, Author, Subject string
	Time                  time.Time
	Raw                   []byte
}

// AIFor starts the git author name of a commit the AI made for a user (Fix
// with AI, M31): "AI for alice".
const AIFor = "AI for "

// Who is the user a commit author name stands for, and whether the AI made
// the commit for them.
func Who(author string) (user string, ai bool) {
	if u, ok := strings.CutPrefix(author, AIFor); ok && u != "" {
		return u, true
	}
	return author, false
}

// Versions lists every version of path in r, newest first, following
// renames.
func Versions(r *gitrepo.Repo, path string) ([]Version, error) {
	es, err := r.LogFollow(path)
	if err != nil || len(es) == 0 {
		return nil, err
	}
	specs := make([]string, len(es))
	for i, e := range es {
		p := e.Path
		if p == "" {
			p = path
		}
		specs[i] = e.Hash + ":" + p
	}
	blobs, err := r.Blobs(specs)
	if err != nil {
		return nil, err
	}
	out := make([]Version, len(es))
	for i, e := range es {
		out[i] = Version{Hash: e.Hash, Author: e.Author, Subject: e.Subject, Time: e.Time, Raw: blobs[i]}
	}
	return out, nil
}

// Cache keeps Versions per key while the repository's HEAD stays the same.
type Cache struct{ c *lru.Cache[string, cached] }

type cached struct {
	head string
	vs   []Version
}

// NewCache holds up to n files' histories.
func NewCache(n int) *Cache { return &Cache{c: lru.New[string, cached](n)} }

// Versions is Versions(r, path), reused while head is unchanged. key names
// the file (engagement and finding).
func (c *Cache) Versions(r *gitrepo.Repo, key, head, path string) ([]Version, error) {
	if e, ok := c.c.Get(key); ok && e.head == head && head != "" {
		return e.vs, nil
	}
	vs, err := Versions(r, path)
	if err != nil {
		return nil, err
	}
	c.c.Add(key, cached{head: head, vs: vs})
	return vs, nil
}

// FrontMatter names the front matter (title, severity, CVSS, details) in
// Changes.
const FrontMatter = "Front matter"

// Line is one line of a diff: Op is ' ' (kept), '-' (removed) or '+'
// (added); Old and New are its line numbers on each side (0 = absent).
type Line struct {
	Op       byte
	Old, New int
	Text     string
}

// SectionChange is one part of the file that differs between two versions.
type SectionChange struct {
	Name           string
	Before, After  string
	Added, Removed int
	Lines          []Line
}

// split cuts a finding file into its front matter and sections (by name,
// in file order). A file that doesn't parse counts as one block of text.
func split(raw []byte) (string, []finding.Section) {
	if raw == nil {
		return "", nil
	}
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	f, err := finding.Parse([]byte(s))
	if err != nil {
		return s, nil
	}
	meta := ""
	if rest, ok := strings.CutPrefix(s, "---\n"); ok {
		if i := strings.Index(rest, "\n---\n"); i >= 0 {
			meta = rest[:i+1]
		}
	}
	return meta, f.Sections
}

func trim(s string) string { return strings.Trim(s, "\n") }

// Changes lists what differs from before to after (nil before = the first
// version): the front matter first, then each section in the newer file's
// order, then sections that were removed.
func Changes(before, after []byte) []SectionChange {
	bm, bs := split(before)
	am, as := split(after)
	var out []SectionChange
	add := func(name, b, a string) {
		b, a = trim(b), trim(a)
		if b == a {
			return
		}
		c := SectionChange{Name: name, Before: b, After: a, Lines: Diff(b, a)}
		for _, l := range c.Lines {
			switch l.Op {
			case '+':
				c.Added++
			case '-':
				c.Removed++
			}
		}
		out = append(out, c)
	}
	add(FrontMatter, bm, am)
	body := func(ss []finding.Section, name string) (string, bool) {
		for _, x := range ss {
			if x.Name == name {
				return x.Body, true
			}
		}
		return "", false
	}
	for _, x := range as {
		old, _ := body(bs, x.Name)
		add(x.Name, old, x.Body)
	}
	for _, x := range bs {
		if _, ok := body(as, x.Name); !ok {
			add(x.Name, x.Body, "")
		}
	}
	return out
}

// maxDiff bounds the lines compared one by one; bigger texts show as all
// removed and all added.
const maxDiff = 4000

func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Diff compares two texts line by line (longest common subsequence).
func Diff(a, b string) []Line {
	x, y := lines(a), lines(b)
	n, m := len(x), len(y)
	var out []Line
	if n*m > maxDiff*maxDiff/4 {
		for i, l := range x {
			out = append(out, Line{Op: '-', Old: i + 1, Text: l})
		}
		for j, l := range y {
			out = append(out, Line{Op: '+', New: j + 1, Text: l})
		}
		return out
	}
	// lcs[i][j]: common length of x[i:] and y[j:]
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			out = append(out, Line{Op: ' ', Old: i + 1, New: j + 1, Text: x[i]})
			i++
			j++
		case j < m && (i == n || lcs[i][j+1] > lcs[i+1][j]):
			out = append(out, Line{Op: '+', New: j + 1, Text: y[j]})
			j++
		default:
			out = append(out, Line{Op: '-', Old: i + 1, Text: x[i]})
			i++
		}
	}
	return out
}
