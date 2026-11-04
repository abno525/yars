// Package index keeps an in-memory table of all findings, rebuilt whenever
// the data repo's HEAD (content) or the database (workflow state, chat)
// changes.
package index

import (
	"cmp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"yars/internal/chat"
	"yars/internal/cvss"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// Row is one finding in the table. Severity is derived from a valid CVSS
// vector when present; Score is the formatted base score or "".
type Row struct {
	EngID, Dir, ID, Title, Status, Severity, Author string
	Score                                           string
	OpenThreads                                     int
	IsRetest                                        bool   // copied into a retest engagement
	RetestResult                                    string // fixed | not_fixed | partially_fixed | ""
	Reviewers                                       []string
	Meta                                            finding.Meta // full front matter, for workflow classification
	score                                           float64      // -1 when no valid vector
}

func scoreOf(vec string) (string, float64) {
	v, err := cvss.Parse(vec)
	if err != nil {
		return "", -1
	}
	s, _ := cvss.Score(v)
	return cvss.FormatScore(s), s
}

// Query filters by exact field values (empty = any) and sorts by
// id|title|status|severity|author (default id).
type Query struct {
	EngID, Status, Severity, Author string
	Sort                            string
	Desc                            bool
}

var StatusOrder = []string{"draft", "verification", "complete", "reported"}

type Index struct {
	store *store.Store
	repo  *gitrepo.Repo
	mu    sync.RWMutex
	head  string
	built bool
	rows  []Row
}

func New(s *store.Store, r *gitrepo.Repo) *Index { return &Index{store: s, repo: r} }

// version identifies the data the index was built from: the git HEAD
// (content) plus the database change counter (workflow state, chat).
func (ix *Index) version() (string, error) {
	head, err := ix.repo.Head()
	if err != nil {
		return "", err
	}
	if d := ix.store.DB(); d != nil {
		seq, err := d.Seq()
		if err != nil {
			return "", err
		}
		head += "+" + strconv.FormatInt(seq, 10)
	}
	return head, nil
}

func (ix *Index) refresh() error {
	head, err := ix.version()
	if err != nil {
		return err
	}
	ix.mu.RLock()
	fresh := ix.built && head == ix.head
	ix.mu.RUnlock()
	if fresh {
		return nil
	}
	engs, err := ix.store.ListEngagements()
	if err != nil {
		return err
	}
	var rows []Row
	for _, e := range engs {
		refs, err := ix.store.ListFindings(e.ID)
		if err != nil {
			return err
		}
		chats, err := ix.store.EngagementChat(e.ID)
		if err != nil {
			return err
		}
		for _, r := range refs {
			m := r.F.Meta
			txt, sc := scoreOf(m.CVSS)
			open, _ := chat.OpenCount(chats[m.ID])
			rows = append(rows, Row{EngID: e.ID, Dir: r.Dir, ID: m.ID, Title: m.Title, Status: m.Status,
				Severity: cvss.Derive(m.CVSS, m.Severity), Author: m.Author, Reviewers: m.Reviewers,
				Score: txt, score: sc, Meta: m, OpenThreads: open})
			if m.Retest != nil {
				rows[len(rows)-1].IsRetest, rows[len(rows)-1].RetestResult = true, m.Retest.Result
			}
		}
	}
	ix.mu.Lock()
	ix.rows, ix.head, ix.built = rows, head, true
	ix.mu.Unlock()
	return nil
}

func rank(order []string, v string) int {
	for i, x := range order {
		if strings.EqualFold(x, v) {
			return i
		}
	}
	return len(order)
}

func (ix *Index) Rows(q Query) ([]Row, error) {
	if err := ix.refresh(); err != nil {
		return nil, err
	}
	ix.mu.RLock()
	var out []Row
	for _, r := range ix.rows {
		if (q.EngID == "" || r.EngID == q.EngID) && (q.Status == "" || r.Status == q.Status) &&
			(q.Severity == "" || r.Severity == q.Severity) && (q.Author == "" || r.Author == q.Author) {
			out = append(out, r)
		}
	}
	ix.mu.RUnlock()

	sev := ix.store.Config().Severities
	less := func(a, b Row) int {
		switch q.Sort {
		case "title":
			return strings.Compare(strings.ToLower(a.Title), strings.ToLower(b.Title))
		case "status":
			return rank(StatusOrder, a.Status) - rank(StatusOrder, b.Status)
		case "severity":
			return rank(sev, a.Severity) - rank(sev, b.Severity)
		case "author":
			return strings.Compare(a.Author, b.Author)
		case "cvss":
			return cmp.Compare(a.score, b.score)
		case "chat":
			return cmp.Compare(a.OpenThreads, b.OpenThreads)
		case "result":
			return strings.Compare(a.RetestResult, b.RetestResult)
		}
		return strings.Compare(a.Dir, b.Dir)
	}
	sort.SliceStable(out, func(i, j int) bool {
		c := less(out[i], out[j])
		if c == 0 {
			c = strings.Compare(out[i].Dir, out[j].Dir)
			return c < 0
		}
		if q.Desc {
			return c > 0
		}
		return c < 0
	})
	return out, nil
}
