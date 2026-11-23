// Package seed fills a data directory with generated engagements, findings,
// workflow state and chat, for benchmarks and demos (yars seed). Each
// engagement repo gets all its findings in one commit, and the main repo
// records every engagement in one commit, so large data sets build quickly.
package seed

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"yars/internal/auth"
	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// Options sizes the data set. Messages are spread at random over all
// findings. Seed makes the data repeatable (0 = a fixed default). Simple
// seeds the simple workflow's accounts and states (SimpleUsers; draft,
// complete, reported, withdrawn), for a data folder set up with yars init
// --simple.
type Options struct {
	Engagements, Findings, Messages int
	Seed                            uint64
	Simple                          bool
}

// Password is the password of every seeded account.
const Password = "password"

// Users are the seeded accounts: a director, a reviewer and a pentester.
var Users = []config.User{
	{Username: "dir1", Role: "director", Email: "dir1@yars.local", IsAdmin: true},
	{Username: "rev1", Role: "reviewer", Email: "rev1@yars.local"},
	{Username: "pen1", Role: "pentester", Email: "pen1@yars.local"},
}

// SimpleUsers are the accounts of a simple-workflow seed: two directors, as
// every account of that workflow is stored; dir1 is the admin.
var SimpleUsers = []config.User{
	{Username: "dir1", Role: "director", Email: "dir1@yars.local", IsAdmin: true},
	{Username: "dir2", Role: "director", Email: "dir2@yars.local"},
}

// EngID is the id of the i-th seeded engagement (0-based).
func EngID(i int) string { return fmt.Sprintf("e%03d", i+1) }

var titles = []string{
	"SQL injection in search", "Stored cross-site scripting in comments", "Missing rate limiting on login",
	"Insecure direct object reference", "Outdated TLS configuration", "Verbose error messages",
	"Server-side request forgery", "Weak password policy", "Session fixation", "Open redirect",
	"Missing security headers", "Path traversal in download", "XML external entity injection",
	"Cleartext credentials in logs", "Privilege escalation via role parameter",
}

var vectors = []string{
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
	"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
	"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
	"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
}

const para = "The application does not validate the `id` parameter before using it. " +
	"An attacker who controls this value can read or change data of other users. " +
	"See the request below for a working example.\n\n" +
	"```http\nGET /api/items?id=1%27%20OR%201=1-- HTTP/1.1\nHost: app.example\n```\n\n" +
	"- affects every tenant\n- requires a valid session\n- reproducible on staging and production\n"

// Fill adds the generated data to the initialised main repository in dir:
// accounts, engagement repos with findings, workflow state and chat (in
// the data directory's database). It refuses a directory that already has
// engagements.
func Fill(dir string, o Options) error {
	if o.Engagements < 1 || o.Findings < 0 || o.Messages < 0 {
		return errors.New("seed: need at least one engagement")
	}
	main, err := gitrepo.Open(dir)
	if err != nil {
		return err
	}
	cfg, err := config.Load(main.Dir)
	if err != nil {
		return err
	}
	engRoot := filepath.Join(main.Dir, "engagements")
	if ents, err := os.ReadDir(engRoot); err == nil {
		for _, e := range ents {
			if e.Name() != ".gitkeep" {
				return fmt.Errorf("seed: %s already has engagements", dir)
			}
		}
	}
	d, err := db.Open(db.Path(main.Dir))
	if err != nil {
		return err
	}
	defer d.Close()
	hash, err := auth.HashPassword(Password)
	if err != nil {
		return err
	}
	// the accounts, the writer of most findings and the team besides dir1
	// (who directs), per workflow
	users, writer, team, state := Users, "pen1", []string{"rev1", "pen1"}, randomState
	if o.Simple {
		users, writer, team, state = SimpleUsers, "dir2", []string{"dir2"}, randomSimpleState
	}
	for _, u := range users {
		u.PasswordHash = hash
		if err := d.AddUser(u); err != nil {
			return err
		}
	}
	seed := o.Seed
	if seed == 0 {
		seed = 12
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	// spread the messages over all findings
	perFinding := make([]int, o.Engagements*o.Findings)
	if len(perFinding) > 0 {
		for range o.Messages {
			perFinding[rng.IntN(len(perFinding))]++
		}
	} else if o.Messages > 0 {
		return errors.New("seed: messages need findings")
	}
	t0 := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)
	author := gitrepo.Author{Name: writer, Email: writer + "@yars.local"}
	gm := ""
	paths := []string{".gitmodules"}
	for ei := range o.Engagements {
		id := EngID(ei)
		edir := filepath.Join(engRoot, id)
		if err := os.MkdirAll(filepath.Join(edir, "findings"), 0o755); err != nil {
			return err
		}
		eb, _ := yaml.Marshal(store.Engagement{Name: "Engagement " + id, Client: fmt.Sprintf("Client %d", ei%7+1), Type: "pentest"})
		if err := os.WriteFile(filepath.Join(edir, "engagement.yaml"), eb, 0o644); err != nil {
			return err
		}
		type gen struct {
			fid  string
			hash string
			msgs int
		}
		var made []gen
		for fi := range o.Findings {
			fid := fmt.Sprintf("F-%03d", fi+1)
			title := titles[rng.IntN(len(titles))]
			who := writer
			if rng.IntN(5) == 0 {
				who = "dir1"
			}
			f := finding.New(fid, title, who, cfg.Sections)
			for _, s := range cfg.Sections {
				f.SetSection(s, para)
			}
			if rng.IntN(3) > 0 {
				if err := f.SetMeta("cvss", vectors[rng.IntN(len(vectors))]); err != nil {
					return err
				}
			} else if err := f.SetMeta("severity", cfg.Severities[rng.IntN(len(cfg.Severities))]); err != nil {
				return err
			}
			fdir := filepath.Join(edir, "findings", fid+"-"+store.Slug(title))
			if err := os.MkdirAll(fdir, 0o755); err != nil {
				return err
			}
			raw := f.Bytes()
			if err := os.WriteFile(filepath.Join(fdir, "finding.md"), raw, 0o644); err != nil {
				return err
			}
			made = append(made, gen{fid, store.ContentHash(raw), perFinding[ei*o.Findings+fi]})
		}
		r, err := gitrepo.Init(edir)
		if err != nil {
			return err
		}
		files := []string{"engagement.yaml"}
		if o.Findings > 0 {
			files = append(files, "findings")
		}
		if err := r.Commit(files, fmt.Sprintf("engagement %s: seed (%d findings)", id, o.Findings), author); err != nil {
			return err
		}
		gm += store.SubmoduleEntry(id)
		paths = append(paths, "engagements/"+id)
		ts := t0
		err = d.TxFor(id, func(tx *db.Tx) error {
			if err := tx.AddMembers(id, team...); err != nil { // the team (dir1 directs)
				return err
			}
			for _, g := range made {
				if err := tx.PutState(id, g.fid, state(rng, g.hash)); err != nil {
					return err
				}
				var open []string // thread roots not yet resolved
				for range g.msgs {
					ts = ts.Add(time.Minute)
					m := chat.Message{ID: chat.NewID(), TS: ts, User: users[rng.IntN(len(users))].Username}
					switch p := rng.IntN(100); {
					case len(open) == 0 || p < 35:
						m.Text = "Please check the wording of this section; the impact looks overstated."
						if rng.IntN(4) > 0 {
							m.Section = cfg.Sections[rng.IntN(len(cfg.Sections))]
						}
						open = append(open, m.ID)
					case p < 90:
						m.Reply = open[rng.IntN(len(open))]
						m.Text = "Agreed, updated the text and added the request."
					default:
						k := rng.IntN(len(open))
						m.Resolves = open[k]
						open = append(open[:k], open[k+1:]...)
					}
					if err := tx.AddMessage(id, g.fid, m); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(main.Dir, ".gitmodules"), []byte(gm), 0o644); err != nil {
		return err
	}
	// keep the database out of the main repo
	gi := filepath.Join(main.Dir, ".gitignore")
	b, _ := os.ReadFile(gi)
	if !strings.Contains(string(b), ".yars/yars.db*") {
		s := string(b)
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		if err := os.WriteFile(gi, []byte(s+".yars/yars.db*\n"), 0o644); err != nil {
			return err
		}
		paths = append(paths, ".gitignore")
	}
	return main.Commit(paths, fmt.Sprintf("seed: %d engagements", o.Engagements), store.System)
}

// randomState picks a workflow state; approvals and clearances are bound to
// the content hash, as the store does.
func randomState(rng *rand.Rand, hash string) db.State {
	st := db.State{Status: "draft"}
	switch p := rng.IntN(100); {
	case p < 40:
		if rng.IntN(5) == 0 {
			st.ReturnedBy, st.ReturnedReason = "rev1", "Needs a clearer impact section."
		}
	case p < 70:
		st.Status = "verification"
		st.Reviewers = []db.Reviewer{{Name: "rev1"}}
		if rng.IntN(2) == 0 {
			st.Reviewers[0].ClearedHash = hash
		}
	case p < 90:
		st.Status, st.ApprovedHash = "complete", hash
		st.Reviewers = []db.Reviewer{{Name: "rev1", ClearedHash: hash}}
	default:
		st.Status, st.ApprovedHash = "reported", hash
		st.Reviewers = []db.Reviewer{{Name: "rev1", ClearedHash: hash}}
	}
	return st
}

// randomSimpleState picks a state of the simple workflow: no reviewers, an
// approval bound to the content hash as Complete binds it.
func randomSimpleState(rng *rand.Rand, hash string) db.State {
	st := db.State{Status: "draft"}
	switch p := rng.IntN(100); {
	case p < 45:
	case p < 75:
		st.Status, st.ApprovedHash = "complete", hash
	case p < 90:
		st.Status, st.ApprovedHash = "reported", hash
	default:
		st.Status, st.WithdrawnBy, st.WithdrawnReason = "withdrawn", "dir1", "Out of scope."
	}
	return st
}
