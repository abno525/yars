package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

const chatUnion = "chat.jsonl merge=union"

// findingDirs lists engagements/<eng>/findings/<dir> folders (repo-relative).
func findingDirs(dir string) [][2]string {
	var out [][2]string
	engs, _ := os.ReadDir(filepath.Join(dir, "engagements"))
	for _, e := range engs {
		if !e.IsDir() || !store.ValidID(e.Name()) {
			continue
		}
		fds, _ := os.ReadDir(filepath.Join(dir, "engagements", e.Name(), "findings"))
		for _, f := range fds {
			if f.IsDir() && store.ValidID(f.Name()) {
				out = append(out, [2]string{e.Name(), f.Name()})
			}
		}
	}
	return out
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// legacyItems lists what in dir still uses the layout from before the
// database (empty = nothing to migrate).
func legacyItems(dir string) []string {
	var items []string
	for _, f := range []string{"users.yaml", "tokens.yaml"} {
		if exists(filepath.Join(dir, ".yars", f)) {
			items = append(items, ".yars/"+f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, ".gitattributes")); strings.Contains(string(b), chatUnion) {
		items = append(items, ".gitattributes (chat merge rule)")
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "engagements"))
	for _, e := range ents {
		if e.IsDir() && store.ValidID(e.Name()) && !ownRepo(dir, e.Name()) {
			items = append(items, "engagements/"+e.Name()+" (not its own repository yet)")
		}
	}
	for _, fd := range findingDirs(dir) {
		base := path.Join("engagements", fd[0], "findings", fd[1])
		if exists(filepath.Join(dir, base, "chat.jsonl")) {
			items = append(items, base+"/chat.jsonl")
		}
		if b, err := os.ReadFile(filepath.Join(dir, base, "finding.md")); err == nil {
			if f, err := finding.Parse(b); err == nil {
				if _, ok := f.Legacy(); ok {
					items = append(items, base+"/finding.md (workflow state)")
				}
			}
		}
	}
	return items
}

type legacyToken struct {
	User    string `yaml:"user"`
	Hash    string `yaml:"sha256"`
	Created string `yaml:"created"`
}

// cmdMigrate moves accounts, workflow state and chat from the files into the
// database: one database transaction, then one git commit. Running it again
// changes nothing.
func cmdMigrate(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	data := flags.String("data", ".", "data repo")
	if err := flags.Parse(args); err != nil {
		return err
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return err
	}
	d, err := db.Open(db.Path(r.Dir))
	if err != nil {
		return err
	}
	defer d.Close()

	// 1. accounts and tokens
	users, err := config.LoadUsers(r.Dir)
	if err != nil {
		return fmt.Errorf("users.yaml: %w", err)
	}
	for _, u := range users {
		if _, ok, err := d.User(u.Username); err != nil {
			return err
		} else if !ok {
			if err := d.AddUser(u); err != nil {
				return err
			}
			fmt.Fprintln(out, "account", u.Username)
		}
	}
	var toks []legacyToken
	if b, err := os.ReadFile(filepath.Join(r.Dir, ".yars", "tokens.yaml")); err == nil {
		if err := yaml.Unmarshal(b, &toks); err != nil {
			return fmt.Errorf("tokens.yaml: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, tk := range toks {
		if _, ok, _ := d.TokenUser(tk.Hash); !ok {
			if err := d.AddToken(tk.User, tk.Hash); err != nil {
				return fmt.Errorf("token of %s: %w", tk.User, err)
			}
			fmt.Fprintln(out, "API token of", tk.User)
		}
	}

	// 2. workflow state and chat
	type rewrite struct {
		rel        string
		orig, next []byte
	}
	var rewrites []rewrite
	var removed []string
	err = d.Tx(func(tx *db.Tx) error {
		for _, fd := range findingDirs(r.Dir) {
			eng, base := fd[0], path.Join("engagements", fd[0], "findings", fd[1])
			rel := base + "/finding.md"
			raw, err := os.ReadFile(filepath.Join(r.Dir, rel))
			if err != nil {
				continue
			}
			f, err := finding.Parse(raw)
			if err != nil {
				fmt.Fprintln(out, "skip", rel+":", err)
				continue
			}
			fid := f.Meta.ID
			if l, ok := f.Legacy(); ok {
				for _, k := range l.Keys {
					if err := f.SetMeta(k, nil); err != nil {
						return err
					}
				}
				next := f.Bytes()
				hash := store.ContentHash(next)
				st := db.State{Status: l.Status}
				if st.Status == "complete" || st.Status == "reported" {
					st.ApprovedHash = hash // approved for exactly this content
				}
				for _, n := range l.Reviewers {
					rv := db.Reviewer{Name: n}
					for _, c := range l.ClearedBy {
						if c == n {
							rv.ClearedHash = hash // cleared for this content
						}
					}
					st.Reviewers = append(st.Reviewers, rv)
				}
				if l.Returned != nil {
					st.ReturnedBy, st.ReturnedReason = l.Returned.By, l.Returned.Reason
				}
				if l.Retest != nil {
					st.RetestSource, st.RetestResult = l.Retest.Source, l.Retest.Result
				}
				if err := tx.PutState(eng, fid, st); err != nil {
					return err
				}
				rewrites = append(rewrites, rewrite{rel, raw, next})
				fmt.Fprintln(out, "state of", eng+"/"+fid)
			}
			cp := base + "/chat.jsonl"
			if cb, err := os.ReadFile(filepath.Join(r.Dir, cp)); err == nil {
				var have int
				for _, m := range chat.Parse(cb) {
					if err := tx.QueryRow("SELECT count(*) FROM chat WHERE id = ?", m.ID).Scan(&have); err != nil {
						return err
					}
					if have == 0 {
						if err := tx.AddMessage(eng, fid, m); err != nil {
							return err
						}
					}
				}
				removed = append(removed, cp)
				fmt.Fprintln(out, "chat of", eng+"/"+fid)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 3. files: strip state, drop chat files and the merge rule, ignore the
	// database; one commit
	var paths []string
	// everything changed on disk is put back if the commit fails, so an
	// interrupted migration leaves a clean tree (pushes need one)
	backup := map[string][]byte{}
	save := func(rel string) {
		if b, err := os.ReadFile(filepath.Join(r.Dir, rel)); err == nil {
			backup[rel] = b
		}
	}
	restore := func() {
		for rel, b := range backup {
			os.WriteFile(filepath.Join(r.Dir, rel), b, 0o644)
		}
		r.Unstage(paths)
	}
	for _, rw := range rewrites {
		backup[rw.rel] = rw.orig
		if err := os.WriteFile(filepath.Join(r.Dir, rw.rel), rw.next, 0o644); err != nil {
			restore()
			return err
		}
		paths = append(paths, rw.rel)
	}
	for _, p := range removed {
		save(p)
		if r.Tracked(p) {
			paths = append(paths, p)
		}
		os.Remove(filepath.Join(r.Dir, p))
	}
	gaPath := filepath.Join(r.Dir, ".gitattributes")
	save(".gitattributes")
	save(".gitignore")
	if b, err := os.ReadFile(gaPath); err == nil && strings.Contains(string(b), chatUnion) {
		var keep []string
		for _, l := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(l) != chatUnion && l != "" {
				keep = append(keep, l)
			}
		}
		if len(keep) == 0 {
			os.Remove(gaPath)
		} else {
			os.WriteFile(gaPath, []byte(strings.Join(keep, "\n")+"\n"), 0o644)
		}
		paths = append(paths, ".gitattributes")
	}
	if changed, err := writeIgnore(r.Dir); err != nil {
		restore()
		return err
	} else if changed {
		paths = append(paths, ".gitignore")
	}
	if len(paths) > 0 {
		if err := r.Commit(paths, "migrate: workflow state and chat moved to the database", system); err != nil {
			restore()
			return err
		}
	}
	for _, f := range []string{"users.yaml", "tokens.yaml"} {
		p := filepath.Join(r.Dir, ".yars", f)
		if r.Tracked(".yars/" + f) {
			if err := r.Untrack(".yars/"+f, "stop tracking "+f+" (accounts live in the database)", system); err != nil {
				return err
			}
		}
		os.Remove(p)
	}
	// 4. one repository per engagement
	if err := splitEngagements(r, out); err != nil {
		return err
	}
	if items := legacyItems(r.Dir); len(items) > 0 {
		return fmt.Errorf("still not migrated: %s", strings.Join(items, ", "))
	}
	fmt.Fprintln(out, "migrated", r.Dir)
	return nil
}

func gitIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "advice.addEmbeddedRepo=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// ownRepo reports whether engagements/<id> is already a repository.
func ownRepo(dir, id string) bool {
	return exists(filepath.Join(dir, "engagements", id, ".git"))
}

// splitEngagements turns every engagements/<id> folder of the main repo into
// a repository of its own, keeping that engagement's history (git subtree
// split; one import commit if that fails), and records them as submodules in
// one main-repo commit.
func splitEngagements(r *gitrepo.Repo, out io.Writer) error {
	ents, _ := os.ReadDir(filepath.Join(r.Dir, "engagements"))
	var paths []string
	gm, _ := os.ReadFile(filepath.Join(r.Dir, ".gitmodules"))
	for _, e := range ents {
		id := e.Name()
		if !e.IsDir() || !store.ValidID(id) || ownRepo(r.Dir, id) {
			continue
		}
		p, abs := "engagements/"+id, filepath.Join(r.Dir, "engagements", id)
		branch := "yars-split-" + id
		split := false
		if tracked, _ := gitIn(r.Dir, "ls-files", "--", p); tracked != "" {
			if _, err := gitIn(r.Dir, "subtree", "split", "-q", "-P", p, "-b", branch, "HEAD"); err == nil {
				split = true
			} else {
				fmt.Fprintln(out, "history of", id, "could not be kept (", err, "); importing its current files")
			}
			if _, err := gitIn(r.Dir, "rm", "-r", "-q", "--cached", "--", p); err != nil {
				return err
			}
		}
		if _, err := gitIn(abs, "init", "-q", "-b", "main"); err != nil {
			return err
		}
		if split {
			if _, err := gitIn(abs, "fetch", "-q", r.Dir, branch); err != nil {
				return err
			}
			if _, err := gitIn(abs, "reset", "-q", "FETCH_HEAD"); err != nil {
				return err
			}
			gitIn(r.Dir, "branch", "-q", "-D", branch)
		}
		// anything not in the split history (or everything, without it)
		if st, _ := gitIn(abs, "status", "--porcelain"); st != "" {
			er, err := gitrepo.Open(abs)
			if err != nil {
				return err
			}
			if err := er.Commit([]string{"."}, "engagement "+id+": import", system); err != nil {
				return err
			}
		}
		if !strings.Contains(string(gm), `[submodule "`+p+`"]`) {
			if len(gm) > 0 && gm[len(gm)-1] != '\n' {
				gm = append(gm, '\n')
			}
			gm = append(gm, fmt.Sprintf("[submodule %q]\n\tpath = %s\n\turl = ../e/%s\n\tbranch = main\n", p, p, id)...)
		}
		paths = append(paths, p)
		fmt.Fprintln(out, "engagement", id, "is now its own repository")
	}
	if len(paths) == 0 {
		return nil
	}
	if err := os.WriteFile(filepath.Join(r.Dir, ".gitmodules"), gm, 0o644); err != nil {
		return err
	}
	return r.Commit(append([]string{".gitmodules"}, paths...), "migrate: one repository per engagement", system)
}
