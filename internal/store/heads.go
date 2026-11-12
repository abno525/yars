package store

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"yars/internal/gitrepo"
)

// errMoved is returned when HEAD moved (e.g. a git push landed) between
// reading a finding and writing it; the caller should reload and retry.
var errMoved = fmt.Errorf("%w: the repository changed meanwhile (a push arrived); reload and try again", ErrConflict)

// unmoved reports whether the engagement repo's HEAD is still head0.
func (s *Store) unmoved(engID, head0 string) error {
	if s.beforeWrite != nil {
		s.beforeWrite()
	}
	if h, err := s.freshHead(engID); err != nil || h != head0 {
		return errMoved
	}
	return nil
}

// System is the author of commits YARS makes on its own (pointer updates).
var System = gitrepo.Author{Name: "yars", Email: "yars@yars.local"}

// EngRepo opens an engagement's own repository (engagements/<id>). Opened
// repos are remembered while their .git exists.
func (s *Store) EngRepo(id string) (*gitrepo.Repo, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	dir := filepath.Join(s.repo.Dir, "engagements", id)
	_, gerr := os.Lstat(filepath.Join(dir, ".git"))
	s.reposMu.Lock()
	defer s.reposMu.Unlock()
	if r, ok := s.repos[id]; ok && gerr == nil {
		return r, nil
	}
	delete(s.repos, id)
	r, err := gitrepo.Open(dir)
	if err != nil {
		return nil, err
	}
	if s.repos == nil {
		s.repos = map[string]*gitrepo.Repo{}
	}
	s.repos[id] = r
	return r, nil
}

// repoDir is the work tree of a repo by cache key ("" = main repo).
func (s *Store) repoDir(key string) string {
	if key == "" {
		return s.repo.Dir
	}
	return filepath.Join(s.repo.Dir, "engagements", key)
}

// freshHead reads a repo's HEAD from disk, bypassing the cache, and
// refreshes the cache with it.
func (s *Store) freshHead(key string) (string, error) {
	if key != "" && !ValidID(key) {
		return "", ErrNotFound
	}
	s.headsMu.RLock()
	gen := s.headGen
	s.headsMu.RUnlock()
	h, err := gitrepo.ReadHead(s.repoDir(key))
	if err != nil {
		return "", err
	}
	s.headsMu.Lock()
	if s.headGen == gen {
		if s.heads == nil {
			s.heads = map[string]string{}
		}
		s.heads[key] = h
	}
	s.headsMu.Unlock()
	return h, nil
}

// head is a repo's HEAD from the cache ("" key = main repo).
func (s *Store) head(key string) (string, error) {
	s.headsMu.RLock()
	h, ok := s.heads[key]
	s.headsMu.RUnlock()
	if ok {
		return h, nil
	}
	return s.freshHead(key)
}

// EngHead is an engagement repo's HEAD ("" before its first commit), from
// the cache: no git process.
func (s *Store) EngHead(id string) (string, error) {
	if !ValidID(id) {
		return "", ErrNotFound
	}
	return s.head(id)
}

// Invalidate drops the cached HEAD of an engagement repo ("" = the main
// repo), after a commit YARS did not make itself (a push).
func (s *Store) Invalidate(eng string) {
	s.headsMu.Lock()
	delete(s.heads, eng)
	s.headGen++
	s.headsMu.Unlock()
}

// Version identifies the content of all repositories (main and every
// engagement); it changes with any commit by YARS, and with a push once
// the git server called Invalidate. It starts no git process.
func (s *Store) Version() (string, error) {
	v, err := s.head("")
	if err != nil {
		return "", err
	}
	ents, _ := s.readDir("engagements")
	var b strings.Builder
	b.WriteString(v)
	for _, e := range ents {
		if e.IsDir() && ValidID(e.Name()) {
			h, _ := s.head(e.Name())
			b.WriteString("|" + e.Name() + "=" + h)
		}
	}
	return b.String(), nil
}

// SyncPointers moves the main repo's submodule pointers to every
// engagement's current HEAD, in one commit (none when nothing moved). It
// reads the cached HEADs and takes only the main repo's lock; with nothing
// to move it starts no git process.
func (s *Store) SyncPointers() error {
	s.mainMu.Lock()
	defer s.mainMu.Unlock()
	ents, err := s.readDir("engagements")
	if err != nil {
		return nil
	}
	mainHead, err := s.head("")
	if err != nil {
		return err
	}
	if s.links == nil || s.linksAt != mainHead {
		links, err := s.repo.Gitlinks("HEAD", "engagements")
		if err != nil {
			return err
		}
		s.links, s.linksAt = links, mainHead
	}
	moved := map[string]string{} // path -> new pointer
	var ids []string
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		h, err := s.head(e.Name())
		if err != nil || h == "" {
			continue
		}
		if s.links[e.Name()] != h {
			moved["engagements/"+e.Name()], ids = h, append(ids, e.Name())
		}
	}
	if len(ids) == 0 {
		return nil
	}
	// record exactly these HEADs (an engagement may commit meanwhile: it is
	// not locked here; the next sync catches up)
	err = s.repo.CommitGitlinks(moved, "engagements: update "+strings.Join(ids, ", "), System)
	s.Invalidate("")
	if err != nil {
		s.links = nil
		return err
	}
	next := maps.Clone(s.links)
	for _, id := range ids {
		next[id] = moved["engagements/"+id]
	}
	s.links = next
	if h, herr := s.head(""); herr == nil {
		s.linksAt = h
	} else {
		s.links = nil
	}
	return nil
}

// addSubmodule records a new engagement repo in the main repo: a
// .gitmodules entry and the pointer, in one commit.
func (s *Store) addSubmodule(id, msg string, a gitrepo.Author) error {
	b, err := s.readFile(".gitmodules")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	gm := string(b)
	if !strings.Contains(gm, `[submodule "engagements/`+id+`"]`) {
		if gm != "" && !strings.HasSuffix(gm, "\n") {
			gm += "\n"
		}
		gm += SubmoduleEntry(id)
		if err := s.writeFile(".gitmodules", []byte(gm)); err != nil {
			return err
		}
	}
	paths := []string{".gitmodules", "engagements/" + id}
	err = s.repo.Commit(paths, msg, a)
	s.Invalidate("")
	if err != nil {
		// leave the main repo exactly as it was
		s.repo.Unstage(paths)
		if b == nil {
			s.root.Remove(".gitmodules")
		} else {
			s.writeFile(".gitmodules", b)
		}
		return err
	}
	return nil
}

// SubmoduleEntry is the .gitmodules section for an engagement. ignore = all
// keeps local commits in the main repo from picking up pointer changes the
// server would refuse (the server moves pointers itself).
func SubmoduleEntry(id string) string {
	return fmt.Sprintf("[submodule \"engagements/%s\"]\n\tpath = engagements/%s\n\turl = ../e/%s\n\tbranch = main\n\tignore = all\n", id, id, id)
}

// newEngagementRepo turns engagements/<id> (already holding files) into its
// own repository with one commit of files, and adds it to the main repo.
// On failure the folder is removed.
func (s *Store) newEngagementRepo(id string, files []string, msg string, a gitrepo.Author) error {
	dir := engDir(id)
	r, err := gitrepo.Init(filepath.Join(s.repo.Dir, "engagements", id))
	if err == nil {
		err = r.Commit(files, msg, a)
	}
	s.Invalidate(id)
	if err == nil {
		err = s.addSubmodule(id, "engagement "+id+": add", a)
	}
	if err != nil {
		s.root.RemoveAll(dir)
		s.Invalidate(id)
		return err
	}
	return nil
}

// commit commits paths (data-dir relative, all in one engagement) in that
// engagement's repo; on failure it restores each path's previous content
// (nil = file did not exist) so the tree is left clean.
func (s *Store) commit(prev map[string][]byte, msg string, a gitrepo.Author, cleanupDir string) error {
	var paths []string
	for p := range prev {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	repo, rel, key := s.repo, paths, ""
	if seg := strings.SplitN(paths[0], "/", 3); len(seg) == 3 && seg[0] == "engagements" {
		r, err := s.EngRepo(seg[1])
		if err != nil {
			return err
		}
		repo, rel, key = r, nil, seg[1]
		for _, p := range paths {
			rel = append(rel, strings.TrimPrefix(p, "engagements/"+seg[1]+"/"))
		}
	}
	err := repo.Commit(rel, msg, a)
	s.Invalidate(key)
	if err == nil {
		return nil
	}
	repo.Unstage(rel)
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
