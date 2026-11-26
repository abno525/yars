package backup

import (
	"archive/zip"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

// A restore takes no program from the ZIP's git folders: every hook is left
// out, and each repository's config is written again with the few settings
// a repository needs. So a hook, a hooks path or a program named in the
// config never runs on the server's own commits.
func TestRestoreDropsHooksAndConfig(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	marks := t.TempDir()
	script := func(p, mark string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\ntouch "+filepath.Join(marks, mark)+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir() // a hooks folder outside the data folder
	script(filepath.Join(outside, "pre-commit"), "outside-hook")
	script(filepath.Join(outside, "fsmonitor"), "fsmonitor")
	script(filepath.Join(dir, ".git", "hooks", "pre-commit"), "main-hook")
	script(filepath.Join(dir, "engagements", "acme", ".git", "hooks", "post-commit"), "eng-hook")
	for _, p := range []string{filepath.Join(dir, ".git"), filepath.Join(dir, "engagements", "acme", ".git")} {
		f, err := os.OpenFile(filepath.Join(p, "config"), os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString("[core]\n\tfsmonitor = " + filepath.Join(outside, "fsmonitor") + "\n[include]\n\tpath = " + filepath.Join(outside, "more") + "\n[filter \"x\"]\n\tclean = " + filepath.Join(outside, "fsmonitor") + "\n")
		f.Close()
		for name, body := range map[string]string{"config.worktree": "[core]\n\thooksPath = " + outside + "\n", "commondir": outside + "\n", "info/attributes": "* filter=x\n"} {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(p, name)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	zipPath := backupFile(t, dir, d, st)
	// set last: with it the folder's own commits would run the outside hook
	// (commondir is removed again so the source stays a repository)
	for _, p := range []string{filepath.Join(dir, ".git"), filepath.Join(dir, "engagements", "acme", ".git")} {
		os.Remove(filepath.Join(p, "commondir"))
	}

	dest := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(zipPath, dest); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{dest, filepath.Join(dest, "engagements", "acme")} {
		for _, gone := range []string{"hooks/pre-commit", "hooks/post-commit", "config.worktree", "commondir", "info/attributes"} {
			if _, err := os.Stat(filepath.Join(repo, ".git", gone)); !os.IsNotExist(err) {
				t.Errorf("%s/.git/%s restored (%v)", repo, gone, err)
			}
		}
		out, err := exec.Command("git", "-C", repo, "config", "--local", "--list").Output()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Fields(string(out)) {
			k, _, _ := strings.Cut(line, "=")
			if !gitConfigKeys[k] {
				t.Errorf("%s: config keeps %s", repo, line)
			}
		}
		if !strings.Contains(string(out), "core.repositoryformatversion=0") || !strings.Contains(string(out), "core.bare=false") {
			t.Errorf("%s: config lost its own settings:\n%s", repo, out)
		}
		// a commit as the server makes them
		r, err := gitrepo.Open(repo)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, "note.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := r.Commit([]string{"note.txt"}, "note", gitrepo.Author{Name: "yars", Email: "yars@yars.local"}); err != nil {
			t.Fatal(err)
		}
		if err := r.Fsck(); err != nil {
			t.Fatal(err)
		}
	}
	if ents, _ := os.ReadDir(marks); len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("programs from the ZIP ran: %v", names)
	}
}

// With the ZIP's config a commit would run the hook the config points at:
// the restored config has no hooks path.
func TestRestoreDropsHooksPath(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	marks, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "pre-commit"), []byte("#!/bin/sh\ntouch "+filepath.Join(marks, "ran")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("[core]\n\thooksPath = " + outside + "\n")
	f.Close()
	dest := filepath.Join(t.TempDir(), "restored")
	if _, err := Restore(backupFile(t, dir, d, st), dest); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dest, "note.txt"), []byte("x"), 0o644)
	if err := r.Commit([]string{"note.txt"}, "note", gitrepo.Author{Name: "yars", Email: "yars@yars.local"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(marks, "ran")); err == nil {
		t.Fatal("the hook the ZIP's config named ran on a commit")
	}
}

// A .git that is a file names another folder as the repository: refused
// before anything is written.
func TestRestoreRefusesGitFile(t *testing.T) {
	dbh := fileHeader(".yars/yars.db", 0o600)
	for _, name := range []string{".git", "engagements/acme/.git", "engagements/acme/findings/F-001-x/.git"} {
		t.Run(name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "restored")
			_, err := Restore(handZip(t, dbh, fileHeader(name, 0o644)), dest)
			if err == nil || !strings.Contains(err.Error(), name+": .git must be a folder") {
				t.Fatalf("err %v", err)
			}
			gone(t, dest)
		})
	}
}

// rezip copies the ZIP at src, giving each entry the name rename returns
// ("" leaves it out), and adds the entries of extra (a name ending in "/" is
// a folder; a file gets mode 0755).
func rezip(t *testing.T, src string, rename func(string) string, extra map[string]string) string {
	t.Helper()
	zr, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	p := filepath.Join(t.TempDir(), "hostile.zip")
	out, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	for _, f := range zr.File {
		name := rename(f.Name)
		if name == "" {
			continue
		}
		h := f.FileHeader
		h.Name = name
		w, err := zw.CreateHeader(&h)
		if err != nil {
			t.Fatal(err)
		}
		if f.Mode().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
	}
	for name, body := range extra {
		mode := fs.FileMode(0o755)
		if strings.HasSuffix(name, "/") {
			mode |= fs.ModeDir
		}
		w, err := zw.CreateHeader(fileHeader(name, mode))
		if err != nil {
			t.Fatal(err)
		}
		if !mode.IsDir() {
			io.WriteString(w, body)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// A repository laid out as a git folder itself (HEAD, objects and refs
// directly in the folder) beside an empty .git: git finds no repository in
// .git and takes the folder, with its config and hooks, which no clean-up of
// .git touched. Such a ZIP is refused before anything is written, in an
// engagement and in the data folder itself.
func TestRestoreRefusesGitFolderOutsideDotGit(t *testing.T) {
	for _, repo := range []string{"engagements/acme/", ""} {
		t.Run("in "+repo, func(t *testing.T) {
			dir, d, st := dataFolder(t, "acme")
			marks := t.TempDir()
			hook := "#!/bin/sh\ntouch " + filepath.Join(marks, "ran") + "\n"
			in := repo + ".git/"
			zipPath := rezip(t, backupFile(t, dir, d, st), func(name string) string {
				rest, ok := strings.CutPrefix(name, in)
				switch {
				case !ok:
					return name
				case rest == "" || rest == "config" || strings.HasPrefix(rest, "hooks/"):
					return ""
				}
				return repo + rest
			}, map[string]string{
				in:                        "",
				in + "HEAD":               "no ref\n", // a HEAD git does not read as one
				repo + "config":           "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tworktree = .\n",
				repo + "hooks/pre-commit": hook,
			})
			dest := filepath.Join(t.TempDir(), "restored")
			_, err := Restore(zipPath, dest)
			if err == nil {
				// what the server's first commit there does with it
				where := filepath.Join(dest, filepath.FromSlash(repo))
				r, oerr := gitrepo.Open(where)
				if oerr == nil {
					os.WriteFile(filepath.Join(where, "note.txt"), []byte("x"), 0o644)
					oerr = r.Commit([]string{"note.txt"}, "note", gitrepo.Author{Name: "yars", Email: "yars@yars.local"})
				}
				_, serr := os.Stat(filepath.Join(marks, "ran"))
				t.Fatalf("restored a git folder outside .git (commit: %v; the ZIP's hook ran: %v)", oerr, serr == nil)
			}
			want := strings.TrimSuffix(repo, "/")
			if want == "" {
				want = "the data folder"
			}
			if !strings.Contains(err.Error(), want+": a git folder outside .git") {
				t.Fatalf("err %v", err)
			}
			gone(t, dest)
		})
	}
}

// A .git folder without HEAD is no repository: git would look for one in
// the folders around it. Refused before anything is written.
func TestRestoreRefusesGitFolderWithoutHead(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	zipPath := rezip(t, backupFile(t, dir, d, st), func(name string) string {
		if name == "engagements/acme/.git/HEAD" {
			return ""
		}
		return name
	}, nil)
	dest := filepath.Join(t.TempDir(), "restored")
	_, err := Restore(zipPath, dest)
	if err == nil || !strings.Contains(err.Error(), "engagements/acme/.git: holds no HEAD") {
		t.Fatalf("err %v", err)
	}
	gone(t, dest)
}

// The config written at a restore keeps what makes the repository readable
// (a SHA-256 or reftable one too) and nothing else.
func TestGitConfigAllowList(t *testing.T) {
	in := "# a comment\n[core]\n\trepositoryformatversion = 1\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = true\n" +
		"\tfsmonitor = /tmp/x\n\thooksPath = /tmp/h\n\tsshCommand = \"/tmp/y\"\n\teditor = vi \\\n\tpager = less\n" +
		"[extensions]\n\tobjectFormat = sha256\n\trefStorage = reftable\n\tworktreeConfig = true\n" +
		"[include]\n\tpath = /tmp/z\n[core \"sub\"]\n\tbare = true\n[filter \"x\"]\n\tclean = /tmp/c\n[alias] bare = true\n"
	want := "[core]\n\trepositoryformatversion = 1\n\tfilemode = false\n\tbare = false\n\tlogallrefupdates = true\n[extensions]\n\tobjectformat = sha256\n\trefstorage = reftable\n"
	if got := cleanGitConfig([]byte(in)); string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// values that are not the plain ones are left out; nothing given is the default
	if got := cleanGitConfig([]byte("[core]\n\tbare = !sh\n\trepositoryformatversion = 7\n[extensions]\n\tobjectformat = md5\n")); string(got) != "[core]\n\trepositoryformatversion = 0\n" {
		t.Fatalf("got %q", got)
	}
	// git reads the result
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "--object-format=sha256", dir).CombinedOutput(); err != nil {
		t.Skipf("git init --object-format=sha256: %v: %s", err, out)
	}
	p := filepath.Join(dir, ".git", "config")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, cleanGitConfig(b), fs.FileMode(0o644)); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-object-format").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "sha256" {
		t.Fatalf("after the rewrite: %s %v", out, err)
	}
}
