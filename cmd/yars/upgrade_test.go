package main

// testdata/m11-data.zip is a data folder made by the M11 release (8fce339,
// the M11 merge on master), built once from this folder:
//
//	git worktree add --detach <scratch>/m11 8fce339
//	mkdir <scratch>/m11/cmd/mkfixture
//	cp cmd/yars/testdata/mkfixture/main.go <scratch>/m11/cmd/mkfixture/
//	go -C <scratch>/m11 build -o <scratch>/yars-m11 ./cmd/yars
//	go -C <scratch>/m11 run ./cmd/mkfixture <scratch>/yars-m11 <scratch>/m11data cmd/yars/testdata/m11-data.zip
//	git worktree remove --force <scratch>/m11
//
// testdata/mkfixture runs the M11 binary's init and useradd (director dora,
// password "upgrade-test-1"; pentester pete, "upgrade-test-2"), creates
// engagement acme ("ACME Web", client ACME) with the findings "SQL
// injection in login" and "Open redirect" through M11's store as dora, and
// zips the data folder with its .git folders, keeping folders and modes.

import (
	"archive/zip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/secret"
	"yars/internal/web"
)

// gitOut is git's trimmed output in repo; a failure fails the test.
func gitOut(t *testing.T, repo string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// unzipTo unpacks a test fixture into dir, with its files' modes.
func unzipTo(t *testing.T, zipPath, dir string) {
	t.Helper()
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		p := filepath.Join(dir, filepath.FromSlash(f.Name))
		if !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			t.Fatalf("%s is outside the folder", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		src, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		dst, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm())
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(dst, src)
		src.Close()
		if cerr := dst.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// A data folder written by M11 starts with this version, through the same
// steps as yars serve: the database migrates from M11's schema (1), keeping
// a snapshot; the director stays an admin and the M11 accounts join their
// engagement's team; the server files are ignored and the engagement pointer
// follows its repository, leaving both trees clean; the git server sets up;
// the findings list with their titles, both accounts log in, and the
// website answers.
func TestUpgradeFromM11Data(t *testing.T) {
	dir := t.TempDir()
	unzipTo(t, filepath.Join("testdata", "m11-data.zip"), dir)
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, d, st, err := prepareData(r)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	snap := filepath.Join(dir, ".yars", "yars.db.before-v1")
	if v, err := db.SchemaOf(snap); err != nil || v != 1 {
		t.Fatalf("the snapshot of the M11 database: schema %d (%v)", v, err)
	}
	if u, ok, _ := d.User("dora"); !ok || !u.IsAdmin {
		t.Fatalf("the M11 director is not an admin: %+v", u)
	}
	pete, ok, _ := d.User("pete")
	if m, _ := d.Members("acme"); !ok || !slices.Contains(m, "pete") || !st.CanSee(pete, "acme") {
		t.Fatalf("the M11 pentester is not on acme's team: %v", m)
	}
	for _, repo := range []string{dir, filepath.Join(dir, "engagements", "acme")} {
		if out := gitOut(t, repo, "status", "--porcelain"); out != "" {
			t.Fatalf("%s is not clean after the start:\n%s", repo, out)
		}
	}
	if head, ptr := gitOut(t, filepath.Join(dir, "engagements", "acme"), "rev-parse", "HEAD"), gitOut(t, dir, "rev-parse", "HEAD:engagements/acme"); head != ptr {
		t.Fatalf("the pointer is at %s, acme at %s", ptr, head)
	}
	if out := gitOut(t, dir, "check-ignore", ".yars/secret.key"); out != ".yars/secret.key" {
		t.Fatalf("the secret key is not ignored: %q", out)
	}
	au := auth.New(d)
	if err := gitServer(r, au, auth.NewTokens(d), st, "yars", func(string) {}).Setup(); err != nil {
		t.Fatal(err)
	}
	if _, err := secret.Open(dir); err != nil {
		t.Fatal(err)
	}
	refs, err := st.ListFindings("acme")
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	for _, ref := range refs {
		titles = append(titles, ref.F.Meta.Title)
	}
	slices.Sort(titles)
	if strings.Join(titles, "|") != "Open redirect|SQL injection in login" {
		t.Fatalf("findings %q", titles)
	}
	for user, pw := range map[string]string{"dora": "upgrade-test-1", "pete": "upgrade-test-2"} {
		if _, ok := au.Login(user, pw); !ok {
			t.Fatalf("the M11 account %s does not log in", user)
		}
	}
	ix := index.New(st, r)
	if n := ix.Findings(); n != 2 {
		t.Fatalf("the index holds %d findings", n)
	}
	h := (&web.Server{Store: st, Index: ix, Auth: au, Cfg: cfg}).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: %d", rec.Code)
	}
}
