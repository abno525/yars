package main

// testdata/m11-data.zip is a data folder made by the M11 release (8fce339,
// the M11 merge on master), built once:
//
//	git worktree add --detach <scratch>/m11 8fce339
//	go -C <scratch>/m11 build -o <scratch>/yars-m11 ./cmd/yars
//	go -C <scratch>/m11 run ./cmd/mkfixture <scratch>/yars-m11 <scratch>/m11data <scratch>/m11-data.zip
//	git worktree remove --force <scratch>/m11
//
// cmd/mkfixture, a throwaway program in that worktree (so it imports the
// M11 packages), ran the M11 binary's `init <dir>` and
// `useradd --data <dir> --role director --email dora@example.com dora`
// (password "upgrade-test-1" on stdin), then created engagement acme
// ("ACME Web") and its findings "SQL injection in login" and "Open
// redirect" with store.CreateEngagement and store.CreateFinding, and zipped
// the data folder with its .git folders.

import (
	"archive/zip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/gitserve"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/web"
)

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

// A data folder written by M11 opens with this version: the trees are
// restored, the database migrates to the current schema (keeping a
// snapshot), the findings list with their titles, the M11 account logs in,
// and the website answers.
func TestUpgradeFromM11Data(t *testing.T) {
	dir := t.TempDir()
	unzipTo(t, filepath.Join("testdata", "m11-data.zip"), dir)
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := gitserve.RestoreTrees(r); err != nil {
		t.Fatal(err)
	}
	if items := legacyItems(dir); len(items) > 0 {
		t.Fatalf("yars serve would ask to migrate: %v", items)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(db.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if v, err := d.Version(); err != nil || v != db.SchemaVersion {
		t.Fatalf("schema %d, want %d (%v)", v, db.SchemaVersion, err)
	}
	snaps, _ := filepath.Glob(filepath.Join(dir, ".yars", "yars.db.before-v*"))
	if len(snaps) == 0 {
		t.Fatal("no snapshot of the M11 database")
	}
	st := store.New(r, cfg, d)
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
	au := auth.New(d)
	if _, ok := au.Login("dora", "upgrade-test-1"); !ok {
		t.Fatal("the M11 account does not log in")
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
