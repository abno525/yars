// mkfixture builds the M11 data folder of cmd/yars/upgrade_test.go. It is
// run from a worktree of the M11 release, so it builds against M11's
// packages (the go tool skips testdata folders here):
//
//	go run ./cmd/mkfixture <yars-m11 binary> <new data dir> <out.zip>
//
// It runs the M11 binary's init and useradd (director dora, pentester pete),
// creates engagement acme and two findings with M11's store as dora, and
// zips the data folder with its .git folders, keeping folders and file modes.
package main

import (
	"archive/zip"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

func main() {
	bin, dir, out := os.Args[1], os.Args[2], os.Args[3]
	run := func(stdin string, args ...string) {
		cmd := exec.Command(bin, args...)
		cmd.Stdin = strings.NewReader(stdin)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatal(args, err)
		}
	}
	run("", "init", dir)
	run("upgrade-test-1\n", "useradd", "--data", dir, "--role", "director", "--email", "dora@example.com", "dora")
	run("upgrade-test-2\n", "useradd", "--data", dir, "--role", "pentester", "--email", "pete@example.com", "pete")
	r, err := gitrepo.Open(dir)
	must(err)
	cfg, err := config.Load(dir)
	must(err)
	d, err := db.Open(db.Path(dir))
	must(err)
	st := store.New(r, cfg, d)
	a := gitrepo.Author{Name: "dora", Email: "dora@example.com"}
	must(st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME Web", Client: "ACME"}, a))
	_, err = st.CreateFinding("acme", "SQL injection in login", a)
	must(err)
	_, err = st.CreateFinding("acme", "Open redirect", a)
	must(err)
	must(d.Close())

	f, err := os.Create(out)
	must(err)
	zw := zip.NewWriter(f)
	must(filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := e.Info()
		if err != nil {
			return err
		}
		h, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if e.IsDir() {
			h.Name += "/"
			_, err = zw.CreateHeader(h)
			return err
		}
		h.Method = zip.Deflate
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(w, src)
		return err
	}))
	must(zw.Close())
	must(f.Close())
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
