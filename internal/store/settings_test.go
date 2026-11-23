package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEditSettingsCommits(t *testing.T) {
	s, dir := withEngagement(t)
	err := s.EditSettings("rules: save r", alice, func(read func(string) ([]byte, error)) ([]SettingsFile, error) {
		if _, err := read(".yars/rules/r.yaml"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read of a missing file: %v", err)
		}
		return []SettingsFile{
			{Path: ".yars/rules/r.yaml", Data: []byte("- id: r\n  check: not-empty\n")},
			{Path: ".yars/rules/r.sh", Data: []byte("#!/bin/sh\necho '[]'\n"), Exec: true},
		}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := mainLast(t, dir, "%an|%s"); got != "alice|rules: save r" {
		t.Fatalf("commit %q", got)
	}
	out, _ := exec.Command("git", "-C", dir, "ls-files", "-s", ".yars/rules/r.sh").Output()
	if !strings.HasPrefix(string(out), "100755") {
		t.Fatalf("script mode: %s", out)
	}
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain", ".yars").Output(); len(st) != 0 {
		t.Fatalf("tree not clean: %s", st)
	}
	// reading sees the committed file; nil data removes it
	err = s.EditSettings("rules: delete r", alice, func(read func(string) ([]byte, error)) ([]SettingsFile, error) {
		b, err := read(".yars/rules/r.yaml")
		if err != nil || !strings.Contains(string(b), "id: r") {
			t.Fatalf("read %q %v", b, err)
		}
		return []SettingsFile{{Path: ".yars/rules/r.yaml"}}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".yars", "rules", "r.yaml")); !os.IsNotExist(err) {
		t.Fatal("file not removed")
	}
	if got := mainLast(t, dir, "%s"); got != "rules: delete r" {
		t.Fatalf("commit %q", got)
	}
}

func TestEditSettingsCheckFailsRestores(t *testing.T) {
	s, dir := withEngagement(t)
	p := filepath.Join(dir, ".yars", "rules", "r.yaml")
	put := func(data string) error {
		return s.EditSettings("save", alice, func(func(string) ([]byte, error)) ([]SettingsFile, error) {
			return []SettingsFile{{Path: ".yars/rules/r.yaml", Data: []byte(data)}}, nil
		}, func() error {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), "bad") {
				return errors.New("bad rule")
			}
			return nil
		})
	}
	if err := put("- id: good\n"); err != nil {
		t.Fatal(err)
	}
	head := mainLast(t, dir, "%H")
	if err := put("- id: bad\n"); err == nil || err.Error() != "bad rule" {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "- id: good\n" {
		t.Fatalf("not restored: %q", b)
	}
	if mainLast(t, dir, "%H") != head {
		t.Fatal("committed anyway")
	}
	// only settings under .yars, never the server's private files
	for _, bad := range []string{"engagements/x.yaml", ".yars/yars.db", ".yars/users.yaml", ".yars/../x", "/etc/x"} {
		err := s.EditSettings("x", alice, func(func(string) ([]byte, error)) ([]SettingsFile, error) {
			return []SettingsFile{{Path: bad, Data: []byte("x")}}, nil
		}, nil)
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
