package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// testHash is a bcrypt hash at the minimum cost. A login check reads the cost
// from the stored hash, so fixtures log in fast; production hashes stay at 12.
func testHash(t testing.TB, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

// The hook binary is the same for every push test, so it is built once per
// test process into a directory TestMain removes.
var (
	binOnce sync.Once
	binDir  string
	binPath string
	binErr  error
	binOut  []byte
)

func hookBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		binDir, binErr = os.MkdirTemp("", "yars-hookbin-")
		if binErr != nil {
			return
		}
		binPath = filepath.Join(binDir, "yars")
		binOut, binErr = exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
	})
	if binErr != nil {
		t.Fatalf("build: %v %s", binErr, binOut)
	}
	return binPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		os.RemoveAll(binDir)
	}
	os.Exit(code)
}
