package web

import (
	"bytes"
	"go/format"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every Go file of the module is gofmt-formatted (the check runs with the
// tests, so it holds where gofmt itself isn't run).
func TestGofmt(t *testing.T) {
	root := filepath.Join("..", "..") // the module, from internal/web
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Skip("module root not found")
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != root && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if out, err := format.Source(b); err != nil || !bytes.Equal(b, out) {
			t.Errorf("%s is not gofmt-formatted", p)
		}
		return nil
	})
}
