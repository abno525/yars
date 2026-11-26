//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// --out may name something that is there and is no file to protect: a
// device or a pipe (/dev/null, /dev/stdout into a pipe, a FIFO). The export
// is written into it, with and without --force, and it is not replaced by
// a file (review of pre1 2.23).
func TestExportCLIWritesThroughDevicesAndPipes(t *testing.T) {
	dir := exportFixture(t)
	var log bytes.Buffer
	for _, force := range []bool{false, true} {
		args := []string{"--data", dir, "--exporter", "confluence"}
		if force {
			args = append(args, "--force")
		}
		// a device
		if code, err := cmdExport(append(append([]string{}, args...), "--out", os.DevNull, "acme", "F-001"), &log); code != 0 || err != nil {
			t.Fatalf("force %v, %s: code %d err %v", force, os.DevNull, code, err)
		}
		if info, err := os.Lstat(os.DevNull); err != nil || info.Mode()&os.ModeCharDevice == 0 {
			t.Fatalf("force %v: %s is no device any more: %v %v", force, os.DevNull, info, err)
		}
		// a pipe with a name
		fifo := filepath.Join(t.TempDir(), "pipe")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Skip("no FIFOs here:", err)
		}
		got := make(chan string, 1)
		go func() {
			b, _ := os.ReadFile(fifo) // blocks until the export opens it
			got <- string(b)
		}()
		code, err := cmdExport(append(append([]string{}, args...), "--out", fifo, "acme", "F-001"), &log)
		if code != 0 || err != nil {
			// let the reader go: open the pipe for writing and close it
			if f, oerr := os.OpenFile(fifo, os.O_WRONLY, 0); oerr == nil {
				f.Close()
			}
			<-got
			t.Fatalf("force %v, a FIFO: code %d err %v", force, code, err)
		}
		if text := <-got; !strings.Contains(text, "SQL injection") {
			t.Fatalf("force %v: the reader of the FIFO got %d bytes", force, len(text))
		}
		if info, err := os.Lstat(fifo); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("force %v: the FIFO was replaced: %v %v", force, info, err)
		}
		if l, _ := filepath.Glob(filepath.Join(filepath.Dir(fifo), ".pipe.*")); len(l) != 0 {
			t.Fatalf("force %v: a temporary file is left: %v", force, l)
		}
	}
}
