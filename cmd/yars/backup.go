package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/backup"
	"github.com/abno525/yars/internal/db"
)

// backupTries is how often cmdBackup takes the backup again when Verify
// refuses it.
const backupTries = 3

// verifyBackup checks a backup file (a test replaces it).
var verifyBackup = backup.Verify

// linkFile puts the finished backup in place without replacing a file (a
// test replaces it).
var linkFile = os.Link

// cmdBackup writes a verified backup of the data folder: yars backup [--data
// dir] [--key] --out file.zip. It takes no locks, so it works while the
// server runs: a backup that a commit landing meanwhile made inconsistent
// fails Verify and is taken again.
func cmdBackup(args []string, out io.Writer) error {
	f := flag.NewFlagSet("backup", flag.ContinueOnError)
	data := dataFlag(f)
	withKey := f.Bool("key", false, "include .yars/secret.key (decrypts stored AI and personal keys and webhook secrets)")
	to := f.String("out", "", "the ZIP file to write (must not exist)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *to == "" || f.NArg() != 0 {
		return fmt.Errorf("usage: yars backup [--data <dir>] [--key] --out <file.zip>")
	}
	if _, err := os.Lstat(*to); err == nil {
		return fmt.Errorf("%s exists already", *to)
	}
	r, err := openData(f, *data)
	if err != nil {
		return err
	}
	if inside(*to, r.Dir) {
		return fmt.Errorf("%s is inside the data folder %s; write the backup elsewhere", *to, r.Dir)
	}
	d, err := dataDB(r.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	part := *to + ".part"
	var last error
	for try := 0; try < backupTries; try++ {
		// a .part that exists belongs to another backup (or a crashed one)
		fh, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			return fmt.Errorf("%s exists: another yars backup is writing it; remove it if none is", part)
		}
		if err != nil {
			return err
		}
		n, err := writeBackup(fh, r.Dir, d, *withKey)
		var rep backup.Report
		if err == nil {
			rep, err = verifyBackup(part)
		}
		if err != nil {
			os.Remove(part)
			last = err
			continue
		}
		if err := place(part, *to); err != nil {
			return err
		}
		detail := "without key"
		if *withKey {
			detail = "with key"
		}
		d.Audit("cli", "backup", "", detail+" · "+byteSize(n))
		fmt.Fprintf(out, "wrote %s (%s, %s, %s)\n", *to, byteSize(n), count(rep.Engagements, "engagement"), count(rep.Findings, "finding"))
		return nil
	}
	return fmt.Errorf("could not take a consistent backup while the server is writing; try again (last try: %v)", last)
}

// place puts the verified part file at to without replacing a file there:
// a hard link, or where the file system has none, a rename after looking
// again. The part file is gone afterwards.
func place(part, to string) error {
	err := linkFile(part, to)
	if err == nil || os.IsExist(err) {
		os.Remove(part)
		if err != nil {
			return fmt.Errorf("%s exists already", to)
		}
		return nil
	}
	if _, lerr := os.Lstat(to); lerr == nil {
		os.Remove(part)
		return fmt.Errorf("%s exists already", to)
	}
	if err := os.Rename(part, to); err != nil {
		os.Remove(part)
		return err
	}
	return nil
}

// inside reports whether file would be written inside dir (both resolved,
// links followed).
func inside(file, dir string) bool {
	parent, err := filepath.Abs(filepath.Dir(file))
	if err != nil {
		return false
	}
	if p, err := filepath.EvalSymlinks(parent); err == nil {
		parent = p
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	if p, err := filepath.EvalSymlinks(root); err == nil {
		root = p
	}
	return parent == root || strings.HasPrefix(parent, root+string(filepath.Separator))
}

// writeBackup writes a backup of dir to fh, without locks, and closes it.
func writeBackup(fh *os.File, dir string, d *db.DB, withKey bool) (int64, error) {
	n, err := backup.Write(fh, dir, d, nil, backup.Options{WithKey: withKey})
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// cmdRestore turns a backup into a new data folder and checks it: yars
// restore --from file.zip --data newdir. --data is never defaulted: a restore
// never writes into a folder in use.
func cmdRestore(args []string, out io.Writer) error {
	f := flag.NewFlagSet("restore", flag.ContinueOnError)
	from := f.String("from", "", "the backup ZIP")
	data := f.String("data", "", "the new data folder (missing or empty)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *from == "" || *data == "" || f.NArg() != 0 {
		return fmt.Errorf("usage: yars restore --from <file.zip> --data <new dir>")
	}
	rep, err := backup.Restore(*from, *data)
	if err != nil {
		return err
	}
	key := "no"
	if rep.HasKey {
		key = "yes"
	}
	fmt.Fprintf(out, "schema v%d\n%s\n%s\nsecret key: %s\n", rep.Schema, count(rep.Engagements, "engagement"), count(rep.Findings, "finding"), key)
	if !rep.HasKey {
		fmt.Fprintln(out, "stored AI and personal keys must be entered again; delete the webhooks and add them again (their secrets cannot be read)")
	}
	fmt.Fprintf(out, "next: yars serve --data %s\n", *data)
	return nil
}

// count is "1 finding", "2 findings".
func count(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// byteSize shows a byte count as the website's audit lines do: B, KB, MB, GB.
func byteSize(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1<<20:
		return strconv.FormatFloat(float64(n)/1024, 'f', 1, 64) + " KB"
	case n < 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	default:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GB"
	}
}
