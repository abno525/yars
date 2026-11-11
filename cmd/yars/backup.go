package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"yars/internal/backup"
	"yars/internal/db"
)

// backupTries is how often cmdBackup takes the backup again when Verify
// refuses it.
const backupTries = 3

// verifyBackup checks a backup file (a test replaces it).
var verifyBackup = backup.Verify

// cmdBackup writes a verified backup of the data folder: yars backup [--data
// dir] [--key] --out file.zip. It takes no locks, so it works while the
// server runs: a backup that a commit landing meanwhile made inconsistent
// fails Verify and is taken again.
func cmdBackup(args []string, out io.Writer) error {
	f := flag.NewFlagSet("backup", flag.ContinueOnError)
	data := dataFlag(f)
	withKey := f.Bool("key", false, "include .yars/secret.key (decrypts stored AI and personal keys)")
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
	d, err := dataDB(r.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	part := *to + ".part"
	for try := 0; try < backupTries; try++ {
		n, err := writeBackup(part, r.Dir, d, *withKey)
		if err != nil {
			os.Remove(part)
			return err
		}
		rep, err := verifyBackup(part)
		if err != nil {
			os.Remove(part)
			continue
		}
		if err := os.Rename(part, *to); err != nil {
			os.Remove(part)
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
	return fmt.Errorf("could not take a consistent backup while the server is writing; try again")
}

// writeBackup writes a backup of dir to path (created or truncated), without
// locks.
func writeBackup(path, dir string, d *db.DB, withKey bool) (int64, error) {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
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
		fmt.Fprintln(out, "stored AI and personal keys must be entered again")
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
