package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// typing makes useradd and passwd see a terminal on which lines are typed,
// one per prompt; it returns how many were read.
func typing(t *testing.T, lines ...string) *int {
	t.Helper()
	old := hiddenLine
	t.Cleanup(func() { hiddenLine = old })
	n := 0
	hiddenLine = func(io.Reader) (string, bool, error) {
		if n >= len(lines) {
			return "", true, io.EOF
		}
		n++
		return lines[n-1], true, nil
	}
	return &n
}

// On a terminal the password is asked twice and not shown; the two must
// agree, and the rule (10 characters to 72 bytes) is checked before the
// second is asked. A password typed there is the account's own: no new one
// is asked at the first login (pre1 2.24).
func TestTypedPasswordAskedTwice(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	var out bytes.Buffer
	read := typing(t, "password-1", "password-2")
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader(""), &out); err == nil || err.Error() != "the two passwords differ" {
		t.Fatalf("two different entries: %v", err)
	}
	if _, ok, _ := d.User("bob"); ok || *read != 2 {
		t.Fatalf("bob added (%v) after %d entries", ok, *read)
	}
	read = typing(t, "too-short", "too-short")
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader(""), &out); err == nil || err.Error() != "password: at least 10 characters" || *read != 1 {
		t.Fatalf("a short entry: %v after %d entries", err, *read)
	}
	typing(t, "")
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader(""), &out); err == nil || err.Error() != "empty password" {
		t.Fatalf("an empty entry: %v", err)
	}
	out.Reset()
	typing(t, "password-1", "password-1")
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	u, ok, _ := d.User("bob")
	if !ok || u.MustChange || u.PasswordHash == "" {
		t.Fatalf("bob %+v", u)
	}
	if got := out.String(); got != "password: \nrepeat password: \nadded bob as reviewer\n" {
		t.Fatalf("output %q", got)
	}
	// passwd: the same two entries; the account's need for a new password
	// stays as it was, set or not
	out.Reset()
	typing(t, "password-2", "password-2")
	if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if u2, _, _ := d.User("bob"); u2.MustChange || u2.PasswordHash == u.PasswordHash {
		t.Fatalf("after passwd %+v", u2)
	}
	if got := out.String(); got != "password: \nrepeat password: \npassword changed for bob\n" {
		t.Fatalf("output %q", got)
	}
	if err := d.ResetPassword("bob", u.PasswordHash); err != nil {
		t.Fatal(err)
	}
	typing(t, "password-3", "password-3")
	if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if u3, _, _ := d.User("bob"); !u3.MustChange {
		t.Fatal("a typed passwd ended the need for a new password")
	}
	typing(t, "password-4", "password-5")
	if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader(""), &out); err == nil || err.Error() != "the two passwords differ" {
		t.Fatalf("passwd, two different entries: %v", err)
	}
}

// What is no terminal is read as piped: a reader, a pipe, a file and
// /dev/null (a character device, but no terminal).
func TestTermLineOnlyOnTerminals(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	for name, in := range map[string]io.Reader{"reader": strings.NewReader("x\n"), "pipe": r, "null": null} {
		if line, typed, err := termLine(in); typed || err != nil || line != "" {
			t.Errorf("%s: %q %v %v", name, line, typed, err)
		}
	}
}

// A password piped to useradd or passwd passed through a shell line, a
// script or a history file: the account must set a new one at its first
// login (pre1 2.24).
func TestPipedPasswordMustChange(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--data", dir, "--role", "director", "--admin", "bob"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	if u, _, _ := d.User("bob"); !u.MustChange {
		t.Fatal("useradd with a piped password: no new password is asked at the first login")
	}
	if !strings.Contains(out.String(), "added bob as director (admin)\nthe first login asks for a new password\n") {
		t.Fatalf("output %q", out.String())
	}
	if err := d.ChangePassword("bob", "x"); err != nil { // bob set his own
		t.Fatal(err)
	}
	out.Reset()
	if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader("password-2\n"), &out); err != nil {
		t.Fatal(err)
	}
	if u, _, _ := d.User("bob"); !u.MustChange {
		t.Fatal("passwd with a piped password: no new password is asked at the next login")
	}
	if !strings.Contains(out.String(), "password changed for bob\nthe next login asks for a new password\n") {
		t.Fatalf("output %q", out.String())
	}
}
