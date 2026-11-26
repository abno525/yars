package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
)

// yars token add gives a token 90 days unless told otherwise: --days N,
// --expires <date> (to the end of that day, UTC) or --expires never. A date
// that is past or does not read, and both flags together, make no token.
// The printed line names the expiry (pre1 2.25).
func TestTokenAddExpiry(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	expiry := func(args ...string) (string, string) {
		t.Helper()
		var out bytes.Buffer
		before, _ := d.UserTokens("bob")
		if code, err := cmdToken(append(append([]string{"add", "--data", dir}, args...), "bob"), &out); code != 0 || err != nil {
			t.Fatalf("%v: code %d err %v", args, code, err)
		}
		after, _ := d.UserTokens("bob")
		if len(after) != len(before)+1 {
			t.Fatalf("%v: %d tokens, were %d", args, len(after), len(before))
		}
		newest := after[0]
		for _, tk := range after {
			if tk.ID > newest.ID {
				newest = tk
			}
		}
		return newest.Expires, out.String()
	}
	days := func(exp string) float64 {
		t.Helper()
		at, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			t.Fatalf("expiry %q: %v", exp, err)
		}
		return time.Until(at).Hours() / 24
	}
	// no flag: 90 days
	exp, out := expiry()
	if n := days(exp); n < 89.9 || n > 90.1 {
		t.Fatalf("the default expiry is %.1f days ahead (%q)", n, exp)
	}
	if !strings.Contains(out, "expires "+exp[:10]) {
		t.Fatalf("the output does not name the expiry: %q", out)
	}
	if exp, _ := expiry("--days", "7"); days(exp) < 6.9 || days(exp) > 7.1 {
		t.Fatalf("--days 7: %q", exp)
	}
	// never is asked for in words
	for _, args := range [][]string{{"--expires", "never"}, {"--days", "0"}} {
		if exp, out := expiry(args...); exp != "" || !strings.Contains(out, "never expires") {
			t.Fatalf("%v: expiry %q, output %q", args, exp, out)
		}
	}
	day := time.Now().UTC().AddDate(0, 0, 10).Format("2006-01-02")
	if exp, out := expiry("--expires", day); exp != day+"T23:59:59Z" || !strings.Contains(out, "expires "+day) {
		t.Fatalf("--expires %s: %q, output %q", day, exp, out)
	}
	today := time.Now().UTC().Format("2006-01-02")
	if exp, _ := expiry("--expires", today); exp != today+"T23:59:59Z" {
		t.Fatalf("--expires today: %q", exp)
	}
	n, _ := d.UserTokens("bob")
	for want, args := range map[string][]string{
		"is in the past":            {"--expires", "2020-01-01"},
		"a date (YYYY-MM-DD)":       {"--expires", "tomorrow"},
		"--days or --expires":       {"--days", "7", "--expires", day},
		"--days: 0 or more":         {"--days", "-3"},
		"a date (YYYY-MM-DD) or ne": {"--expires", ""},
	} {
		var out bytes.Buffer
		code, err := cmdToken(append(append([]string{"add", "--data", dir}, args...), "bob"), &out)
		if code != 2 || err == nil || !strings.Contains(err.Error(), want) || strings.Contains(out.String(), "yars_") {
			t.Errorf("%v: code %d err %v, output %q", args, code, err, out.String())
		}
	}
	if after, _ := d.UserTokens("bob"); len(after) != len(n) {
		t.Fatalf("a refused command made a token: %d, were %d", len(after), len(n))
	}
}
