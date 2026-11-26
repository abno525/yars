package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// yars token add on a data folder of the simple workflow (its database's
// workflow setting) refuses the reviewers scope, which Settings › Tokens
// does not offer either, and stores nothing; the other scopes are as before.
// The standard workflow keeps it.
func TestTokenAddSimpleNoReviewers(t *testing.T) {
	for _, simple := range []bool{true, false} {
		dir := t.TempDir()
		if err := cmdInit([]string{dir}); err != nil {
			t.Fatal(err)
		}
		d := openDB(t, dir)
		if simple {
			if err := d.SetSetting("workflow", config.WorkflowSimple); err != nil {
				t.Fatal(err)
			}
		}
		d.AddUser(config.User{Username: "ben", Role: "director"})
		var out bytes.Buffer
		for _, sc := range []string{"reviewers", "status,reviewers"} {
			code, err := cmdToken([]string{"add", "--data", dir, "--scopes", sc, "ben"}, &out)
			if simple && (code != 1 || err == nil || err.Error() != "token scope reviewers: the simple workflow has no reviewers") {
				t.Errorf("simple %s: code %d err %v", sc, code, err)
			}
			if !simple && code != 0 {
				t.Errorf("standard %s: code %d err %v", sc, code, err)
			}
		}
		if code, err := cmdToken([]string{"add", "--data", dir, "--scopes", "status,checks", "ben"}, &out); code != 0 {
			t.Fatal(code, err)
		}
		ts, _ := d.UserTokens("ben")
		var got [][]string
		for _, tk := range ts {
			got = append(got, tk.Scopes)
		}
		want := [][]string{{"status", "checks"}}
		if !simple {
			want = [][]string{{"reviewers"}, {"status", "reviewers"}, {"status", "checks"}}
		}
		if !slices.EqualFunc(got, want, slices.Equal) {
			t.Errorf("simple %v: tokens %v", simple, got)
		}
		if l, _ := d.AuditLog(10); simple && len(l) != 1 {
			t.Errorf("audit %+v", l)
		}
	}
	// the flag's help names the workflow without the scope
	var help bytes.Buffer
	cmdToken([]string{"add", "-h"}, &help)
	if !strings.Contains(help.String(), "reviewers,checks,export; the simple workflow has no reviewers)") {
		t.Fatalf("help:\n%s", help.String())
	}
}
