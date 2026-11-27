package main

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
)

// accounts is a new data folder with the given accounts (the password is
// piped, as a script would).
func accounts(t *testing.T, simple bool, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	args := []string{"init", dir}
	if simple {
		args = []string{"init", "--simple", dir}
	}
	if code, _, e := yars(t, "", args...); code != 0 {
		t.Fatalf("init: %d %s", code, e)
	}
	for _, l := range lines {
		if code, _, e := yars(t, "password-1\n", append([]string{"useradd", "--data", dir}, strings.Fields(l)...)...); code != 0 {
			t.Fatalf("useradd %s: %d %s", l, code, e)
		}
	}
	return dir
}

// The last admin who can sign in keeps the flag, stays enabled and is not
// deleted from the command line either: each command says why, exits 1,
// changes nothing and writes no audit row. With a second admin each works.
func TestCLILastAdminStays(t *testing.T) {
	for _, c := range []struct {
		name, want string
		args       func(dir string) []string
		done       func(config.User, bool) bool
	}{
		{"admin off", "yars: ann is the last admin: the admin flag stays (first: yars admin <user> on)\n",
			func(dir string) []string { return []string{"admin", "--data", dir, "ann", "off"} },
			func(u config.User, ok bool) bool { return ok && !u.IsAdmin }},
		{"disable", "yars: ann is the last admin: the account stays enabled (first: yars admin <user> on)\n",
			func(dir string) []string { return []string{"disable", "--data", dir, "ann"} },
			func(u config.User, ok bool) bool { return ok && u.Disabled }},
		{"userdel", "yars: ann is the last admin: the account stays (first: yars admin <user> on)\n",
			func(dir string) []string { return []string{"userdel", "--data", dir, "ann"} },
			func(u config.User, ok bool) bool { return !ok }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := accounts(t, false, "--role director --admin ann", "--role director --admin bea", "--role pentester pen")
			d := openDB(t, dir)
			// bea is disabled: she does not count
			if code, _, e := yars(t, "", "disable", "--data", dir, "bea"); code != 0 {
				t.Fatalf("disable bea: %d %s", code, e)
			}
			before, _ := d.AuditLog(50)
			code, out, errOut := yars(t, "", c.args(dir)...)
			if code != 1 || out != "" || errOut != c.want {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
			}
			if u, ok, _ := d.User("ann"); !ok || !u.IsAdmin || u.Disabled {
				t.Fatalf("ann after the refusal: %+v %v", u, ok)
			}
			if after, _ := d.AuditLog(50); len(after) != len(before) {
				t.Fatalf("the refusal is in the audit log: %+v", after[0])
			}
			// the way out: another enabled admin first
			if code, _, e := yars(t, "", "enable", "--data", dir, "bea"); code != 0 {
				t.Fatalf("enable bea: %d %s", code, e)
			}
			if code, _, e := yars(t, "", c.args(dir)...); code != 0 {
				t.Fatalf("with a second admin: %d %s", code, e)
			}
			if u, ok, _ := d.User("ann"); !c.done(u, ok) {
				t.Fatalf("ann after the command: %+v %v", u, ok)
			}
		})
	}
}

// yars disable ends the account's sessions and yars enable brings the
// account back; both are in the audit log by cli. A pentester is disabled
// and deleted while one admin exists. An unknown name and a deleted one are
// not enabled.
func TestCLIDisableEnable(t *testing.T) {
	dir := accounts(t, false, "--role director --admin ann", "--role pentester bob")
	d := openDB(t, dir)
	if err := d.CreateSession("s-bob", "bob"); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := yars(t, "", "disable", "--data", dir, "bob")
	if code != 0 || out != "disabled bob\n" || errOut != "" {
		t.Fatalf("disable: %d %q %q", code, out, errOut)
	}
	if u, _, _ := d.User("bob"); !u.Disabled {
		t.Fatal("bob is not disabled")
	}
	if _, ok, _ := d.SessionUser("s-bob"); ok {
		t.Fatal("bob's session is still there")
	}
	code, out, errOut = yars(t, "", "enable", "--data", dir, "bob")
	if code != 0 || out != "enabled bob\n" || errOut != "" {
		t.Fatalf("enable: %d %q %q", code, out, errOut)
	}
	if u, _, _ := d.User("bob"); u.Disabled {
		t.Fatal("bob is still disabled")
	}
	l, _ := d.AuditLog(2)
	if len(l) != 2 || l[0].Action != "user.enable" || l[1].Action != "user.disable" || l[0].Actor != "cli" || l[1].Actor != "cli" || l[0].Target != "bob" {
		t.Fatalf("audit %+v", l)
	}
	for _, cmd := range []string{"disable", "enable"} {
		if code, _, e := yars(t, "", cmd, "--data", dir, "ghost"); code != 1 || e != "yars: no user ghost\n" {
			t.Fatalf("%s ghost: %d %q", cmd, code, e)
		}
		if code, _, e := yars(t, "", cmd, "--data", dir); code != 1 || !strings.Contains(e, "wrong arguments") {
			t.Fatalf("%s without a name: %d %q", cmd, code, e)
		}
	}
	if code, _, e := yars(t, "", "userdel", "--data", dir, "bob"); code != 0 {
		t.Fatalf("userdel bob: %d %s", code, e)
	}
	if code, _, e := yars(t, "", "enable", "--data", dir, "bob"); code != 1 || e != "yars: no user bob\n" {
		t.Fatalf("enable of a deleted account: %d %q", code, e)
	}
	if code, _, e := yars(t, "password-1\n", "useradd", "--data", dir, "bob"); code != 1 || !strings.Contains(e, "was deleted: the name stays taken") {
		t.Fatalf("the deleted name is free again: %d %q", code, e)
	}
}

// yars users lists every account on a line: name, role, admin, disabled,
// created. No password hash and no email. The simple workflow has no role
// column. It writes nothing: no audit row, no commit.
func TestCLIUsers(t *testing.T) {
	dir := accounts(t, false, "--role director --admin --email ann@x.test ann", "--role pentester bob", "--role reviewer cy")
	d := openDB(t, dir)
	if code, _, e := yars(t, "", "disable", "--data", dir, "bob"); code != 0 {
		t.Fatalf("disable: %d %s", code, e)
	}
	us, _ := d.Users()
	before, _ := d.AuditLog(50)
	code, out, errOut := yars(t, "", "users", "--data", dir)
	if code != 0 || errOut != "" {
		t.Fatalf("users: %d %q", code, errOut)
	}
	want := "ann\tdirector\tadmin\tenabled\tcreated " + us[0].Created + "\n" +
		"bob\tpentester\t-\tdisabled\tcreated " + us[1].Created + "\n" +
		"cy\treviewer\t-\tenabled\tcreated " + us[2].Created + "\n"
	if out != want {
		t.Fatalf("users:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(out, us[0].PasswordHash) || strings.Contains(out, "ann@x.test") {
		t.Fatalf("the list holds a hash or an email:\n%s", out)
	}
	if after, _ := d.AuditLog(50); len(after) != len(before) {
		t.Fatal("the list is in the audit log")
	}
	if code, _, e := yars(t, "", "users", "--data", dir, "extra"); code != 1 || e != "yars: usage: yars users --data <dir>\n" {
		t.Fatalf("users with an argument: %d %q", code, e)
	}
	// the simple workflow: no roles to name
	simple := accounts(t, true, "--admin anna", "ben")
	sd := openDB(t, simple)
	su, _ := sd.Users()
	_, out, _ = yars(t, "", "users", "--data", simple)
	if want := "anna\tadmin\tenabled\tcreated " + su[0].Created + "\nben\t-\tenabled\tcreated " + su[1].Created + "\n"; out != want {
		t.Fatalf("simple:\n%s\nwant:\n%s", out, want)
	}
}

// yars users on a folder without a database says so and makes none, and
// commits nothing to the repository.
func TestCLIUsersWithoutDatabase(t *testing.T) {
	dir := accounts(t, false)
	for _, f := range []string{"", "-wal", "-shm"} {
		os.Remove(db.Path(dir) + f)
	}
	head := func() string {
		out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	was := head()
	code, out, errOut := yars(t, "", "users", "--data", dir)
	if code != 1 || out != "" || errOut != "yars: "+dir+" has no database\n" {
		t.Fatalf("users: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(db.Path(dir)); err == nil {
		t.Fatal("the list made a database")
	}
	if head() != was {
		t.Fatal("the list made a commit")
	}
}

// Beside a running server: yars disable is a write to the database the
// server reads, so the account's next request is sent to the login.
func TestCLIDisableBesideAServer(t *testing.T) {
	const pw = "password-12345"
	lg, _ := logs.NewRecorder()
	s := serveLogged(t, lg, "yars", pw)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(s.url+"/login", url.Values{"username": {"alice"}, "password": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) == 0 {
		t.Fatalf("login: %d, cookies %v", resp.StatusCode, resp.Cookies())
	}
	home := func() *http.Response {
		req, _ := http.NewRequest("GET", s.url+"/", nil)
		for _, c := range resp.Cookies() {
			req.AddCookie(c)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r
	}
	if r := home(); r.StatusCode != http.StatusOK {
		t.Fatalf("signed in: %d", r.StatusCode)
	}
	if code, _, e := yars(t, "", "disable", "--data", s.dir, "alice"); code != 0 {
		t.Fatalf("disable: %d %s", code, e)
	}
	if r := home(); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/login" {
		t.Fatalf("after yars disable: %d to %q", r.StatusCode, r.Header.Get("Location"))
	}
	// the server's last admin is not disabled beside it either
	if code, _, e := yars(t, "", "disable", "--data", s.dir, "dora"); code != 1 || !strings.Contains(e, "dora is the last admin") {
		t.Fatalf("disable the last admin: %d %q", code, e)
	}
}
