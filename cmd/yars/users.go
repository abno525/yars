package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/abno525/yars/internal/db"
)

// lastAdmin words the database's refusal to leave no admin who can sign in
// (db.ErrLastAdmin) for the command line: who, what stays (as Admin › Users
// says "Your own admin flag stays"), and the way on. There is no flag to
// pass the rule: another account gets the admin flag first. Any other error
// is returned as it is.
func lastAdmin(err error, name, stays string) error {
	if errors.Is(err, db.ErrLastAdmin) {
		return fmt.Errorf("%s is the last admin: %s (first: yars admin <user> on)", name, stays)
	}
	return err
}

// cmdUsers lists the accounts, one on a line, the fields separated by tabs:
// the username, the role (not in the simple workflow, which has none),
// admin or -, enabled or disabled, and when it was made.
//
//	yars users --data <dir>
//
// It only reads: no audit row, nothing committed to the main repository and
// no database made where there is none. Neither the email (free text of
// yars useradd --email) nor the password hash is printed.
func cmdUsers(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("users", flag.ContinueOnError)
	data := dataFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: yars users --data <dir>")
	}
	r, err := openData(fs, *data)
	if err != nil {
		return err
	}
	d, err := existingDB(r.Dir)
	if err != nil {
		return err
	}
	if d == nil {
		return fmt.Errorf("%s has no database", r.Dir)
	}
	defer d.Close()
	simple, err := simpleData(d)
	if err != nil {
		return err
	}
	users, err := d.Users()
	if err != nil {
		return err
	}
	for _, u := range users {
		admin, state := "-", "enabled"
		if u.IsAdmin {
			admin = "admin"
		}
		if u.Disabled {
			state = "disabled"
		}
		line := word(u.Username) + "\t"
		if !simple {
			line += word(u.Role) + "\t"
		}
		fmt.Fprintln(out, line+admin+"\t"+state+"\tcreated "+word(u.Created))
	}
	return nil
}

// cmdDisabled disables an account (on) or enables it again:
//
//	yars disable --data <dir> <user>
//	yars enable --data <dir> <user>
//
// It is the write Admin › Users makes (db.SetDisabled), so it works beside
// a running server: disabling ends the account's sessions at once, its
// tokens are refused while it is disabled, and its open pages stop updating
// at their next heartbeat. The last admin who can sign in is not disabled.
func cmdDisabled(on bool, args []string, out io.Writer) error {
	cmd, action, done := "enable", "user.enable", "enabled"
	if on {
		cmd, action, done = "disable", "user.disable", "disabled"
	}
	fs, d, err := accountCmd(cmd, args, 1, nil)
	if err != nil {
		return err
	}
	defer d.Close()
	name := fs.Arg(0)
	if err := d.SetDisabled(name, on); err != nil {
		return lastAdmin(err, name, "the account stays enabled")
	}
	d.Audit("cli", action, name, "")
	fmt.Fprintln(out, done, word(name))
	return nil
}
