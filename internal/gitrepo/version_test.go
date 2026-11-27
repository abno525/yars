package gitrepo

import (
	"errors"
	"strings"
	"testing"
)

// The version check reads the first two numbers of what git printed and
// compares them as numbers. It is given the text: the git of the machine
// the test runs on plays no part.
func TestCheckVersionText(t *testing.T) {
	for _, c := range []struct {
		text, version string
		old, unread   bool
	}{
		{text: "git version 2.43.0\n", version: "2.43"},
		{text: "2.30.0", version: "2.30"},
		{text: "git version 2.30.0\n", version: "2.30"},
		{text: "git version 2.29.2\n", version: "2.29", old: true},
		{text: "git version 2.9.5\n", version: "2.9", old: true}, // as text, 2.9 sorts after 2.30
		{text: "git version 2.25.1\n", version: "2.25", old: true},
		{text: "git version 1.8.3.1\n", version: "1.8", old: true},
		{text: "git version 1.99.0\n", version: "1.99", old: true},
		{text: "git version 3.0.0\n", version: "3.0"},
		{text: "git version 2.100.1\n", version: "2.100"},
		{text: "git version 2.39.3 (Apple Git-146)\n", version: "2.39"},
		{text: "git version 2.30.0.windows.1\r\n", version: "2.30"},
		{text: "git version 2.45.GIT\n", version: "2.45"},
		{text: "git version 2.44.0-rc1\n", version: "2.44"},
		{text: "git version 2.43\n", version: "2.43"},
		{text: "", unread: true},
		{text: "garbage", unread: true},
		{text: "git version x.y\n", unread: true},
		{text: "git version 2\n", unread: true},
		{text: "git version 2.\n", unread: true},
		{text: "git version .30\n", unread: true},
		{text: "git version -2.30\n", unread: true},
		{text: "git version 2.x\n", unread: true},
		{text: "git version 99999999999999999999.1\n", unread: true},
		{text: "version 2.43.0", unread: true},
	} {
		v, err := CheckVersionText(c.text)
		switch {
		case c.unread:
			if !errors.Is(err, ErrVersionUnread) || v != "" {
				t.Errorf("%q: %q %v, want ErrVersionUnread", c.text, v, err)
			}
			// what git printed is another program's text: not in the error
			if err != nil && c.text != "" && strings.Contains(err.Error(), strings.TrimSpace(c.text)) {
				t.Errorf("%q: the error holds the text: %v", c.text, err)
			}
		case c.old:
			want := "git " + MinVersion() + " or later is needed; this is git " + c.version
			if err == nil || err.Error() != want || errors.Is(err, ErrVersionUnread) {
				t.Errorf("%q: %v, want %q", c.text, err, want)
			}
		default:
			if err != nil || v != c.version {
				t.Errorf("%q: %q %v, want %q", c.text, v, err, c.version)
			}
		}
	}
	if MinVersion() != "2.30" {
		t.Errorf("MinVersion %q", MinVersion())
	}
}

// The machine's own git is read and passes: every other test of this
// package needs it anyway.
func TestVersionTextOfThisGit(t *testing.T) {
	text, err := VersionText()
	if err != nil || !strings.HasPrefix(text, "git version ") {
		t.Fatalf("%q %v", text, err)
	}
	if _, _, ok := ParseVersion(text); !ok {
		t.Fatalf("the version of this machine's git does not read: %q", text)
	}
}
