package main

import (
	"bytes"
	"strings"
	"testing"
)

// yars userdel keeps the name: yars useradd of it fails with the reason,
// also in another case of its letters.
func TestUseraddAfterUserdel(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--data", dir, "bob"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdUserdel([]string{"--data", dir, "bob"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bob", "Bob"} {
		err := cmdUseradd([]string{"--data", dir, name}, strings.NewReader("password-1\n"), &out)
		if err == nil || !strings.Contains(err.Error(), "user bob was deleted: the name stays taken") {
			t.Fatalf("useradd %s after userdel bob: %v", name, err)
		}
	}
	if us, _ := openDB(t, dir).Users(); len(us) != 0 {
		t.Fatalf("accounts %+v", us)
	}
	if err := cmdUseradd([]string{"--data", dir, "bobby"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
}
