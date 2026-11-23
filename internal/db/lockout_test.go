package db

import (
	"sync"
	"testing"
	"time"
)

// D27: 5 failures lock a username for 15 minutes; a success before that
// clears the count; the lockout ends by itself or by an admin.
func TestLoginLockout(t *testing.T) {
	d := openTest(t)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	fail := func() (bool, bool) {
		ok, _, err := d.LoginAttempt("pen2")
		if err != nil {
			t.Fatal(err)
		}
		locked := false
		if ok {
			locked, _, _ = d.LoginDone("pen2", false)
		}
		return ok, locked
	}
	for i := 1; i <= 4; i++ {
		if ok, locked := fail(); !ok || locked {
			t.Fatalf("attempt %d: ok %v locked %v", i, ok, locked)
		}
	}
	// a success clears it
	if ok, _, _ := d.LoginAttempt("pen2"); !ok {
		t.Fatal("5th attempt refused")
	}
	d.LoginDone("pen2", true)
	for i := 1; i <= 4; i++ {
		fail()
	}
	if ok, locked := fail(); !ok || !locked {
		t.Fatalf("5th failure: ok %v locked %v", ok, locked)
	}
	ok, until, _ := d.LoginAttempt("pen2")
	if ok || !until.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("locked attempt: ok %v until %v", ok, until)
	}
	if u, locked, _ := d.LockedUntil("pen2"); !locked || !u.Equal(until) {
		t.Fatalf("LockedUntil %v %v", u, locked)
	}
	if l, _ := d.Lockouts(); len(l) != 1 {
		t.Fatalf("lockouts %v", l)
	}
	// a restart does not end it: it is stored
	now = now.Add(14 * time.Minute)
	if ok, _, _ := d.LoginAttempt("pen2"); ok {
		t.Fatal("lockout ended early")
	}
	now = now.Add(2 * time.Minute)
	if ok, _, _ := d.LoginAttempt("pen2"); !ok {
		t.Fatal("lockout did not end")
	}
	d.LoginDone("pen2", false)
	// the admin clears it
	for i := 0; i < 5; i++ {
		fail()
	}
	if _, locked, _ := d.LockedUntil("pen2"); !locked {
		t.Fatal("not locked again")
	}
	d.ClearLockout("pen2")
	if ok, _, _ := d.LoginAttempt("pen2"); !ok {
		t.Fatal("cleared lockout still holds")
	}
}

// Parallel attempts never get more than 5 guesses.
func TestLoginAttemptsAtomic(t *testing.T) {
	d := openTest(t)
	var mu sync.Mutex
	allowed := 0
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _, err := d.LoginAttempt("dir1")
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != LoginTries {
		t.Fatalf("%d guesses allowed", allowed)
	}
}

// A lockout survives any number of other names sprayed: the cap drops
// only rows that are not locked, and a table full of lockouts refuses new
// names instead.
func TestLockoutSurvivesSpray(t *testing.T) {
	d := openTest(t)
	loginRows = 20
	t.Cleanup(func() { loginRows = 10000 })
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	lock := func(name string) {
		for i := 0; i < LoginTries; i++ {
			d.LoginAttempt(name)
			d.LoginDone(name, false)
		}
	}
	lock("admin")
	for i := 0; i < 3*loginRows; i++ {
		now = now.Add(time.Second)
		d.LoginAttempt("spray" + time.Duration(i).String())
	}
	if _, locked, _ := d.LockedUntil("admin"); !locked {
		t.Fatal("the spray dropped the lockout")
	}
	if ok, _, _ := d.LoginAttempt("admin"); ok {
		t.Fatal("admin got a guess")
	}
	// a table full of lockouts drops none and still lets a new name in
	for i := 0; i < loginRows; i++ {
		lock("l" + time.Duration(i).String())
	}
	if ok, _, _ := d.LoginAttempt("fresh"); !ok {
		t.Fatal("a legitimate new name refused because others are locked")
	}
	if _, locked, _ := d.LockedUntil("admin"); !locked {
		t.Fatal("lockout dropped when full")
	}
}

// Old failures stop counting after 15 minutes.
func TestLoginFailuresExpire(t *testing.T) {
	d := openTest(t)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	for i := 0; i < 4; i++ {
		d.LoginAttempt("x")
		d.LoginDone("x", false)
	}
	now = now.Add(16 * time.Minute)
	for i := 0; i < 4; i++ {
		d.LoginAttempt("x")
		if locked, _, _ := d.LoginDone("x", false); locked {
			t.Fatalf("locked after %d new failures", i+1)
		}
	}
}
