package main

import (
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// On a real terminal (a pty) the line typed is read and not echoed, and the
// terminal has its echo back afterwards (pre1 2.24).
func TestTermLineHidesTheLine(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pty here:", err)
	}
	defer master.Close()
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skip("no pty here:", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skip("no pty here:", err)
	}
	tty, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no pty here:", err)
	}
	defer tty.Close()
	before, err := unix.IoctlGetTermios(int(tty.Fd()), termGet)
	if err != nil || before.Lflag&unix.ECHO == 0 {
		t.Fatalf("the new terminal does not echo: %v", err)
	}
	type res struct {
		line  string
		typed bool
		err   error
	}
	got := make(chan res, 1)
	go func() {
		line, typed, err := termLine(tty)
		got <- res{line, typed, err}
	}()
	// type once echo is off
	for i := 0; ; i++ {
		now, _ := unix.IoctlGetTermios(int(tty.Fd()), termGet)
		if now != nil && now.Lflag&unix.ECHO == 0 {
			break
		}
		if i > 500 {
			t.Fatal("echo was never turned off")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := master.WriteString("s3cret-word\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if r.line != "s3cret-word" || !r.typed || r.err != nil {
			t.Fatalf("read %q typed %v err %v", r.line, r.typed, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no line read")
	}
	after, err := unix.IoctlGetTermios(int(tty.Fd()), termGet)
	if err != nil || after.Lflag != before.Lflag {
		t.Fatalf("the terminal's settings were not put back: %v", err)
	}
	// nothing of the line came back to the screen: with echo it would be
	// readable on the master now
	if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	master.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _ := master.Read(buf); n > 0 && string(buf[:n]) != "\r\n" && string(buf[:n]) != "\n" {
		t.Fatalf("the terminal showed %q", buf[:n])
	}
}
