//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// termLine reads one line from in without showing it, when in is a
// terminal; typed is false when it is not (a pipe, a file, /dev/null), and
// nothing is read then. The terminal gets its echo back when the line is
// read, and also when the command is interrupted at the prompt.
func termLine(in io.Reader) (line string, typed bool, err error) {
	f, ok := in.(*os.File)
	if !ok {
		return "", false, nil
	}
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, termGet)
	if err != nil {
		return "", false, nil // no terminal
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, termSet, &quiet); err != nil {
		return "", true, err
	}
	restore := func() { unix.IoctlSetTermios(fd, termSet, old) }
	sig := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() {
		signal.Stop(sig)
		close(done)
		restore()
	}()
	// byte by byte: nothing after the line is taken from the terminal
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := f.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			b = append(b, one[0])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", true, err
		}
	}
	return strings.TrimRight(string(b), "\r"), true, nil
}
