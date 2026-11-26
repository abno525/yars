//go:build unix

package main

import "syscall"

// privateUmask makes every file and folder this process and its git child
// processes create the service user's alone (umask 077): the work trees,
// .git, the database's companions and temporary files. It returns the way
// back (tests).
func privateUmask() (restore func()) {
	old := syscall.Umask(0o077)
	return func() { syscall.Umask(old) }
}
