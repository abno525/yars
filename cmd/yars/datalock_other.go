//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

// lockData takes no lock where there is no flock: the status socket is the
// only guard against a second yars serve there.
func lockData(dir string) (release func(), err error) { return func() {}, nil }
