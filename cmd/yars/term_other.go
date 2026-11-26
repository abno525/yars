//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

import "io"

// termLine knows no terminal here: a password is read as a piped one.
func termLine(io.Reader) (line string, typed bool, err error) { return "", false, nil }
