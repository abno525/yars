package main

import "golang.org/x/sys/unix"

// the requests that read and set a terminal's settings
const termGet, termSet = unix.TCGETS, unix.TCSETS
