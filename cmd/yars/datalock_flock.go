//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// lockData takes the data folder's lock for a yars serve: an exclusive
// advisory lock (flock) on .yars/yars.db.lock, held until release is called
// or the process ends, however it ends. The file is made once and never
// removed; only the lock comes and goes. A lock another server holds is
// errDataLocked's error; a lock that cannot be taken for any other reason
// (the file cannot be made, a file system without flock) stops the start
// too. A folder without .yars is no data folder: no lock is taken and
// nothing is made there.
//
// Only yars serve calls it. The account commands, yars backup and the push
// hook open the database beside the running server and take no lock.
func lockData(dir string) (release func(), err error) {
	f, err := os.OpenFile(dataLockPath(dir), os.O_RDWR|os.O_CREATE, 0o600)
	if errors.Is(err, fs.ErrNotExist) {
		return func() {}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the data folder's lock: %w", err)
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		if err == unix.EWOULDBLOCK {
			return nil, errDataLocked(dir)
		}
		return nil, fmt.Errorf("the data folder's lock (%s): %w", dataLockPath(dir), err)
	}
	// f stays reachable through release: a file that is collected is closed,
	// and the lock would go with it
	return func() { f.Close() }, nil
}
