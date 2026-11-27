//go:build !unix

package web

import "errors"

// diskSpace is not read where there is no statfs: the System page shows the
// disk as unknown.
func diskSpace(string) (free, total int64, err error) {
	return 0, 0, errors.New("the disk's space is not read on this system")
}
