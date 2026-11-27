//go:build !unix

package rules

import "os/exec"

// ownGroup does nothing where there are no process groups: the timeout
// kills the script itself (exec's default), and a process the script started
// can outlive it. WaitDelay still closes its pipes.
func ownGroup(*exec.Cmd) {}
