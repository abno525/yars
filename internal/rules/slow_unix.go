//go:build unix

package rules

import (
	"os/exec"
	"syscall"
)

// ownGroup gives a script its own process group and makes the timeout kill
// the whole group: what the script started goes with it.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
