//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// killTreeOnCancel runs the script in its own process group and, when its
// context ends (timeout or operator cancel), kills the whole group. Killing
// only the shell would leave anything it started in the background running,
// holding the output open, so the run would last until that child exits.
func killTreeOnCancel(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
