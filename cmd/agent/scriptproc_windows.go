//go:build windows

package main

import (
	"os/exec"
	"strconv"
)

// killTreeOnCancel kills the script's whole process tree (taskkill /T) when its
// context ends, so a stuck downloader or installer it started dies too. The
// default cancel kills only the direct child.
func killTreeOnCancel(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
		}
		return nil
	}
}
