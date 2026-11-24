//go:build !windows && !darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/shirou/gopsutil/v3/host"
)

// loggedInUser reports a user logged in at the machine, preferring a local
// console or graphical seat over an SSH session. systemd-logind is asked
// first: recent distributions (Ubuntu 26.04, with systemd 259) no longer keep
// utmp, so a utmp read finds no one. Without logind, utmp is read as before.
func loggedInUser() string {
	if user, ok := logindUser(); ok {
		return user
	}
	users, err := host.Users()
	if err != nil {
		return ""
	}
	return utmpSessionUser(users)
}

// logindUser asks loginctl for the sessions. ok is false when logind cannot
// answer (no loginctl, or no logind running, as in a container), and the
// caller falls back to utmp. When logind answers, its word is final, even if
// no one is logged in.
func logindUser() (user string, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	list, err := loginctl(ctx, "list-sessions", "--no-legend", "--no-pager")
	if err != nil {
		return "", false
	}
	ids := loginctlSessionIDs(list)
	if len(ids) == 0 {
		return "", true
	}
	args := append([]string{"show-session", "--no-pager",
		"-p", "Id", "-p", "Name", "-p", "Class", "-p", "State", "-p", "Seat", "-p", "Remote", "-p", "Active"}, ids...)
	show, err := loginctl(ctx, args...)
	if err != nil {
		// A session can end between the two calls; show-session then fails for
		// the whole list. The next heartbeat asks again.
		return "", false
	}
	return logindSessionUser(parseLoginctlShow(show)), true
}

// loginctlPaths are where systemd installs loginctl. The agent runs as root,
// so it runs only that binary, never one found first on some other PATH entry.
var loginctlPaths = []string{"/usr/bin/loginctl", "/bin/loginctl"}

func loginctl(ctx context.Context, args ...string) (string, error) {
	path := ""
	for _, candidate := range loginctlPaths {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			path = candidate
			break
		}
	}
	if path == "" {
		return "", os.ErrNotExist
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"LC_ALL=C", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	out, err := cmd.Output()
	return string(out), err
}
