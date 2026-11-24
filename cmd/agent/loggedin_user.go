package main

import (
	"strings"

	"github.com/shirou/gopsutil/v3/host"
)

// The interactive user (Devices ▸ Logged-in user). Each heartbeat carries the
// user of the device's active interactive session, so operators can find a
// user's machine, triage support and check device assignments. "" means no
// one is logged in. The platform files read the session; these functions
// choose among sessions and format the name, and are the same everywhere.

// winSession is one session WTSEnumerateSessions reported as active.
type winSession struct {
	ID           uint32
	Domain, User string
}

// windowsSessionUser picks the user at the physical console when someone is
// logged in there, else the first other active session (RDP), and names it
// DOMAIN\user — AzureAD\user for an Entra ID account, the machine name for a
// local one.
func windowsSessionUser(sessions []winSession, consoleID uint32) string {
	var first string
	for _, s := range sessions {
		name := qualifiedUser(s.Domain, s.User)
		if name == "" {
			continue
		}
		if s.ID == consoleID {
			return name
		}
		if first == "" {
			first = name
		}
	}
	return first
}

func qualifiedUser(domain, user string) string {
	user, domain = strings.TrimSpace(user), strings.TrimSpace(domain)
	if user == "" {
		return ""
	}
	if domain == "" {
		return user
	}
	return domain + `\` + user
}

// utmpSessionUser picks, from the logged-in users utmp lists, someone at the
// machine itself (a local terminal or graphical seat: no host, or an X display
// such as ":0") before someone connected over the network (SSH).
func utmpSessionUser(users []host.UserStat) string {
	var remote string
	for _, u := range users {
		name := strings.TrimSpace(u.User)
		if name == "" || name == "LOGIN" || name == "reboot" {
			continue
		}
		if u.Host == "" || strings.HasPrefix(u.Host, ":") {
			return name
		}
		if remote == "" {
			remote = name
		}
	}
	return remote
}

// logindSession is one session systemd-logind reports (loginctl show-session).
type logindSession struct {
	ID, Name, Class, State, Seat string
	Remote, Active               bool
}

// loginctlSessionIDs reads the session ids from `loginctl list-sessions
// --no-legend`: the first column of each line. An id loginctl would not print
// (empty, or starting with "-") is dropped, so none can become an option.
func loginctlSessionIDs(out string) []string {
	var ids []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !validLogindSessionID(fields[0]) {
			continue
		}
		ids = append(ids, fields[0])
	}
	return ids
}

func validLogindSessionID(id string) bool {
	if id == "" || len(id) > 64 || id[0] == '-' {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// parseLoginctlShow reads `loginctl show-session ID... -p Id -p Name ...`:
// one KEY=VALUE block per session, blocks separated by a blank line.
func parseLoginctlShow(out string) []logindSession {
	var sessions []logindSession
	var cur logindSession
	seen := false
	flush := func() {
		if seen {
			sessions = append(sessions, cur)
		}
		cur, seen = logindSession{}, false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		seen = true
		switch key {
		case "Id":
			cur.ID = value
		case "Name":
			cur.Name = value
		case "Class":
			cur.Class = value
		case "State":
			cur.State = value
		case "Seat":
			cur.Seat = value
		case "Remote":
			cur.Remote = value == "yes"
		case "Active":
			cur.Active = value == "yes"
		}
	}
	flush()
	return sessions
}

// logindSessionUser picks, as utmpSessionUser does, someone at the machine
// before someone connected over the network: first the active session on a
// seat (the console or the graphical login), then any other local session,
// then a remote one (SSH). Only user sessions count: the login screen
// (greeter), the lock screen and the per-user service managers do not.
func logindSessionUser(sessions []logindSession) string {
	var seated, local, remote string
	for _, s := range sessions {
		name := strings.TrimSpace(s.Name)
		if name == "" || !strings.HasPrefix(s.Class, "user") || s.State == "closing" {
			continue
		}
		switch {
		case s.Remote:
			if remote == "" {
				remote = name
			}
		case s.Seat != "" && s.Active:
			return name
		case s.Seat != "":
			if seated == "" {
				seated = name
			}
		default:
			if local == "" {
				local = name
			}
		}
	}
	for _, name := range []string{seated, local, remote} {
		if name != "" {
			return name
		}
	}
	return ""
}
