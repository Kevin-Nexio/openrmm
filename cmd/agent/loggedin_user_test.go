package main

import (
	"strings"
	"testing"

	"github.com/shirou/gopsutil/v3/host"
)

// Windows: the user at the physical console wins; otherwise the first other
// active session (remote desktop); the name is DOMAIN\user, AzureAD\user for
// an Entra ID account.
func TestWindowsSessionUser(t *testing.T) {
	for name, tc := range map[string]struct {
		sessions []winSession
		console  uint32
		want     string
	}{
		"console user":  {[]winSession{{ID: 3, Domain: "ACME", User: "rdp.user"}, {ID: 1, Domain: "ACME", User: "maria"}}, 1, `ACME\maria`},
		"azure ad":      {[]winSession{{ID: 1, Domain: "AzureAD", User: "JoaoSilva"}}, 1, `AzureAD\JoaoSilva`},
		"local account": {[]winSession{{ID: 1, Domain: "PC-01", User: "suporte"}}, 1, `PC-01\suporte`},
		"rdp only":      {[]winSession{{ID: 2, Domain: "ACME", User: "admin"}}, 1, `ACME\admin`},
		"console empty": {[]winSession{{ID: 1, Domain: "", User: ""}, {ID: 4, Domain: "ACME", User: "ops"}}, 1, `ACME\ops`},
		"no domain":     {[]winSession{{ID: 1, User: "kiosk"}}, 1, "kiosk"},
		"nobody":        {nil, 1, ""},
		"trimmed":       {[]winSession{{ID: 1, Domain: " ACME ", User: " maria "}}, 1, `ACME\maria`},
	} {
		if got := windowsSessionUser(tc.sessions, tc.console); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// Linux and other Unixes: someone at the machine (no host, or an X display)
// before someone connected over SSH; utmp's bookkeeping entries are skipped.
func TestUtmpSessionUser(t *testing.T) {
	for name, tc := range map[string]struct {
		users []host.UserStat
		want  string
	}{
		"local first": {[]host.UserStat{{User: "ops", Terminal: "pts/0", Host: "10.0.0.5"}, {User: "maria", Terminal: "tty2"}}, "maria"},
		"x display":   {[]host.UserStat{{User: "ops", Host: "10.0.0.5"}, {User: "ana", Terminal: ":0", Host: ":0"}}, "ana"},
		"ssh only":    {[]host.UserStat{{User: "root", Terminal: "pts/1", Host: "192.0.2.10"}}, "root"},
		"bookkeeping": {[]host.UserStat{{User: "LOGIN", Terminal: "tty1"}, {User: "reboot"}, {User: " "}}, ""},
		"nobody":      {nil, ""},
	} {
		if got := utmpSessionUser(tc.users); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// The platform reader never fails a heartbeat: on a machine without a
// session it reports "".
func TestLoggedInUserDoesNotPanic(t *testing.T) {
	_ = loggedInUser()
}

// Linux with logind: someone at the machine (the active session on a seat)
// before someone over SSH; the login screen, the lock screen and the service
// managers are not users.
func TestLogindSessionUser(t *testing.T) {
	greeter := logindSession{ID: "c1", Name: "lightdm", Class: "greeter", State: "active", Seat: "seat0", Active: true}
	manager := logindSession{ID: "1", Name: "lightdm", Class: "manager-early", State: "active", Active: true}
	desktop := logindSession{ID: "3", Name: "teste", Class: "user", State: "active", Seat: "seat0", Active: true}
	inactiveSeat := logindSession{ID: "5", Name: "ana", Class: "user", State: "online", Seat: "seat0"}
	ssh := logindSession{ID: "4", Name: "ops", Class: "user", State: "active", Remote: true}
	tty := logindSession{ID: "6", Name: "root", Class: "user", State: "active"}
	closing := logindSession{ID: "7", Name: "old", Class: "user", State: "closing", Seat: "seat0", Active: true}
	for name, tc := range map[string]struct {
		sessions []logindSession
		want     string
	}{
		"only the login screen":        {[]logindSession{manager, greeter}, ""},
		"graphical login":              {[]logindSession{manager, greeter, desktop}, "teste"},
		"seat before ssh":              {[]logindSession{ssh, desktop}, "teste"},
		"active seat before inactive":  {[]logindSession{inactiveSeat, desktop}, "teste"},
		"inactive seat before ssh":     {[]logindSession{ssh, inactiveSeat}, "ana"},
		"local terminal before ssh":    {[]logindSession{ssh, tty}, "root"},
		"ssh only":                     {[]logindSession{greeter, ssh}, "ops"},
		"a closing session is not one": {[]logindSession{closing}, ""},
		"nothing":                      {nil, ""},
	} {
		if got := logindSessionUser(tc.sessions); got != tc.want {
			t.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}
}

// The ids come from the first column of list-sessions; show-session prints
// one block per session. The sample is the Ubuntu 26.04 lab device at its
// login screen, plus an SSH session.
func TestLoginctlParsing(t *testing.T) {
	list := " 1 105 lightdm -     1402 manager-early - no -\nc1 105 lightdm seat0 1373 greeter       - no -\n 9 1000 ops   -     2210 user          pts/0 no -\n--bad 1 x\n\n"
	if got := strings.Join(loginctlSessionIDs(list), ","); got != "1,c1,9" {
		t.Fatalf("ids = %q", got)
	}
	show := "Id=1\nName=lightdm\nClass=manager-early\nState=active\nSeat=\nRemote=no\nActive=yes\n\n" +
		"Id=c1\nName=lightdm\nSeat=seat0\nClass=greeter\nState=active\nRemote=no\nActive=yes\n\n" +
		"Id=9\nName=ops\nClass=user\nState=active\nSeat=\nRemote=yes\nActive=yes\n"
	sessions := parseLoginctlShow(show)
	if len(sessions) != 3 || sessions[1].Seat != "seat0" || sessions[1].Class != "greeter" || !sessions[2].Remote || sessions[2].Name != "ops" {
		t.Fatalf("sessions = %#v", sessions)
	}
	if got := logindSessionUser(sessions); got != "ops" {
		t.Fatalf("user = %q, want the SSH user", got)
	}
}
