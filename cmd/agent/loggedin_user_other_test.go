//go:build !windows && !darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// loggedInUser asks logind first and takes its answer, even "no one"; without
// loginctl it falls back to utmp.
func TestLoggedInUserAsksLogindFirst(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "loginctl")
	script := `#!/bin/sh
case "$1" in
list-sessions) printf ' 1 105 lightdm - 1402 manager-early - no -\nc1 105 lightdm seat0 1373 greeter - no -\n 3 1000 teste seat0 2001 user tty7 no -\n' ;;
show-session) printf 'Id=1\nName=lightdm\nClass=manager-early\nState=active\nSeat=\nRemote=no\nActive=yes\n\nId=c1\nName=lightdm\nClass=greeter\nState=active\nSeat=seat0\nRemote=no\nActive=no\n\nId=3\nName=teste\nClass=user\nState=active\nSeat=seat0\nRemote=no\nActive=yes\n' ;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	previous := loginctlPaths
	t.Cleanup(func() { loginctlPaths = previous })

	loginctlPaths = []string{filepath.Join(dir, "missing"), fake}
	if user, ok := logindUser(); !ok || user != "teste" {
		t.Fatalf("logind user = %q ok=%v, want teste", user, ok)
	}
	if got := loggedInUser(); got != "teste" {
		t.Fatalf("loggedInUser = %q, want the logind user", got)
	}

	// logind answers, and no user is logged in: that is the answer.
	greeterOnly := "#!/bin/sh\ncase \"$1\" in\nlist-sessions) printf 'c1 105 lightdm seat0 1373 greeter - no -\\n' ;;\nshow-session) printf 'Id=c1\\nName=lightdm\\nClass=greeter\\nState=active\\nSeat=seat0\\nRemote=no\\nActive=yes\\n' ;;\nesac\n"
	if err := os.WriteFile(fake, []byte(greeterOnly), 0o755); err != nil {
		t.Fatal(err)
	}
	if user, ok := logindUser(); !ok || user != "" {
		t.Fatalf("login screen only: user = %q ok=%v, want no one", user, ok)
	}

	// No loginctl: utmp decides, as before.
	loginctlPaths = []string{filepath.Join(dir, "missing")}
	if _, ok := logindUser(); ok {
		t.Fatal("logindUser answered without loginctl")
	}
	_ = loggedInUser() // the utmp path must still work
}
