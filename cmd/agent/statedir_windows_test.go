//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/protocol"
	"golang.org/x/sys/windows"
)

// An endpoint installed by an older installer has BUILTIN\Users read access on
// the agent directory, inherited by state.json. Restricting the directory must
// take that inherited grant off the file that already exists, not only off
// files created afterwards.
func TestRestrictAgentDirRemovesInheritedUserAccess(t *testing.T) {
	dir := t.TempDir()
	if err := setSDDL(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;0x1200a9;;;BU)"); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state.json")
	if err := os.WriteFile(state, []byte(`{"agent_token":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !grants(t, state, windows.WinBuiltinUsersSid) {
		t.Fatal("setup: state.json should start out readable by BUILTIN\\Users")
	}
	t.Cleanup(func() { _ = setSDDL(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)") })

	if err := restrictAgentDir(dir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, state} {
		if grants(t, path, windows.WinBuiltinUsersSid) {
			t.Fatalf("%s is still readable by BUILTIN\\Users", path)
		}
		if !grants(t, path, windows.WinLocalSystemSid) {
			t.Fatalf("%s lost SYSTEM access", path)
		}
	}
}

func TestEncryptedSessionParametersIgnoreOldStagingACL(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, "remote-sessions")
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setSDDL(old, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;0x1200a9;;;BU)"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = setSDDL(root, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)") })
	if err := restrictAgentDir(root); err != nil {
		t.Fatal(err)
	}
	_, viewerKey, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{statePath: filepath.Join(root, "state.json"), st: state{AgentID: "test-agent"}}
	path, err := a.writeE2ESessionFile(protocol.RemoteStartMsg{
		SessionID: "test-session", Kind: protocol.RemoteKindDesktop, ViewerKey: viewerKey,
	}, "wss://relay.example.invalid/ws/remote", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) == old || grants(t, path, windows.WinBuiltinUsersSid) {
		t.Fatal("session parameters reused a staging directory with insecure access")
	}
	if !grants(t, path, windows.WinLocalSystemSid) {
		t.Fatal("session parameters are inaccessible to the system service")
	}
}

func setSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// grants reports whether path's DACL holds an allow entry for the well-known SID.
func grants(t *testing.T, path string, who windows.WELL_KNOWN_SID_TYPE) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	want, err := windows.CreateWellKnownSid(who)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(want) {
			return true
		}
	}
	return false
}
