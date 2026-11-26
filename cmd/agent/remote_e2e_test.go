package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/protocol"
)

func TestEnsureDeviceIdentityPersistsReloadsAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	a := &agent{statePath: statePath}
	priv1, pub1, err := a.ensureDeviceIdentity()
	if err != nil {
		t.Fatalf("ensureDeviceIdentity first run: %v", err)
	}
	if err := e2e.ValidatePublicKey(pub1); err != nil {
		t.Fatalf("generated public key invalid: %v", err)
	}

	// Verify durable file persistence and 0600 permissions on POSIX.
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("state file not persisted: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(statePath)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("state file mode = %o, want 0600", info.Mode().Perm())
		}
	}
	var saved state
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.DevicePrivateKey != priv1 || saved.DevicePublicKey != pub1 {
		t.Fatal("persisted state did not match returned identity keypair")
	}

	// Second call is idempotent and returns the same keypair.
	priv2, pub2, err := a.ensureDeviceIdentity()
	if err != nil || priv2 != priv1 || pub2 != pub1 {
		t.Fatalf("second ensureDeviceIdentity = (%q, %q, %v), want same keypair", priv2, pub2, err)
	}

	// Mismatched DevicePublicKey is repaired from DevicePrivateKey and re-saved.
	b := &agent{statePath: statePath, st: state{DevicePrivateKey: priv1, DevicePublicKey: "corrupted"}}
	priv3, pub3, err := b.ensureDeviceIdentity()
	if err != nil || priv3 != priv1 || pub3 != pub1 {
		t.Fatalf("repair ensureDeviceIdentity = (%q, %q, %v), want derived pub", priv3, pub3, err)
	}

	// If persisting fails, in-memory state must roll back cleanly.
	broken := &agent{statePath: filepath.Join(dir, "no-such-subdir", "state.json")}
	if _, _, err := broken.ensureDeviceIdentity(); err == nil {
		t.Fatal("ensureDeviceIdentity succeeded despite unwritable statePath")
	}
	if broken.st.DevicePrivateKey != "" || broken.st.DevicePublicKey != "" {
		t.Fatal("in-memory identity was not rolled back after saveState failure")
	}
}

func TestWriteE2ESessionFileAndSidecarArgs(t *testing.T) {
	dir := t.TempDir()
	a := &agent{
		statePath: filepath.Join(dir, "state.json"),
		st:        state{AgentID: "agent-e2e-1"},
	}
	_, viewPub, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	rs := protocol.RemoteStartMsg{
		SessionID: "sess-file-1",
		Kind:      protocol.RemoteKindDesktop,
		GuestMode: "view",
		NoChat:    true,
		E2E:       true,
		ViewerKey: viewPub,
	}
	path, err := a.writeE2ESessionFile(rs, "wss://rmm.example.test/ws/remote?role=agent&session=sess-file-1", "agent-ticket-1", false)
	if err != nil {
		t.Fatalf("writeE2ESessionFile: %v", err)
	}
	defer func() {
		_ = os.Remove(path)
		_ = os.Remove(filepath.Dir(path))
	}()

	if runtime.GOOS != "windows" {
		fInfo, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fInfo.Mode().Perm() != 0o600 {
			t.Fatalf("session file perm = %o, want 0600", fInfo.Mode().Perm())
		}
		dInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if dInfo.Mode().Perm() != 0o700 {
			t.Fatalf("session dir perm = %o, want 0700", dInfo.Mode().Perm())
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sp e2e.SessionParams
	if err := json.Unmarshal(raw, &sp); err != nil {
		t.Fatal(err)
	}
	if !sp.E2E || sp.SessionID != "sess-file-1" || sp.AgentID != "agent-e2e-1" ||
		sp.Kind != "desktop" || sp.GuestMode != "view" || !sp.NoFiles || !sp.NoChat || sp.FilesOnly ||
		sp.Ticket != "agent-ticket-1" || sp.ViewerKey != viewPub {
		t.Fatalf("unexpected SessionParams: %+v", sp)
	}
	ekPub, err := e2e.PublicKeyFromPrivate(sp.EKPriv)
	if err != nil {
		t.Fatalf("invalid EKPriv in SessionParams: %v", err)
	}
	if !e2e.VerifyDelegation(sp.IKPub, e2e.Delegation{
		SessionID: sp.SessionID,
		AgentID:   sp.AgentID,
		Kind:      sp.Kind,
		GuestMode: sp.GuestMode,
		EKPub:     ekPub,
		Exp:       sp.Exp,
	}, sp.SigDel) {
		t.Fatal("SessionParams delegation signature failed verification")
	}

	// sidecarArgs passes "-session <path>" verbatim without adding -relay/-ticket.
	gotArgs := sidecarArgs("wss://ignored", "ignored-ticket", []string{"-session", path})
	if len(gotArgs) != 2 || gotArgs[0] != "-session" || gotArgs[1] != path {
		t.Fatalf("sidecarArgs(-session) = %#v, want [-session %s]", gotArgs, path)
	}

	// Rejects missing agent_id and invalid viewer_key.
	noID := &agent{statePath: filepath.Join(dir, "state2.json")}
	if _, err := noID.writeE2ESessionFile(rs, "wss://r", "t", true); err == nil || !strings.Contains(err.Error(), "agent_id") {
		t.Fatalf("missing agent_id err = %v, want agent_id error", err)
	}
	badKey := rs
	badKey.ViewerKey = "not-a-key"
	if _, err := a.writeE2ESessionFile(badKey, "wss://r", "t", true); err == nil {
		t.Fatal("writeE2ESessionFile accepted invalid viewer key")
	}
}

func TestSidecarSupportsE2E(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell script fixture")
	}
	dir := t.TempDir()
	makeFake := func(name, script string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldBin := makeFake("old", `echo 0.18.0`)
	e2eBin := makeFake("e2e", `echo 0.19.0`)
	newerBin := makeFake("newer", `echo 0.20.1`)
	failBin := makeFake("fail", `exit 1`)

	if sidecarSupportsE2E(oldBin) {
		t.Error("0.18.0 reported as E2E capable")
	}
	if !sidecarSupportsE2E(e2eBin) {
		t.Error("0.19.0 not reported as E2E capable")
	}
	if !sidecarSupportsE2E(newerBin) {
		t.Error("0.20.1 not reported as E2E capable")
	}
	if sidecarSupportsE2E(failBin) {
		t.Error("failing binary reported as E2E capable")
	}
}

func TestStartTerminalSessionE2EEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX PTY interactive shell E2E test")
	}
	dir := t.TempDir()
	a := &agent{
		statePath: filepath.Join(dir, "state.json"),
		st:        state{AgentID: "agent-term-e2e"},
	}
	_, ikPub, err := a.ensureDeviceIdentity()
	if err != nil {
		t.Fatal(err)
	}
	viewPriv, viewPub, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	const secretMarker = "E2E-TERMINAL-SECRET-MARKER-7741"
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var (
		wireMu     sync.Mutex
		wireFrames [][]byte
	)
	doneCh := make(chan error, 1)

	// Bridge raw WebSocket frames through a local spy so we verify both E2E
	// handshake + encrypted interactive PTY I/O + zero plaintext on the wire.
	agentAccepted := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Remote-Agent term-ticket" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		agentAccepted <- c
	}))
	defer srv.Close()

	// Create a second local WS endpoint so HandshakeViewer connects over a real
	// spying relay pipe to the agent's connection.
	viewerAccepted := make(chan *websocket.Conn, 1)
	viewerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		viewerAccepted <- c
	}))
	defer viewerSrv.Close()

	rawViewer, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(viewerSrv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawViewer.Close()
	spyViewerSide := <-viewerAccepted
	defer spyViewerSide.Close()

	a.wsURL = "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/agent"
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		a.startTerminalSession(protocol.RemoteStartMsg{
			SessionID:   "sess-term-e2e",
			AgentTicket: "term-ticket",
			Kind:        protocol.RemoteKindTerminal,
			E2E:         true,
			ViewerKey:   viewPub,
		})
	}()

	spyAgentSide := <-agentAccepted
	defer spyAgentSide.Close()

	pipe := func(src, dst *websocket.Conn) {
		defer dst.Close()
		for {
			mt, data, err := src.ReadMessage()
			if err != nil {
				return
			}
			wireMu.Lock()
			wireFrames = append(wireFrames, append([]byte(nil), data...))
			wireMu.Unlock()
			if err := dst.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}
	go pipe(spyAgentSide, spyViewerSide)
	go pipe(spyViewerSide, spyAgentSide)

	go func() {
		viewerConn, err := e2e.HandshakeViewer(rawViewer, e2e.ViewerHandshakeOpts{
			SessionID:       "sess-term-e2e",
			EKPriv:          viewPriv,
			ExpectedAgentID: "agent-term-e2e",
			ExpectedKind:    protocol.RemoteKindTerminal,
			ExpectedIKPub:   ikPub,
		})
		if err != nil {
			doneCh <- err
			return
		}
		defer viewerConn.Close()

		// 1. Expect encrypted hello frame from the agent shell.
		_ = rawViewer.SetReadDeadline(time.Now().Add(10 * time.Second))
		mt, helloRaw, err := viewerConn.ReadMessage()
		if err != nil || mt != websocket.TextMessage {
			doneCh <- err
			return
		}
		var hello struct {
			T     string `json:"t"`
			Shell string `json:"shell"`
		}
		if err := json.Unmarshal(helloRaw, &hello); err != nil || hello.T != "hello" || hello.Shell == "" {
			doneCh <- os.ErrInvalid
			return
		}

		// 2. Send encrypted resize + command printing secretMarker and exiting.
		if err := viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"resize","cols":100,"rows":30}`)); err != nil {
			doneCh <- err
			return
		}
		cmd := "printf '%s\\n' '" + secretMarker + "'; exit\n"
		if err := viewerConn.WriteMessage(websocket.BinaryMessage, []byte(cmd)); err != nil {
			doneCh <- err
			return
		}

		var out bytes.Buffer
		sawExit := false
		for !sawExit {
			mt, msg, err := viewerConn.ReadMessage()
			if err != nil {
				break
			}
			if mt == websocket.BinaryMessage {
				out.Write(msg)
			} else if mt == websocket.TextMessage && strings.Contains(string(msg), `"exit"`) {
				sawExit = true
			}
		}
		if !strings.Contains(out.String(), secretMarker) {
			doneCh <- os.ErrNotExist
			return
		}
		if !sawExit {
			doneCh <- os.ErrClosed
			return
		}
		doneCh <- nil
	}()

	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("E2E terminal session failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for E2E terminal session")
	}

	select {
	case <-agentDone:
	case <-time.After(5 * time.Second):
		t.Fatal("agent startTerminalSession did not exit after shell closed")
	}

	wireMu.Lock()
	defer wireMu.Unlock()
	if len(wireFrames) < 4 {
		t.Fatalf("expected encrypted frames on wire, saw %d", len(wireFrames))
	}
	for _, frame := range wireFrames {
		if bytes.Contains(frame, []byte(secretMarker)) || bytes.Contains(frame, []byte(`"t":"hello"`)) || bytes.Contains(frame, []byte(`"t":"resize"`)) {
			t.Fatalf("relay saw terminal plaintext on the wire: %q", frame)
		}
	}
}
