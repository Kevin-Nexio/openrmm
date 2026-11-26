package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/protocol"
)

// A damaged identity key is never replaced by a new one: the server pinned the
// old key, and a new one would make this device look like another machine.
func TestEnsureDeviceIdentityNeverReplacesADamagedKey(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	a := newDedupeAgent(t, statePath)
	a.statePath = statePath
	a.st.AgentID, a.st.AgentToken = "agent-7", "stored-token"
	a.st.DevicePrivateKey = "not-a-key"
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(statePath)
	if _, _, err := a.ensureDeviceIdentity(); !errors.Is(err, errDeviceKeyUnreadable) {
		t.Fatalf("damaged key = %v, want errDeviceKeyUnreadable", err)
	}
	if a.st.DevicePrivateKey != "not-a-key" {
		t.Fatal("the damaged key was replaced in memory")
	}
	if after, _ := os.ReadFile(statePath); string(after) != string(before) {
		t.Fatal("the state file was rewritten")
	}
}

// With no key at all, the agent creates one, saves it before using it, and
// returns the same one afterwards.
func TestEnsureDeviceIdentityCreatesOneKeyAndKeepsIt(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	a := newDedupeAgent(t, statePath)
	a.statePath = statePath
	priv, pub, err := a.ensureDeviceIdentity()
	if err != nil || priv == "" || pub == "" {
		t.Fatalf("first identity = (%q, %q, %v)", priv, pub, err)
	}
	var saved state
	raw, _ := os.ReadFile(statePath)
	if json.Unmarshal(raw, &saved) != nil || saved.DevicePrivateKey != priv {
		t.Fatal("the new key was not saved")
	}
	if _, again, err := a.ensureDeviceIdentity(); err != nil || again != pub {
		t.Fatalf("second identity = (%q, %v), want the same key", again, err)
	}
	if got := a.deviceFingerprint(); got != e2e.DisplayFingerprint(pub) || got == "" {
		t.Fatalf("deviceFingerprint = %q", got)
	}
}

// An unreadable key still connects, without a key and saying why, so the
// server keeps the device online and pauses only its remote sessions.
func TestHandshakeConnectsWithoutAnUnreadableKey(t *testing.T) {
	registered := make(chan protocol.RegisterReq, 2)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		var env protocol.Envelope
		if conn.ReadJSON(&env) != nil {
			return
		}
		var req protocol.RegisterReq
		_ = json.Unmarshal(env.Data, &req)
		registered <- req
		data, _ := json.Marshal(protocol.RegisterResp{AgentID: req.AgentID})
		_ = conn.WriteJSON(protocol.Envelope{Type: protocol.MsgRegistered, Data: data})
	}))
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	register := func(privateKey string) protocol.RegisterReq {
		t.Helper()
		statePath := filepath.Join(t.TempDir(), "state.json")
		a := newDedupeAgent(t, statePath)
		a.statePath = statePath
		a.st.AgentID, a.st.AgentToken = "agent-7", "stored-token"
		a.st.DevicePrivateKey = privateKey
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := a.handshake(conn); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		return <-registered
	}

	if req := register("not-a-key"); req.DevicePublicKey != "" || req.DeviceKeyStatus != protocol.DeviceKeyUnavailable {
		t.Fatalf("damaged key registered as %q / %q, want no key and %q", req.DevicePublicKey, req.DeviceKeyStatus, protocol.DeviceKeyUnavailable)
	}
	priv, pub, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if req := register(priv); req.DevicePublicKey != pub || req.DeviceKeyStatus != "" {
		t.Fatalf("good key registered as %q / %q", req.DevicePublicKey, req.DeviceKeyStatus)
	}
}

// -fingerprint reads the state file only, and says why when it cannot answer.
func TestStateFingerprint(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, st state) string {
		path := filepath.Join(dir, name)
		raw, _ := json.Marshal(st)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	priv, pub, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := stateFingerprint(write("ok.json", state{DevicePrivateKey: priv})); err != nil || got != e2e.DisplayFingerprint(pub) {
		t.Fatalf("fingerprint = (%q, %v), want %q", got, err, e2e.DisplayFingerprint(pub))
	}
	if _, err := stateFingerprint(write("none.json", state{AgentID: "a"})); err == nil {
		t.Fatal("a state file without a key gave a fingerprint")
	}
	if _, err := stateFingerprint(write("bad.json", state{DevicePrivateKey: "not-a-key"})); !errors.Is(err, errDeviceKeyUnreadable) {
		t.Fatalf("damaged key = %v, want errDeviceKeyUnreadable", err)
	}
	if _, err := stateFingerprint(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("a missing state file gave a fingerprint")
	}
	if fp := e2e.DisplayFingerprint(pub); len(fp) != 19 || strings.Count(fp, "-") != 3 {
		t.Fatalf("fingerprint shape = %q", fp)
	}
}
