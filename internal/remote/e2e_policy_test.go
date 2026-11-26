package remote

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/hub"
	"github.com/p1ngu/rmm/internal/models"
)

func TestSetE2EPolicyAndBrokerGuards(t *testing.T) {
	h := hub.New()
	m := NewManager(nil, h, "", "", "", false, false)

	// SetE2EPolicy only accepts "required"; anything else normalizes to "preferred".
	m.SetE2EPolicy("required")
	if m.e2ePolicy != "required" {
		t.Fatalf("e2ePolicy = %q, want required", m.e2ePolicy)
	}
	m.SetE2EPolicy("invalid")
	if m.e2ePolicy != "preferred" {
		t.Fatalf("e2ePolicy = %q, want preferred", m.e2ePolicy)
	}

	_, pinnedPub, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	offlineAgent := &models.Agent{ID: "agent-offline"}
	legacyAgent := &models.Agent{ID: "agent-legacy"}
	pinnedAgent := &models.Agent{ID: "agent-pinned", DevicePublicKey: pinnedPub}

	h.Add(legacyAgent.ID, func() {})
	h.Add(pinnedAgent.ID, func() {})

	for _, provider := range []string{"native", "files", "terminal"} {
		t.Run(provider, func(t *testing.T) {
			if _, err := m.Start(context.Background(), provider, offlineAgent, "u1", StartOptions{}); err == nil || !strings.Contains(err.Error(), "offline") {
				t.Fatalf("offline %s err = %v, want offline error", provider, err)
			}

			// Under "required", legacy unpinned devices are refused with ErrAgentEncryptionRequired.
			m.SetE2EPolicy("required")
			if _, err := m.Start(context.Background(), provider, legacyAgent, "u1", StartOptions{}); !errors.Is(err, ErrAgentEncryptionRequired) {
				t.Fatalf("legacy %s under required err = %v, want ErrAgentEncryptionRequired", provider, err)
			}

			// Even under "preferred", a pinned device permanently requires a valid E2E viewer key (anti-downgrade ratchet).
			m.SetE2EPolicy("preferred")
			if _, err := m.Start(context.Background(), provider, pinnedAgent, "u1", StartOptions{}); err == nil || !strings.Contains(err.Error(), "viewer key") {
				t.Fatalf("pinned %s without viewer key err = %v, want viewer key error", provider, err)
			}
			if _, err := m.Start(context.Background(), provider, pinnedAgent, "u1", StartOptions{ViewerKey: "not-a-valid-key"}); err == nil || !strings.Contains(err.Error(), "viewer key") {
				t.Fatalf("pinned %s with invalid viewer key err = %v, want viewer key error", provider, err)
			}
		})
	}
}

func TestGuestPolicyE2ERelayForwarding(t *testing.T) {
	r := NewRelay()
	var chatHookCalls atomic.Int32
	r.SetChatHook(func(agentID, sessionID, role, text string) {
		chatHookCalls.Add(1)
	})

	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c, err := up.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		role := req.URL.Query().Get("role")
		if role == "viewer" {
			_ = r.JoinGuest("sess-e2e-guest", "agent-1", c, GuestPolicy{E2E: true})
			return
		}
		_ = r.Join("sess-e2e-guest", "agent-1", "agent", c)
	}))
	defer srv.Close()

	base := "ws" + strings.TrimPrefix(srv.URL, "http")
	agentWS, _, err := websocket.DefaultDialer.Dial(base+"?role=agent", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer agentWS.Close()
	viewerWS, _, err := websocket.DefaultDialer.Dial(base+"?role=viewer", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer viewerWS.Close()

	// 1. e2e_hello passes in both directions; non-e2e_hello text (e.g. legacy chat) and oversized hello are dropped.
	_ = viewerWS.WriteMessage(websocket.TextMessage, []byte(`{"t":"chat","text":"must-drop"}`))
	_ = viewerWS.WriteMessage(websocket.TextMessage, []byte(`{"t":"e2e_hello","pad":"`+strings.Repeat("x", guestE2EViewerHelloLimit)+`"}`))
	helloViewer := []byte(`{"t":"e2e_hello","v":1,"role":"viewer"}`)
	if err := viewerWS.WriteMessage(websocket.TextMessage, helloViewer); err != nil {
		t.Fatal(err)
	}
	_ = agentWS.SetReadDeadline(time.Now().Add(3 * time.Second))
	mt, got, err := agentWS.ReadMessage()
	if err != nil || mt != websocket.TextMessage || !bytes.Equal(got, helloViewer) {
		t.Fatalf("agent got (%d, %q, %v), want viewer e2e_hello only", mt, got, err)
	}

	// 2. Binary frames: non-0xE0, truncated (<26B), and oversized (>guestE2EFrameLimit) viewer frames are dropped;
	// valid >=26B 0xE0 frames pass untouched in both directions.
	_ = viewerWS.WriteMessage(websocket.BinaryMessage, append([]byte{0x02}, make([]byte, 30)...))
	_ = viewerWS.WriteMessage(websocket.BinaryMessage, []byte{chE2E, 0, 0, 0, 0, 0, 0, 0, 1, 0xAA})
	_ = viewerWS.WriteMessage(websocket.BinaryMessage, append([]byte{chE2E}, make([]byte, guestE2EFrameLimit)...))
	v2aCipher := append([]byte{chE2E, 0, 0, 0, 0, 0, 0, 0, 1}, bytes.Repeat([]byte{0xAA}, 24)...)
	_ = viewerWS.WriteMessage(websocket.BinaryMessage, v2aCipher)
	mt, got, err = agentWS.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || !bytes.Equal(got, v2aCipher) {
		t.Fatalf("agent binary got (%d, %x, %v), want 0xE0 frame", mt, got, err)
	}

	_ = agentWS.WriteMessage(websocket.TextMessage, []byte(`{"t":"chat","from":"user","text":"must-drop"}`))
	_ = agentWS.WriteMessage(websocket.TextMessage, []byte(`{"t":"e2e_hello","pad":"`+strings.Repeat("y", guestE2EAgentHelloLimit)+`"}`))
	_ = agentWS.WriteMessage(websocket.BinaryMessage, append([]byte{0x01}, make([]byte, 30)...))
	_ = agentWS.WriteMessage(websocket.BinaryMessage, []byte{chE2E, 0, 0, 0, 0, 0, 0, 0, 1, 0xCC})
	a2vCipher := append([]byte{chE2E, 0, 0, 0, 0, 0, 0, 0, 1}, bytes.Repeat([]byte{0xCC}, 24)...)
	_ = agentWS.WriteMessage(websocket.BinaryMessage, a2vCipher)
	_ = viewerWS.SetReadDeadline(time.Now().Add(3 * time.Second))
	mt, got, err = viewerWS.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || !bytes.Equal(got, a2vCipher) {
		t.Fatalf("viewer binary got (%d, %x, %v), want 0xE0 frame", mt, got, err)
	}

	if calls := chatHookCalls.Load(); calls != 0 {
		t.Fatalf("legacy ChatHook fired %d times on E2E guest session, want 0", calls)
	}
}
