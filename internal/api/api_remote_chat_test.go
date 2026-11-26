package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/remote"
)

func TestEncryptedChatEpochIsBoundToApprovedMembership(t *testing.T) {
	sessions := newGuestSessions()
	viewer := remote.Viewer{SessionID: "tech-session", AgentID: "device", User: "technician", E2E: true}
	first := map[string]int{"guest-a": 1}
	both := map[string]int{"guest-a": 1, "guest-b": 1}
	second := map[string]int{"guest-b": 1}
	publish := func(kid string, generation uint64, members map[string]int, wrapped bool) ([]remoteChatLine, bool) {
		return sessions.exchangeChat(viewer, remoteChatRequest{
			Kid: kid, Generation: generation, Envelope: json.RawMessage(`{"t":"e2e_chat"}`),
		}, "tech", "", members, wrapped, func() bool { return true })
	}
	read := func(kid, share string, members map[string]int) ([]remoteChatLine, bool) {
		return sessions.exchangeChat(viewer, remoteChatRequest{Kid: kid}, "guest", share, members, true, func() bool { return true })
	}

	if _, ok := publish("initial", 1, first, true); !ok {
		t.Fatal("initial room was rejected")
	}
	if lines, ok := read("initial", "guest-a", first); !ok || len(lines) != 1 {
		t.Fatal("approved guest could not read the current room")
	}
	if _, ok := read("initial", "guest-b", both); ok {
		t.Fatal("new guest accessed the old room")
	}
	if _, ok := publish("second", 2, both, false); ok {
		t.Fatal("room activated before every guest received the new key")
	}
	if _, ok := publish("second", 2, both, true); !ok {
		t.Fatal("new room was rejected")
	}
	if lines, ok := read("second", "guest-b", both); !ok || len(lines) != 1 || lines[0].Cursor != 1 {
		t.Fatal("new room exposed history from the previous epoch")
	}
	if _, ok := publish("second", 3, second, true); ok {
		t.Fatal("same key accepted after removal")
	}
	if _, ok := publish("second", 3, both, true); ok {
		t.Fatal("suspended room reactivated when membership matched again")
	}
	if _, ok := publish("third", 3, second, true); !ok {
		t.Fatal("replacement key after removal was rejected")
	}
	if _, ok := read("third", "guest-a", second); ok {
		t.Fatal("removed guest could read the new epoch")
	}
	if _, ok := publish("initial", 1, first, true); ok {
		t.Fatal("out-of-order previous epoch reactivated")
	}

	// A local endpoint user line forwarded by the technician may also activate a new generation.
	if lines, ok := sessions.exchangeChat(viewer, remoteChatRequest{
		Kid: "fourth", Generation: 4, Envelope: json.RawMessage(`{"t":"e2e_chat"}`),
	}, "user", "", second, true, func() bool { return true }); !ok || len(lines) != 1 || lines[0].From != "user" {
		t.Fatalf("endpoint user line failed to activate new generation: lines=%+v ok=%v", lines, ok)
	}
	if _, ok := sessions.exchangeChat(viewer, remoteChatRequest{
		Kid: "guest-epoch", Generation: 5, Envelope: json.RawMessage(`{"t":"e2e_chat"}`),
	}, "guest", "guest-b", second, true, func() bool { return true }); ok {
		t.Fatal("guest activated a new chat epoch")
	}

	// Suspending a room clears buffered messages and refuses the suspended kid until rekeyed.
	sessions.suspendChat(viewer.SessionID)
	if _, ok := read("fourth", "guest-b", second); ok {
		t.Fatal("suspended room remained readable")
	}
	if _, ok := publish("fourth", 5, second, true); ok {
		t.Fatal("suspended room reactivated under the same kid")
	}
	if lines, ok := publish("fifth", 5, second, true); !ok || len(lines) != 1 || lines[0].Cursor != 1 {
		t.Fatalf("replacement epoch after suspend failed: lines=%+v ok=%v", lines, ok)
	}

	sessions.forgetChat(viewer.SessionID)
	if _, ok := read("fifth", "guest-b", second); ok {
		t.Fatal("room survived the technician's session")
	}
}

func TestReadRemoteChatValidation(t *testing.T) {
	validEnv, _ := json.Marshal(e2e.ChatEnvelope{T: "e2e_chat", V: 1, Kid: "kid-1", IV: "iv", CT: "ct"})
	mismatchEnv, _ := json.Marshal(e2e.ChatEnvelope{T: "e2e_chat", V: 1, Kid: "kid-other", IV: "iv", CT: "ct"})

	cases := []struct {
		name   string
		body   string
		wantOK bool
	}{
		{name: "valid_poll", body: `{"session_id":"s1","kid":"kid-1","cursor":0}`, wantOK: true},
		{name: "valid_send", body: `{"session_id":"s1","kid":"kid-1","cursor":0,"envelope":` + string(validEnv) + `}`, wantOK: true},
		{name: "invalid_json", body: `{bad`, wantOK: false},
		{name: "missing_session", body: `{"kid":"kid-1"}`, wantOK: false},
		{name: "missing_kid", body: `{"session_id":"s1"}`, wantOK: false},
		{name: "kid_too_long", body: `{"session_id":"s1","kid":"` + strings.Repeat("k", 65) + `"}`, wantOK: false},
		{name: "invalid_envelope", body: `{"session_id":"s1","kid":"kid-1","envelope":{"t":"chat","text":"plain"}}`, wantOK: false},
		{name: "envelope_kid_mismatch", body: `{"session_id":"s1","kid":"kid-1","envelope":` + string(mismatchEnv) + `}`, wantOK: false},
		{name: "body_too_large", body: `{"session_id":"s1","kid":"kid-1","source":"` + strings.Repeat("a", 13<<10) + `"}`, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/devices/a1/remote-chat", strings.NewReader(tc.body))
			_, ok := readRemoteChat(rec, req)
			if ok != tc.wantOK {
				t.Fatalf("readRemoteChat(%s) ok=%v (status=%d body=%s), want %v", tc.name, ok, rec.Code, rec.Body.String(), tc.wantOK)
			}
			if !tc.wantOK && rec.Code != http.StatusBadRequest {
				t.Fatalf("readRemoteChat(%s) status=%d, want 400", tc.name, rec.Code)
			}
		})
	}
}

func TestSuspendRemoteChatIsolatesByAgentAndSponsor(t *testing.T) {
	s := &Server{presence: remote.NewPresence(), guests: newGuestSessions()}
	env := json.RawMessage(`{"t":"e2e_chat","v":1,"kid":"k1","iv":"iv","ct":"ct"}`)
	attached := func() bool { return true }
	members := map[string]int{"share-1": 1}

	vTarget := remote.Viewer{SessionID: "sess-target", AgentID: "a1", User: "u1", Kind: "native", E2E: true}
	vOtherTech := remote.Viewer{SessionID: "sess-other-tech", AgentID: "a1", User: "u2", Kind: "native", E2E: true}
	vOtherDev := remote.Viewer{SessionID: "sess-other-dev", AgentID: "a2", User: "u1", Kind: "native", E2E: true}
	vLegacy := remote.Viewer{SessionID: "sess-legacy", AgentID: "a1", User: "u1", Kind: "native", E2E: false}

	for _, v := range []remote.Viewer{vTarget, vOtherTech, vOtherDev, vLegacy} {
		s.presence.Join(v)
		_, ok := s.guests.exchangeChat(v, remoteChatRequest{Session: v.SessionID, Kid: "k1", Generation: 1, Envelope: env}, "tech", "", members, true, attached)
		if !ok {
			t.Fatalf("failed to activate room for %s", v.SessionID)
		}
	}

	// Suspending (a1, u1) must suspend ONLY the E2E native session of (a1, u1).
	s.suspendRemoteChat("a1", "u1")

	if _, ok := s.guests.exchangeChat(vTarget, remoteChatRequest{Session: vTarget.SessionID, Kid: "k1"}, "tech", "", members, true, attached); ok {
		t.Fatal("target E2E room stayed active after suspendRemoteChat")
	}
	if lines, ok := s.guests.exchangeChat(vOtherTech, remoteChatRequest{Session: vOtherTech.SessionID, Kid: "k1"}, "tech", "", members, true, attached); !ok || len(lines) != 1 {
		t.Fatalf("other technician's room was affected: ok=%v len=%d", ok, len(lines))
	}
	if lines, ok := s.guests.exchangeChat(vOtherDev, remoteChatRequest{Session: vOtherDev.SessionID, Kid: "k1"}, "tech", "", members, true, attached); !ok || len(lines) != 1 {
		t.Fatalf("other device's room was affected: ok=%v len=%d", ok, len(lines))
	}
	if lines, ok := s.guests.exchangeChat(vLegacy, remoteChatRequest{Session: vLegacy.SessionID, Kid: "k1"}, "tech", "", members, true, attached); !ok || len(lines) != 1 {
		t.Fatalf("legacy session room was unexpectedly suspended: ok=%v len=%d", ok, len(lines))
	}

	// Calling with nil fields or empty sessionID is a safe no-op.
	(&Server{}).suspendRemoteChat("a1", "u1")
	s.guests.suspendChat("")
}

func TestLegacyChatBridgeIgnoresE2ESessions(t *testing.T) {
	s := &Server{relay: remote.NewRelay(), presence: remote.NewPresence(), guests: newGuestSessions()}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := up.Upgrade(w, req, nil)
		if err != nil {
			return
		}
		q := req.URL.Query()
		_ = s.relay.Join(q.Get("session"), "a1", q.Get("role"), conn)
	}))
	defer srv.Close()

	base := "ws" + strings.TrimPrefix(srv.URL, "http") + "?session="
	dial := func(u string) *websocket.Conn {
		t.Helper()
		c, _, err := websocket.DefaultDialer.Dial(u, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	pair := func(id string) (agent, viewer *websocket.Conn) {
		t.Helper()
		agent = dial(base + id + "&role=agent")
		viewer = dial(base + id + "&role=viewer")
		_ = agent.WriteMessage(websocket.TextMessage, []byte(`{"t":"notice","text":"ready"}`))
		_ = viewer.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, _, err := viewer.ReadMessage(); err != nil {
			t.Fatalf("pair %s failed: %v", id, err)
		}
		return agent, viewer
	}

	e2eTechAgent, e2eTechViewer := pair("tech-e2e")
	_, e2eGuestViewer := pair("guest-e2e")
	_, legacyGuestViewer := pair("guest-legacy")

	s.presence.Join(remote.Viewer{SessionID: "tech-e2e", AgentID: "a1", User: "u1", Kind: "native", E2E: true})
	s.presence.Join(remote.Viewer{SessionID: "guest-e2e", AgentID: "a1", User: models.GuestPrincipal("s-e2e"), Kind: "native", E2E: true})
	s.presence.Join(remote.Viewer{SessionID: "guest-legacy", AgentID: "a1", User: models.GuestPrincipal("s-leg"), Kind: "native", E2E: false})

	s.guests.start(&guestSession{shareID: "s-e2e", sessionID: "guest-e2e", agentID: "a1", sponsor: "u1", name: "Alice", e2e: true})
	s.guests.start(&guestSession{shareID: "s-leg", sessionID: "guest-legacy", agentID: "a1", sponsor: "u1", name: "Bob", e2e: false})

	// 1. E2E technician chat line must never be carried in cleartext to any guest.
	s.carryChat(chatLine{agentID: "a1", sessionID: "tech-e2e", role: "viewer", text: "secret-from-e2e-tech"})
	// 2. E2E guest chat line must never be carried in cleartext.
	s.carryChat(chatLine{agentID: "a1", sessionID: "guest-e2e", role: "viewer", text: "secret-from-e2e-guest"})
	// 3. Legacy guest line must never be injected into an E2E technician or E2E guest session!
	s.carryChat(chatLine{agentID: "a1", sessionID: "guest-legacy", role: "viewer", text: "from-legacy-guest"})

	// Verify neither E2E socket received any cleartext chat frame by sending a direct marker and reading immediately.
	marker := `{"t":"notice","text":"marker"}`
	_ = e2eTechAgent.WriteMessage(websocket.TextMessage, []byte(marker))
	_ = e2eTechViewer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, gotTech, err := e2eTechViewer.ReadMessage()
	if err != nil || string(gotTech) != marker {
		t.Fatalf("E2E tech viewer got %q (err=%v), want marker only", gotTech, err)
	}

	_ = e2eGuestViewer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, gotGuest, err := e2eGuestViewer.ReadMessage(); err == nil {
		t.Fatalf("E2E guest viewer unexpectedly received cleartext %q", gotGuest)
	}

	_ = legacyGuestViewer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, gotLeg, err := legacyGuestViewer.ReadMessage(); err == nil {
		t.Fatalf("legacy guest unexpectedly received E2E tech chat %q", gotLeg)
	}
}
