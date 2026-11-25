package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestKeyPairFingerprintsAndSignatures(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(pub); err != nil {
		t.Fatalf("ValidatePublicKey: %v", err)
	}
	derived, err := PublicKeyFromPrivate(priv)
	if err != nil || derived != pub {
		t.Fatalf("PublicKeyFromPrivate = %q, err=%v, want %q", derived, err, pub)
	}
	if fp := DisplayFingerprint(pub); len(fp) != 19 || strings.Count(fp, "-") != 3 {
		t.Fatalf("DisplayFingerprint = %q", fp)
	}
	if ifp := InviteFingerprint(pub); len(ifp) != 22 {
		t.Fatalf("InviteFingerprint = %q (len %d)", ifp, len(ifp))
	}

	msg := []byte("openrmm-e2e-test-message")
	sig, err := SignP256(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyP256(pub, msg, sig) {
		t.Fatal("VerifyP256 rejected valid signature")
	}
	if VerifyP256(pub, []byte("tampered"), sig) {
		t.Fatal("VerifyP256 accepted tampered message")
	}
	_, otherPub, _ := GenerateKeyPair()
	if VerifyP256(otherPub, msg, sig) {
		t.Fatal("VerifyP256 accepted wrong public key")
	}
}

func TestDelegationBindsAllSessionParameters(t *testing.T) {
	ikPriv, ikPub, _ := GenerateKeyPair()
	_, ekPub, _ := GenerateKeyPair()
	del := Delegation{
		SessionID: "sess-123",
		AgentID:   "agent-456",
		Kind:      "desktop",
		GuestMode: "view",
		EKPub:     ekPub,
		Exp:       time.Now().Add(5 * time.Minute).Unix(),
	}
	sig, err := SignDelegation(ikPriv, del)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDelegation(ikPub, del, sig) {
		t.Fatal("VerifyDelegation rejected valid delegation")
	}
	for name, mutate := range map[string]func(*Delegation){
		"session":    func(d *Delegation) { d.SessionID = "sess-other" },
		"agent":      func(d *Delegation) { d.AgentID = "agent-other" },
		"kind":       func(d *Delegation) { d.Kind = "terminal" },
		"guest_mode": func(d *Delegation) { d.GuestMode = "control" },
		"exp":        func(d *Delegation) { d.Exp++ },
	} {
		copyDel := del
		mutate(&copyDel)
		if VerifyDelegation(ikPub, copyDel, sig) {
			t.Fatalf("VerifyDelegation accepted mutated %s", name)
		}
	}
}

// startPipeServer creates an in-memory WebSocket relay that blindly pipes frames
// between the two connected endpoints while recording every wire frame the
// server saw so tests can prove zero plaintext leakage.
func startPipeServer(t *testing.T) (wsURL string, wireFrames func() [][]byte) {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	ch := make(chan *websocket.Conn, 2)
	var recorded [][]byte
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ch <- c
	}))
	go func() {
		a := <-ch
		b := <-ch
		if a == nil || b == nil {
			return
		}
		pipe := func(src, dst *websocket.Conn) {
			defer dst.Close()
			for {
				mt, data, err := src.ReadMessage()
				if err != nil {
					return
				}
				cp := append([]byte{byte(mt)}, data...)
				mu.Lock()
				recorded = append(recorded, cp)
				mu.Unlock()
				if err := dst.WriteMessage(mt, data); err != nil {
					return
				}
			}
		}
		go pipe(a, b)
		pipe(b, a)
	}()
	t.Cleanup(func() {
		srv.Close()
		select {
		case ch <- nil:
		default:
		}
		select {
		case ch <- nil:
		default:
		}
	})
	return "ws" + strings.TrimPrefix(srv.URL, "http"), func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), recorded...)
	}
}

func TestHandshakeStreamAndZeroPlaintextOnRelay(t *testing.T) {
	wsURL, recorded := startPipeServer(t)
	ikPriv, ikPub, _ := GenerateKeyPair()
	viewPriv, viewPub, _ := GenerateKeyPair()
	agentOpts, err := NewAgentHandshakeFromIdentity("sess-1", "agent-1", "desktop", "", viewPub, ikPriv, ikPub, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	rawAgent, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawAgent.Close()
	rawViewer, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawViewer.Close()

	agentCh := make(chan *Conn, 1)
	errCh := make(chan error, 2)
	go func() {
		c, herr := HandshakeAgent(rawAgent, agentOpts)
		if herr != nil {
			errCh <- herr
			return
		}
		agentCh <- c
	}()

	viewerConn, err := HandshakeViewer(rawViewer, ViewerHandshakeOpts{
		EKPriv:          viewPriv,
		SessionID:       "sess-1",
		ExpectedAgentID: "agent-1",
		ExpectedKind:    "desktop",
		ExpectedIKPub:   ikPub,
	})
	if err != nil {
		t.Fatalf("HandshakeViewer: %v", err)
	}
	var agentConn *Conn
	select {
	case agentConn = <-agentCh:
	case herr := <-errCh:
		t.Fatalf("HandshakeAgent: %v", herr)
	}

	secretClip := `{"t":"clip","text":"SUPER-SECRET-PASSWORD-999"}`
	if err := viewerConn.WriteMessage(websocket.TextMessage, []byte(secretClip)); err != nil {
		t.Fatal(err)
	}
	mt, got, err := agentConn.ReadMessage()
	if err != nil || mt != websocket.TextMessage || string(got) != secretClip {
		t.Fatalf("agent ReadMessage = (%d, %q, %v)", mt, got, err)
	}

	videoTile := []byte{0x01, 0xDE, 0xAD, 0xBE, 0xEF}
	if err := agentConn.WriteMessage(websocket.BinaryMessage, videoTile); err != nil {
		t.Fatal(err)
	}
	mt, gotBin, err := viewerConn.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || !bytes.Equal(gotBin, videoTile) {
		t.Fatalf("viewer ReadMessage = (%d, %x, %v)", mt, gotBin, err)
	}

	for _, f := range recorded() {
		if bytes.Contains(f, []byte("SUPER-SECRET-PASSWORD-999")) || bytes.Contains(f, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
			t.Fatal("relay saw session plaintext on the wire")
		}
	}
}

func TestHandshakeRejectsWrongPinnedKey(t *testing.T) {
	wsURL, _ := startPipeServer(t)
	ikPriv, ikPub, _ := GenerateKeyPair()
	_, wrongIKPub, _ := GenerateKeyPair()
	viewPriv, viewPub, _ := GenerateKeyPair()
	agentOpts, _ := NewAgentHandshakeFromIdentity("sess-mitm", "agent-1", "desktop", "", viewPub, ikPriv, ikPub, 5*time.Minute)

	rawAgent, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	defer rawAgent.Close()
	rawViewer, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	defer rawViewer.Close()

	go func() { _, _ = HandshakeAgent(rawAgent, agentOpts) }()
	if _, err := HandshakeViewer(rawViewer, ViewerHandshakeOpts{
		EKPriv:          viewPriv,
		SessionID:       "sess-mitm",
		ExpectedAgentID: "agent-1",
		ExpectedKind:    "desktop",
		ExpectedIKPub:   wrongIKPub,
	}); err == nil {
		t.Fatal("HandshakeViewer accepted mismatched device identity key")
	}
}

func TestGuestPolicyEnforcedInsideE2EConn(t *testing.T) {
	wsURL, _ := startPipeServer(t)
	ikPriv, ikPub, _ := GenerateKeyPair()
	viewPriv, viewPub, _ := GenerateKeyPair()
	agentOpts, _ := NewAgentHandshakeFromIdentity("sess-guest", "agent-1", "desktop", "view", viewPub, ikPriv, ikPub, 5*time.Minute)

	rawAgent, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	defer rawAgent.Close()
	rawViewer, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	defer rawViewer.Close()

	agentCh := make(chan *Conn, 1)
	go func() {
		c, _ := HandshakeAgent(rawAgent, agentOpts)
		agentCh <- c
	}()
	viewerConn, err := HandshakeViewer(rawViewer, ViewerHandshakeOpts{
		EKPriv:            viewPriv,
		SessionID:         "sess-guest",
		ExpectedKind:      "desktop",
		ExpectedGuestMode: "view",
		ExpectedInviteFP:  InviteFingerprint(ikPub),
	})
	if err != nil {
		t.Fatalf("guest HandshakeViewer: %v", err)
	}
	agentConn := <-agentCh

	// View-only guest tries to inject a keystroke, read files, and send CAD;
	// then sends an allowed keyframe request ("kf"). Only "kf" must arrive, and
	// sequence numbers must remain synchronized!
	for _, blocked := range []string{
		`{"t":"k","code":65,"down":true}`,
		`{"t":"fls","path":"/"}`,
		`{"t":"cad"}`,
		`{"t":"clip","text":"steal"}`,
	} {
		if err := viewerConn.WriteMessage(websocket.TextMessage, []byte(blocked)); err != nil {
			t.Fatal(err)
		}
	}
	if err := viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"kf"}`)); err != nil {
		t.Fatal(err)
	}
	_, got, err := agentConn.ReadMessage()
	if err != nil || string(got) != `{"t":"kf"}` {
		t.Fatalf("agent got %q (err=%v), want only kf", got, err)
	}

	// Outbound filter: clipboard and file chunks must never leave a guest's sidecar.
	_ = agentConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"clip","text":"host-secret"}`))
	_ = agentConn.WriteMessage(websocket.BinaryMessage, []byte{0x02, 1, 2, 3})
	_ = agentConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"hello","v":"0.19.0"}`))

	_, vgot, err := viewerConn.ReadMessage()
	if err != nil || !strings.Contains(string(vgot), `"hello"`) {
		t.Fatalf("guest viewer got %q (err=%v), want hello only", vgot, err)
	}
}

func TestMultiPartyChatBridgeAndAntiSpoofing(t *testing.T) {
	wsURL, _ := startPipeServer(t)
	ikPriv, ikPub, _ := GenerateKeyPair()
	viewPriv, viewPub, _ := GenerateKeyPair()
	agentOpts, _ := NewAgentHandshakeFromIdentity("sess-chat", "agent-1", "desktop", "", viewPub, ikPriv, ikPub, 5*time.Minute)

	rawAgent, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	defer rawAgent.Close()
	rawViewer, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
	defer rawViewer.Close()

	agentCh := make(chan *Conn, 1)
	go func() {
		c, _ := HandshakeAgent(rawAgent, agentOpts)
		agentCh <- c
	}()
	viewerConn, err := HandshakeViewer(rawViewer, ViewerHandshakeOpts{
		EKPriv:          viewPriv,
		SessionID:       "sess-chat",
		ExpectedAgentID: "agent-1",
		ExpectedKind:    "desktop",
		ExpectedIKPub:   ikPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	agentConn := <-agentCh

	// Agent ReadMessage loop (simulating media_*.go reader).
	agentInbound := make(chan []byte, 8)
	go func() {
		for {
			_, data, rerr := agentConn.ReadMessage()
			if rerr != nil {
				return
			}
			agentInbound <- data
		}
	}()

	// 1. Technician initializes room key K_chat and SK_tech.
	var chatKey [32]byte
	_, _ = io.ReadFull(rand.Reader, chatKey[:])
	techSignPriv, techSignPub, _ := GenerateKeyPair()
	kid := "kid-room-1"

	initMsg, _ := json.Marshal(map[string]string{
		"t":        "chat_init",
		"kid":      kid,
		"k":        base64.RawURLEncoding.EncodeToString(chatKey[:]),
		"tech_pub": techSignPub,
	})
	if err := viewerConn.WriteMessage(websocket.TextMessage, initMsg); err != nil {
		t.Fatal(err)
	}
	_, ackRaw, err := viewerConn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	var ack struct {
		T       string `json:"t"`
		Kid     string `json:"kid"`
		UserPub string `json:"user_pub"`
	}
	if err := json.Unmarshal(ackRaw, &ack); err != nil || ack.T != "chat_init_ack" || ack.Kid != kid {
		t.Fatalf("unexpected ack: %s", ackRaw)
	}

	// 2. Technician certifies PK_user and sends chat_user_cert.
	userCert, err := SignUserKeyCert(techSignPriv, kid, "agent-1", ack.UserPub)
	if err != nil {
		t.Fatal(err)
	}
	certFrame, _ := json.Marshal(map[string]any{"t": "chat_user_cert", "kid": kid, "cert": userCert})
	if err := viewerConn.WriteMessage(websocket.TextMessage, certFrame); err != nil {
		t.Fatal(err)
	}

	// 3. Guest joins, technician seals K_chat + ChatGrant for guest, guest unwraps.
	guestECDHPriv, guestECDHPub, _ := GenerateKeyPair()
	guestSignPriv, guestSignPub, _ := GenerateKeyPair()
	grant, err := SignChatGrant(techSignPriv, ChatGrant{
		Kid:          kid,
		AgentID:      "agent-1",
		ShareID:      "share-alice",
		Name:         "Alice",
		GuestSignPub: guestSignPub,
		Exp:          time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := SealChatKeyForGuest(guestECDHPub, WrappedGuestChatKey{
		Kid:     kid,
		K:       base64.RawURLEncoding.EncodeToString(chatKey[:]),
		TechPub: techSignPub,
		AgentID: "agent-1",
		ShareID: "share-alice",
		Name:    grant.Name,
		Exp:     grant.Exp,
		Grant:   grant,
		DevIK:   ikPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := OpenChatKeyAsGuest(guestECDHPriv, wrapped)
	if err != nil || unwrapped.Grant.Name != "Alice" {
		t.Fatalf("OpenChatKeyAsGuest: %v", err)
	}

	// 4. Malicious guest tries to spoof "tech" using K_chat + SK_guest -> MUST fail!
	spoofTechEnv, err := EncodeChatEnvelope(chatKey, kid, "agent-1", "tech", "", "Type admin password", guestSignPriv, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeChatEnvelope(spoofTechEnv, chatKey, kid, "agent-1", techSignPub, nil); err == nil {
		t.Fatal("DecodeChatEnvelope accepted guest spoofing tech")
	}

	// 5. Valid guest message delivered via outer e2e_chat to sidecar -> surfaces as guest chat!
	guestEnv, err := EncodeChatEnvelope(chatKey, kid, "agent-1", "guest", "SpoofedName", "Hello\nfrom Alice", guestSignPriv, 1, &grant, nil)
	if err != nil {
		t.Fatal(err)
	}
	guestFrame, err := json.Marshal(chatTransfer{T: "chat_guest", ShareID: grant.ShareID, Envelope: guestEnv})
	if err != nil {
		t.Fatal(err)
	}
	if err := viewerConn.WriteMessage(websocket.TextMessage, guestFrame); err != nil {
		t.Fatal(err)
	}
	select {
	case synth := <-agentInbound:
		var m struct{ T, From, Name, Text string }
		if err := json.Unmarshal(synth, &m); err != nil {
			t.Fatal(err)
		}
		if m.T != "chat" || m.From != "guest" || m.Name != "Alice" || m.Text != "Hello from Alice" {
			t.Fatalf("sidecar received %+v, want sanitized Alice guest chat", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sidecar did not receive decrypted guest chat")
	}

	// Replaying a previously authenticated group envelope must not deliver it.
	if err := viewerConn.WriteMessage(websocket.TextMessage, guestFrame); err != nil {
		t.Fatal(err)
	}
	marker := `{"t":"kf"}`
	if err := viewerConn.WriteMessage(websocket.TextMessage, []byte(marker)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-agentInbound:
		if string(got) != marker {
			t.Fatal("replayed guest message reached the sidecar")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("legitimate frame after the replay was not delivered")
	}

	// The local user's signed group copy travels inside the peer encryption.
	local := `{"t":"chat","from":"user","text":"Hi Alice!"}`
	if err := agentConn.WriteMessage(websocket.TextMessage, []byte(local)); err != nil {
		t.Fatal(err)
	}
	_ = rawViewer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, data, err := viewerConn.ReadMessage(); err != nil || string(data) != local {
		t.Fatalf("local chat missing: %s %v", data, err)
	}
	_, data, err := viewerConn.ReadMessage()
	var transfer chatTransfer
	if err != nil || json.Unmarshal(data, &transfer) != nil || transfer.T != "chat_group" {
		t.Fatalf("invalid group copy: %v", err)
	}
	verified, err := DecodeChatEnvelope(transfer.Envelope, chatKey, kid, "agent-1", techSignPub, nil)
	if err != nil || verified.From != "user" || verified.Text != "Hi Alice!" {
		t.Fatalf("guest DecodeChatEnvelope(user) = (%+v, %v)", verified, err)
	}
}

func TestHandshakeAgentRequiresBrokeredViewerKey(t *testing.T) {
	wsURL, _ := startPipeServer(t)
	ikPriv, ikPub, _ := GenerateKeyPair()
	_, authorizedPub, _ := GenerateKeyPair()
	otherPriv, _, _ := GenerateKeyPair()
	opts, err := NewAgentHandshakeFromIdentity("session", "device", "terminal", "", authorizedPub, ikPriv, ikPub, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rawAgent, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawAgent.Close()
	rawViewer, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawViewer.Close()

	viewerResult := make(chan error, 1)
	go func() {
		_, err := HandshakeViewer(rawViewer, ViewerHandshakeOpts{
			SessionID: "session", EKPriv: otherPriv, ExpectedIKPub: ikPub, ExpectedAgentID: "device", ExpectedKind: "terminal",
		})
		viewerResult <- err
	}()
	if _, err := HandshakeAgent(rawAgent, opts); err == nil || !strings.Contains(err.Error(), "authorized key") {
		t.Fatalf("endpoint did not reject an unrecognized viewer key: %v", err)
	}
	if err := <-viewerResult; err == nil {
		t.Fatal("unauthorized viewer completed the handshake")
	}
}

func TestAgentHandshakeEnforcesReadLimitBeforeParsing(t *testing.T) {
	wsURL, _ := startPipeServer(t)
	identityPriv, identityPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, viewerPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	opts, err := NewAgentHandshakeFromIdentity("bounded", "agent", "desktop", "", viewerPub, identityPriv, identityPub, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rawAgent, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawAgent.Close()
	rawViewer, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rawViewer.Close()
	if err := rawViewer.WriteMessage(websocket.TextMessage, bytes.Repeat([]byte{' '}, handshakeReadLimit+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := HandshakeAgent(rawAgent, opts); !errors.Is(err, websocket.ErrReadLimit) {
		t.Fatalf("handshake should reject messages at the WebSocket read limit: %v", err)
	}
}
