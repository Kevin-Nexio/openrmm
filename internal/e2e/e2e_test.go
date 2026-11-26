package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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

	// Outbound filter: clipboard, direct chat, and file chunks must never leave a guest's sidecar.
	_ = agentConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"clip","text":"host-secret"}`))
	_ = agentConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"chat","from":"user","text":"not-over-guest-ws"}`))
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

func TestHandshakeValidationGuards(t *testing.T) {
	ikPriv, ikPub, _ := GenerateKeyPair()
	ekPriv, ekPub, _ := GenerateKeyPair()
	exp := time.Now().Add(time.Minute).Unix()
	sig, err := SignDelegation(ikPriv, Delegation{
		SessionID: "sess-guard",
		AgentID:   "agent-guard",
		Kind:      "desktop",
		EKPub:     ekPub,
		Exp:       exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HandshakeAgent(nil, AgentHandshakeOpts{
		SessionID: "sess-guard",
		AgentID:   "agent-guard",
		Kind:      "desktop",
		EKPriv:    ekPriv,
		ViewerKey: "",
		IKPub:     ikPub,
		Exp:       exp,
		SigDel:    sig,
	}); err == nil || !strings.Contains(err.Error(), "authorized viewer key") {
		t.Fatalf("HandshakeAgent accepted missing viewer key before I/O: %v", err)
	}
	if _, err := HandshakeViewer(nil, ViewerHandshakeOpts{
		SessionID: "sess-guard",
		EKPriv:    ekPriv,
	}); err == nil || !strings.Contains(err.Error(), "expected device identity") {
		t.Fatalf("HandshakeViewer accepted empty identity pin and invite fingerprint: %v", err)
	}
}

func TestKeyValidationAndFingerprintsEdgeCases(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rawPub, _, err := DecodePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	// Non-canonical base64 trailing bits: flip an unused low bit in the last char.
	nonCanonPub := pub[:len(pub)-1] + string(pub[len(pub)-1]^1)
	if nonCanonPub == pub {
		nonCanonPub = pub[:len(pub)-1] + "B"
	}
	wrongPrefix := append([]byte(nil), rawPub...)
	wrongPrefix[0] = 0x02
	offCurve := make([]byte, pubKeyRawLen)
	offCurve[0] = 0x04
	offCurve[32] = 0x01
	offCurve[64] = 0x02

	badPubs := []string{
		"",
		"not-base64!!!",
		base64.RawURLEncoding.EncodeToString(rawPub[:64]),
		base64.RawURLEncoding.EncodeToString(wrongPrefix),
		base64.RawURLEncoding.EncodeToString(offCurve),
		nonCanonPub,
	}
	for _, bad := range badPubs {
		if err := ValidatePublicKey(bad); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("ValidatePublicKey(%q) = %v, want ErrInvalidPublicKey", bad, err)
		}
		if fp := DisplayFingerprint(bad); fp != "" {
			t.Errorf("DisplayFingerprint(%q) = %q, want empty", bad, fp)
		}
		if ifp := InviteFingerprint(bad); ifp != "" {
			t.Errorf("InviteFingerprint(%q) = %q, want empty", bad, ifp)
		}
	}

	// Private key validation: wrong length, zero scalar, non-canonical trailing bits.
	zeroPriv := base64.RawURLEncoding.EncodeToString(make([]byte, privKeyRawLen))
	nonCanonPriv := priv[:len(priv)-1] + string(priv[len(priv)-1]^1)
	for _, bad := range []string{"", "!!!", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), zeroPriv, nonCanonPriv} {
		if _, _, err := DecodePrivateKey(bad); !errors.Is(err, ErrInvalidPrivateKey) {
			t.Errorf("DecodePrivateKey(%q) = %v, want ErrInvalidPrivateKey", bad, err)
		}
		if _, err := PublicKeyFromPrivate(bad); err == nil {
			t.Errorf("PublicKeyFromPrivate(%q) succeeded", bad)
		}
		if _, err := SignP256(bad, []byte("msg")); err == nil {
			t.Errorf("SignP256(%q) succeeded", bad)
		}
	}

	// Signature verification guards.
	sig, err := SignP256(priv, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if VerifyP256("bad-key", []byte("hello"), sig) {
		t.Error("VerifyP256 accepted invalid public key")
	}
	if VerifyP256(pub, []byte("hello"), base64.RawURLEncoding.EncodeToString(make([]byte, 63))) {
		t.Error("VerifyP256 accepted short signature")
	}
	nonCanonSig := sig[:len(sig)-1] + string(sig[len(sig)-1]^1)
	if nonCanonSig != sig && VerifyP256(pub, []byte("hello"), nonCanonSig) {
		t.Error("VerifyP256 accepted non-canonical signature encoding")
	}

	// DelegationBytes & DeriveSessionKeys edge cases.
	if _, err := DelegationBytes(Delegation{EKPub: "bad", Exp: 100}); err == nil {
		t.Error("DelegationBytes accepted invalid EKPub")
	}
	if _, err := DelegationBytes(Delegation{EKPub: pub, Exp: -1}); err == nil {
		t.Error("DelegationBytes accepted negative Exp")
	}
	if _, err := DeriveSessionKeys([]byte("short"), [32]byte{}); err == nil {
		t.Error("DeriveSessionKeys accepted short shared secret")
	}
	if NormalizeKind("") != "desktop" || NormalizeKind("terminal") != "terminal" {
		t.Error("NormalizeKind returned unexpected value")
	}

	// IsChatEnvelope validation.
	validEnv, _ := json.Marshal(ChatEnvelope{T: "e2e_chat", V: 1, Kid: "k1", IV: "iv", CT: "ct"})
	if !IsChatEnvelope(validEnv) {
		t.Fatal("IsChatEnvelope rejected valid envelope")
	}
	for name, raw := range map[string][]byte{
		"oversized":   bytes.Repeat([]byte("a"), 8193),
		"invalidJSON": []byte("{bad"),
		"wrongType":   []byte(`{"t":"chat","v":1,"kid":"k","iv":"i","ct":"c"}`),
		"wrongVer":    []byte(`{"t":"e2e_chat","v":2,"kid":"k","iv":"i","ct":"c"}`),
		"missingKid":  []byte(`{"t":"e2e_chat","v":1,"kid":"","iv":"i","ct":"c"}`),
		"missingIV":   []byte(`{"t":"e2e_chat","v":1,"kid":"k","iv":"","ct":"c"}`),
		"missingCT":   []byte(`{"t":"e2e_chat","v":1,"kid":"k","iv":"i","ct":""}`),
	} {
		if IsChatEnvelope(raw) {
			t.Errorf("IsChatEnvelope(%s) = true, want false", name)
		}
	}
}

func TestHandshakeNegativeAndTamperingCases(t *testing.T) {
	ikPriv, ikPub, _ := GenerateKeyPair()
	ekPriv, ekPub, _ := GenerateKeyPair()
	viewPriv, viewPub, _ := GenerateKeyPair()
	exp := time.Now().Add(5 * time.Minute).Unix()
	validSig, err := SignDelegation(ikPriv, Delegation{
		SessionID: "sess-neg",
		AgentID:   "agent-neg",
		Kind:      "desktop",
		EKPub:     ekPub,
		Exp:       exp,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Agent pre-I/O option validation.
	for name, opts := range map[string]AgentHandshakeOpts{
		"empty session": {AgentID: "a", ViewerKey: viewPub, EKPriv: ekPriv, IKPub: ikPub, Exp: exp, SigDel: validSig},
		"expired":       {SessionID: "s", AgentID: "a", ViewerKey: viewPub, EKPriv: ekPriv, IKPub: ikPub, Exp: time.Now().Add(-time.Minute).Unix(), SigDel: validSig},
		"bad guestmode": {SessionID: "s", AgentID: "a", GuestMode: "admin", ViewerKey: viewPub, EKPriv: ekPriv, IKPub: ikPub, Exp: exp, SigDel: validSig},
		"bad ekpriv":    {SessionID: "s", AgentID: "a", ViewerKey: viewPub, EKPriv: "bad", IKPub: ikPub, Exp: exp, SigDel: validSig},
		"bad ikpub":     {SessionID: "s", AgentID: "a", ViewerKey: viewPub, EKPriv: ekPriv, IKPub: "bad", Exp: exp, SigDel: validSig},
		"bad sig len":   {SessionID: "s", AgentID: "a", ViewerKey: viewPub, EKPriv: ekPriv, IKPub: ikPub, Exp: exp, SigDel: "short"},
		"self check":    {SessionID: "wrong-sess", AgentID: "agent-neg", ViewerKey: viewPub, EKPriv: ekPriv, IKPub: ikPub, Exp: exp, SigDel: validSig},
	} {
		if _, err := HandshakeAgent(nil, opts); err == nil {
			t.Errorf("HandshakeAgent(%s) succeeded, want error", name)
		}
	}
	if _, err := NewAgentHandshakeFromIdentity("s", "a", "desktop", "", "bad-viewer", ikPriv, ikPub, 0); err == nil {
		t.Error("NewAgentHandshakeFromIdentity accepted invalid viewer key")
	}

	// Viewer pre-I/O validation.
	if _, err := HandshakeViewer(nil, ViewerHandshakeOpts{EKPriv: viewPriv, ExpectedIKPub: ikPub}); err == nil {
		t.Error("HandshakeViewer accepted empty session_id")
	}
	if _, err := HandshakeViewer(nil, ViewerHandshakeOpts{SessionID: "s", EKPriv: "bad", ExpectedIKPub: ikPub}); err == nil {
		t.Error("HandshakeViewer accepted invalid EKPriv")
	}

	// Wire-level viewer rejection cases against crafted agent hello frames.
	nonce32, _ := RandomBytesB64(32)
	makeAgentHello := func() helloFrame {
		return helloFrame{
			T: "e2e_hello", V: 1, Role: "agent", AgentID: "agent-neg", Kind: "desktop",
			EK: ekPub, Nonce: nonce32, IK: ikPub, Exp: exp, Sig: validSig,
		}
	}
	viewerCases := []struct {
		name   string
		mutate func(*helloFrame)
		opts   ViewerHandshakeOpts
	}{
		{name: "wrong role", mutate: func(h *helloFrame) { h.Role = "viewer" }},
		{name: "wrong kind", mutate: func(h *helloFrame) { h.Kind = "terminal" }},
		{name: "wrong guest_mode", mutate: func(h *helloFrame) { h.GuestMode = "view" }},
		{name: "wrong agent_id", mutate: func(h *helloFrame) { h.AgentID = "other-agent" }},
		{name: "missing agent_id", mutate: func(h *helloFrame) { h.AgentID = "" }},
		{name: "invalid ik", mutate: func(h *helloFrame) { h.IK = "bad" }},
		{name: "wrong invite fp", opts: ViewerHandshakeOpts{ExpectedInviteFP: "AAAAAAAAAAAAAAAAAAAAAA"}},
		{name: "invalid ek", mutate: func(h *helloFrame) { h.EK = "bad" }},
		{name: "invalid nonce", mutate: func(h *helloFrame) { h.Nonce = "short" }},
		{name: "invalid sig len", mutate: func(h *helloFrame) { h.Sig = "short" }},
		{name: "expired delegation", mutate: func(h *helloFrame) { h.Exp = time.Now().Add(-time.Minute).Unix() }},
		{name: "tampered sig", mutate: func(h *helloFrame) {
			raw, _ := base64.RawURLEncoding.DecodeString(h.Sig)
			raw[0] ^= 0xff
			h.Sig = base64.RawURLEncoding.EncodeToString(raw)
		}},
	}
	for _, tc := range viewerCases {
		t.Run("viewer_"+tc.name, func(t *testing.T) {
			wsURL, _ := startPipeServer(t)
			rawPeer, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer rawPeer.Close()
			rawViewer, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer rawViewer.Close()

			h := makeAgentHello()
			if tc.mutate != nil {
				tc.mutate(&h)
			}
			b, _ := json.Marshal(h)
			go func() {
				_, _, _ = rawPeer.ReadMessage()
				_ = rawPeer.WriteMessage(websocket.TextMessage, b)
			}()
			opts := tc.opts
			opts.SessionID = "sess-neg"
			opts.EKPriv = viewPriv
			opts.ExpectedKind = "desktop"
			if opts.ExpectedInviteFP == "" {
				opts.ExpectedAgentID = "agent-neg"
				opts.ExpectedIKPub = ikPub
			}
			if _, err := HandshakeViewer(rawViewer, opts); err == nil {
				t.Fatalf("HandshakeViewer accepted %s", tc.name)
			}
		})
	}

	// Agent rejects bad viewer hello (binary frame, bad nonce, plaintext ready).
	t.Run("agent_rejects_bad_viewer_nonce", func(t *testing.T) {
		wsURL, _ := startPipeServer(t)
		rawAgent, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
		defer rawAgent.Close()
		rawViewer, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
		defer rawViewer.Close()
		agentOpts, _ := NewAgentHandshakeFromIdentity("sess-badnonce", "agent-1", "desktop", "", viewPub, ikPriv, ikPub, 5*time.Minute)
		go func() {
			_, _, _ = rawViewer.ReadMessage()
			b, _ := json.Marshal(helloFrame{T: "e2e_hello", V: 1, Role: "viewer", EK: viewPub, Nonce: "short"})
			_ = rawViewer.WriteMessage(websocket.TextMessage, b)
		}()
		if _, err := HandshakeAgent(rawAgent, agentOpts); err == nil || !strings.Contains(err.Error(), "nonce") {
			t.Fatalf("HandshakeAgent err = %v, want nonce error", err)
		}
	})

	t.Run("agent_rejects_plaintext_ready", func(t *testing.T) {
		wsURL, _ := startPipeServer(t)
		rawAgent, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
		defer rawAgent.Close()
		rawViewer, _, _ := websocket.DefaultDialer.Dial(wsURL, nil)
		defer rawViewer.Close()
		agentOpts, _ := NewAgentHandshakeFromIdentity("sess-plainready", "agent-1", "desktop", "", viewPub, ikPriv, ikPub, 5*time.Minute)
		go func() {
			_, _, _ = rawViewer.ReadMessage()
			b, _ := json.Marshal(helloFrame{T: "e2e_hello", V: 1, Role: "viewer", EK: viewPub, Nonce: nonce32})
			_ = rawViewer.WriteMessage(websocket.TextMessage, b)
			_ = rawViewer.WriteMessage(websocket.TextMessage, []byte(`{"t":"e2e_ready"}`))
		}()
		if _, err := HandshakeAgent(rawAgent, agentOpts); err == nil || !strings.Contains(err.Error(), "e2e_ready") {
			t.Fatalf("HandshakeAgent err = %v, want e2e_ready error", err)
		}
	})
}

func TestConnFrameIntegrityAndLimits(t *testing.T) {
	openPair := func(t *testing.T) (agentConn, viewerConn *Conn, rawAgent, rawViewer *websocket.Conn) {
		t.Helper()
		wsURL, _ := startPipeServer(t)
		ikPriv, ikPub, _ := GenerateKeyPair()
		viewPriv, viewPub, _ := GenerateKeyPair()
		agentOpts, err := NewAgentHandshakeFromIdentity("sess-frame", "agent-1", "desktop", "", viewPub, ikPriv, ikPub, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		rawAgent, _, err = websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rawAgent.Close() })
		rawViewer, _, err = websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { rawViewer.Close() })
		ch := make(chan *Conn, 1)
		go func() {
			c, _ := HandshakeAgent(rawAgent, agentOpts)
			ch <- c
		}()
		viewerConn, err = HandshakeViewer(rawViewer, ViewerHandshakeOpts{
			EKPriv: viewPriv, SessionID: "sess-frame", ExpectedAgentID: "agent-1", ExpectedKind: "desktop", ExpectedIKPub: ikPub,
		})
		if err != nil {
			t.Fatal(err)
		}
		agentConn = <-ch
		if viewerConn.PeerIdentityKey() != ikPub || agentConn.PeerIdentityKey() != ikPub {
			t.Fatalf("PeerIdentityKey mismatch: viewer=%q agent=%q", viewerConn.PeerIdentityKey(), agentConn.PeerIdentityKey())
		}
		return agentConn, viewerConn, rawAgent, rawViewer
	}

	t.Run("oversized_and_unsupported_mt_do_not_desync", func(t *testing.T) {
		agentConn, viewerConn, _, _ := openPair(t)
		if err := viewerConn.WriteMessage(websocket.PingMessage, []byte("x")); err == nil {
			t.Fatal("WriteMessage accepted unsupported PingMessage")
		}
		oversized := make([]byte, maxPayloadSize+1)
		if err := viewerConn.WriteMessage(websocket.BinaryMessage, oversized); err == nil {
			t.Fatal("WriteMessage accepted payload above maxPayloadSize")
		}
		// Sequence number must still be in sync after both rejected writes!
		if err := viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"kf"}`)); err != nil {
			t.Fatal(err)
		}
		mt, got, err := agentConn.ReadMessage()
		if err != nil || mt != websocket.TextMessage || string(got) != `{"t":"kf"}` {
			t.Fatalf("ReadMessage after rejected writes = (%d, %q, %v)", mt, got, err)
		}
		if err := viewerConn.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})

	t.Run("plaintext_text_frame_rejected", func(t *testing.T) {
		agentConn, _, _, rawViewer := openPair(t)
		_ = rawViewer.WriteMessage(websocket.TextMessage, []byte(`{"t":"kf"}`))
		if _, _, err := agentConn.ReadMessage(); err == nil || !strings.Contains(err.Error(), "unexpected websocket message type") {
			t.Fatalf("ReadMessage err = %v, want unexpected websocket message type", err)
		}
	})

	t.Run("tampered_ciphertext_rejected", func(t *testing.T) {
		agentConn, viewerConn, _, rawViewer := openPair(t)
		// Craft a frame with valid header/seq=1 but corrupted GCM tag.
		bad := make([]byte, HeaderSize+1+TagSize)
		bad[0] = FramePrefix
		binary.BigEndian.PutUint64(bad[1:9], 1)
		_ = rawViewer.WriteMessage(websocket.BinaryMessage, bad)
		if _, _, err := agentConn.ReadMessage(); err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("ReadMessage err = %v, want authentication failed", err)
		}
		_ = viewerConn.Close()
	})

	t.Run("out_of_order_sequence_rejected", func(t *testing.T) {
		agentConn, viewerConn, _, _ := openPair(t)
		// Send seq=2 when agent expects seq=1.
		if err := viewerConn.sealAndSend(2, InnerText, []byte(`{"t":"kf"}`)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := agentConn.ReadMessage(); err == nil || !strings.Contains(err.Error(), "sequence mismatch") {
			t.Fatalf("ReadMessage err = %v, want sequence mismatch", err)
		}
	})

	t.Run("unknown_inner_frame_type_rejected", func(t *testing.T) {
		agentConn, viewerConn, _, _ := openPair(t)
		if err := viewerConn.sealAndSend(1, 0x03, []byte("bogus")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := agentConn.ReadMessage(); err == nil || !strings.Contains(err.Error(), "unknown inner frame type") {
			t.Fatalf("ReadMessage err = %v, want unknown inner frame type", err)
		}
	})
}

func TestChatProtocolEdgeCases(t *testing.T) {
	var chatKey [32]byte
	_, _ = io.ReadFull(rand.Reader, chatKey[:])
	var wrongKey [32]byte
	_, _ = io.ReadFull(rand.Reader, wrongKey[:])

	techPriv, techPub, _ := GenerateKeyPair()
	userPriv, userPub, _ := GenerateKeyPair()
	guestECDHPriv, guestECDHPub, _ := GenerateKeyPair()
	otherECDHPriv, _, _ := GenerateKeyPair()
	guestSignPriv, guestSignPub, _ := GenerateKeyPair()
	_, otherPub, _ := GenerateKeyPair()
	kid := "kid-edge"
	agentID := "agent-edge"
	futureExp := time.Now().Add(time.Hour).Unix()

	// UserKeyCert negative checks.
	if _, err := SignUserKeyCert(techPriv, kid, agentID, "bad"); err == nil {
		t.Error("SignUserKeyCert accepted invalid user key")
	}
	userCert, err := SignUserKeyCert(techPriv, kid, agentID, userPub)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyUserKeyCert(techPub, userCert) {
		t.Fatal("VerifyUserKeyCert rejected valid cert")
	}
	if VerifyUserKeyCert(otherPub, userCert) || VerifyUserKeyCert(techPub, UserKeyCert{UserPub: "bad"}) {
		t.Error("VerifyUserKeyCert accepted invalid cert")
	}

	// ChatGrant negative checks.
	if _, err := SignChatGrant(techPriv, ChatGrant{Kid: "", AgentID: agentID, ShareID: "s1", Name: "Alice", GuestSignPub: guestSignPub, Exp: futureExp}); err == nil {
		t.Error("SignChatGrant accepted empty kid")
	}
	if _, err := SignChatGrant(techPriv, ChatGrant{Kid: kid, AgentID: agentID, ShareID: "s1", Name: "Alice", GuestSignPub: "bad", Exp: futureExp}); err == nil {
		t.Error("SignChatGrant accepted bad guest key")
	}
	grant, err := SignChatGrant(techPriv, ChatGrant{Kid: kid, AgentID: agentID, ShareID: "s1", Name: "  Alice\n ", GuestSignPub: guestSignPub, Exp: futureExp})
	if err != nil || grant.Name != "Alice" {
		t.Fatalf("SignChatGrant = (%+v, %v)", grant, err)
	}
	if VerifyChatGrant(techPub, ChatGrant{Kid: kid, AgentID: agentID, ShareID: "s1", Name: "Alice\n", GuestSignPub: guestSignPub, Exp: futureExp, Sig: grant.Sig}) {
		t.Error("VerifyChatGrant accepted uncleaned name")
	}
	if VerifyChatGrant(otherPub, grant) {
		t.Error("VerifyChatGrant accepted wrong tech key")
	}

	// EncodeChatEnvelope error paths.
	if _, err := EncodeChatEnvelope(chatKey, kid, agentID, "tech", "", "   \n\t", techPriv, 1, nil, nil); err == nil {
		t.Error("EncodeChatEnvelope accepted whitespace-only text")
	}
	if _, err := EncodeChatEnvelope(chatKey, kid, agentID, "guest", "", "hi", guestSignPriv, 1, nil, nil); err == nil {
		t.Error("EncodeChatEnvelope accepted guest without grant")
	}
	if _, err := EncodeChatEnvelope(chatKey, kid, agentID, "user", "", "hi", userPriv, 1, nil, nil); err == nil {
		t.Error("EncodeChatEnvelope accepted user without cert")
	}
	if _, err := EncodeChatEnvelope(chatKey, kid, agentID, "admin", "", "hi", techPriv, 1, nil, nil); err == nil {
		t.Error("EncodeChatEnvelope accepted unknown role")
	}
	if _, err := EncodeChatEnvelope(chatKey, kid, agentID, "tech", "", "hi", techPriv, 0, nil, nil); err == nil {
		t.Error("EncodeChatEnvelope accepted seq=0")
	}
	if _, err := EncodeChatEnvelope(chatKey, kid, agentID, "tech", "", "hi", techPriv, maxChatSequence+1, nil, nil); err == nil {
		t.Error("EncodeChatEnvelope accepted seq > maxChatSequence")
	}

	// DecodeChatEnvelope valid + negative paths.
	techEnv, err := EncodeChatEnvelope(chatKey, kid, agentID, "tech", "", "hello tech", techPriv, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msg, err := DecodeChatEnvelope(techEnv, chatKey, kid, agentID, techPub, nil); err != nil || msg.From != "tech" || msg.Text != "hello tech" {
		t.Fatalf("DecodeChatEnvelope(tech) = (%+v, %v)", msg, err)
	}
	if _, err := DecodeChatEnvelope(bytes.Repeat([]byte("a"), 8193), chatKey, kid, agentID, techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted oversized envelope")
	}
	if _, err := DecodeChatEnvelope(techEnv, wrongKey, kid, agentID, techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted wrong chat key")
	}
	if _, err := DecodeChatEnvelope(techEnv, chatKey, "other-kid", agentID, techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted wrong kid")
	}
	if _, err := DecodeChatEnvelope(techEnv, chatKey, kid, "other-agent", techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted wrong agentID AAD")
	}
	if _, err := DecodeChatEnvelope([]byte(`{"t":"e2e_chat","v":1,"kid":"kid-edge","iv":"short","ct":"short"}`), chatKey, kid, agentID, techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted invalid IV")
	}
	if _, err := DecodeChatEnvelope([]byte(`{"t":"e2e_chat","v":1,"kid":"kid-edge","iv":"AAAAAAAAAAAAAAAA","ct":"short"}`), chatKey, kid, agentID, techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted short CT")
	}

	// User chat errors: wrong cert signature / wrong user signature.
	badUserEnv, err := EncodeChatEnvelope(chatKey, kid, agentID, "user", "", "hello user", guestSignPriv, 1, nil, &userCert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeChatEnvelope(badUserEnv, chatKey, kid, agentID, techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted user message signed by wrong key")
	}
	if _, err := DecodeChatEnvelope(badUserEnv, chatKey, kid, agentID, otherPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted user_cert signed by wrong tech key")
	}

	// Guest chat errors: revoked, expired grant, wrong key.
	guestEnv, err := EncodeChatEnvelope(chatKey, kid, agentID, "guest", "", "hello guest", guestSignPriv, 1, &grant, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeChatEnvelope(guestEnv, chatKey, kid, agentID, techPub, map[string]bool{"s1": true}); err == nil {
		t.Error("DecodeChatEnvelope accepted revoked guest")
	}
	expiredGrant, err := SignChatGrant(techPriv, ChatGrant{Kid: kid, AgentID: agentID, ShareID: "s1", Name: "Alice", GuestSignPub: guestSignPub, Exp: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	expEnv, _ := EncodeChatEnvelope(chatKey, kid, agentID, "guest", "", "late", guestSignPriv, 1, &expiredGrant, nil)
	if _, err := DecodeChatEnvelope(expEnv, chatKey, kid, agentID, techPub, nil); err == nil {
		t.Error("DecodeChatEnvelope accepted expired guest grant")
	}

	// OpenChatKeyAsGuest error paths.
	wrapped, err := SealChatKeyForGuest(guestECDHPub, WrappedGuestChatKey{
		Kid: kid, K: base64.RawURLEncoding.EncodeToString(chatKey[:]), TechPub: techPub,
		AgentID: agentID, ShareID: "s1", Name: "Alice", Exp: futureExp, Grant: grant, DevIK: otherPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenChatKeyAsGuest("bad-priv", wrapped); err == nil {
		t.Error("OpenChatKeyAsGuest accepted bad private key")
	}
	if _, err := OpenChatKeyAsGuest(otherECDHPriv, wrapped); err == nil {
		t.Error("OpenChatKeyAsGuest succeeded with wrong guest private key")
	}
	if _, err := OpenChatKeyAsGuest(guestECDHPriv, "!!!not-base64"); err == nil {
		t.Error("OpenChatKeyAsGuest accepted bad base64")
	}
	tamperedGrant := grant
	tamperedGrant.Name = "Mallory"
	badGrantWrap, err := SealChatKeyForGuest(guestECDHPub, WrappedGuestChatKey{
		Kid: kid, K: base64.RawURLEncoding.EncodeToString(chatKey[:]), TechPub: techPub,
		AgentID: agentID, ShareID: "s1", Name: "Mallory", Exp: futureExp, Grant: tamperedGrant, DevIK: otherPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenChatKeyAsGuest(guestECDHPriv, badGrantWrap); err == nil {
		t.Error("OpenChatKeyAsGuest accepted tampered grant inside wrapped key")
	}

	// agentChatBridge HandleControl (invalid init, revoke, maxChatSenders cap).
	bridge := newAgentChatBridge(agentID)
	if _, ok := bridge.MaybeEncodeUserChat([]byte(`{"t":"chat","from":"user","text":"too early"}`)); ok {
		t.Error("MaybeEncodeUserChat encoded before chat_init")
	}
	// Invalid chat_init frames are consumed (handled=true) without emitting ack.
	for _, raw := range []string{
		`{"t":"chat_init","kid":"","k":"x","tech_pub":"y"}`,
		`{"t":"chat_init","kid":"k","k":"short","tech_pub":"y"}`,
	} {
		handled, reply := bridge.HandleControl([]byte(raw))
		if !handled || len(reply) != 0 {
			t.Errorf("HandleControl(%s) = (%v, %q), want (true, empty)", raw, handled, reply)
		}
	}
	// Valid init -> revoke -> DecodeGuestEnvelope rejects revoked share.
	initRaw, _ := json.Marshal(map[string]string{
		"t": "chat_init", "kid": kid, "k": base64.RawURLEncoding.EncodeToString(chatKey[:]), "tech_pub": techPub,
	})
	handled, ack := bridge.HandleControl(initRaw)
	if !handled || len(ack) == 0 {
		t.Fatalf("HandleControl(valid chat_init) = (%v, %q)", handled, ack)
	}
	// Mismatched chat_user_cert is ignored.
	badCertRaw, _ := json.Marshal(map[string]any{"t": "chat_user_cert", "kid": "wrong", "cert": userCert})
	bridge.HandleControl(badCertRaw)
	if _, ok := bridge.MaybeEncodeUserChat([]byte(`{"t":"chat","from":"user","text":"still uncertified"}`)); ok {
		t.Error("MaybeEncodeUserChat encoded with mismatched cert")
	}
	// Revoke s1 -> guest envelope from s1 is dropped.
	bridge.HandleControl([]byte(`{"t":"chat_revoke","share_id":"s1"}`))
	if _, ok := bridge.DecodeGuestEnvelope(guestEnv, "s1"); ok {
		t.Error("DecodeGuestEnvelope accepted revoked share after chat_revoke")
	}

	// Sender cap: fill up to maxChatSenders distinct senders, then verify 257th is rejected.
	bridge2 := newAgentChatBridge(agentID)
	bridge2.HandleControl(initRaw)
	for i := 0; i < maxChatSenders; i++ {
		bridge2.seen[fmt.Sprintf("sender-%d", i)] = 1
	}
	if _, ok := bridge2.DecodeGuestEnvelope(guestEnv, "s1"); ok {
		t.Error("DecodeGuestEnvelope exceeded maxChatSenders cap")
	}
}

func TestGuestControlModeAllowlist(t *testing.T) {
	wsURL, _ := startPipeServer(t)
	ikPriv, ikPub, _ := GenerateKeyPair()
	viewPriv, viewPub, _ := GenerateKeyPair()
	agentOpts, _ := NewAgentHandshakeFromIdentity("sess-ctrl", "agent-1", "desktop", "control", viewPub, ikPriv, ikPub, 5*time.Minute)

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
		EKPriv: viewPriv, SessionID: "sess-ctrl", ExpectedKind: "desktop", ExpectedGuestMode: "control", ExpectedInviteFP: InviteFingerprint(ikPub),
	})
	if err != nil {
		t.Fatal(err)
	}
	agentConn := <-agentCh

	// Control guest can send mouse/keyboard/wheel/kf/mon, but NOT cad/clip/fls/chat/oversized.
	_ = viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"cad"}`))
	_ = viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"clip","text":"nope"}`))
	_ = viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"fls","path":"/"}`))
	_ = viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"k","code":65,"down":true,"pad":"`+strings.Repeat("a", guestInnerLimit)+`"}`))
	_ = viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"k","code":65,"down":true}`))
	_ = viewerConn.WriteMessage(websocket.TextMessage, []byte(`{"t":"m","x":0.5,"y":0.5}`))

	_, got1, err := agentConn.ReadMessage()
	if err != nil || string(got1) != `{"t":"k","code":65,"down":true}` {
		t.Fatalf("got1 = (%q, %v), want key event", got1, err)
	}
	_, got2, err := agentConn.ReadMessage()
	if err != nil || string(got2) != `{"t":"m","x":0.5,"y":0.5}` {
		t.Fatalf("got2 = (%q, %v), want mouse move", got2, err)
	}

	// Outbound video frame (0x01) is allowed; file chunk (0x02) is dropped.
	_ = agentConn.WriteMessage(websocket.BinaryMessage, []byte{0x02, 0x01, 0x99})
	_ = agentConn.WriteMessage(websocket.BinaryMessage, []byte{chVideo, 0x01, 0x02, 0x03})
	mt, gotBin, err := viewerConn.ReadMessage()
	if err != nil || mt != websocket.BinaryMessage || !bytes.Equal(gotBin, []byte{chVideo, 0x01, 0x02, 0x03}) {
		t.Fatalf("guest outbound binary = (%d, %x, %v)", mt, gotBin, err)
	}
}
