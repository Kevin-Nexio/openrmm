package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/p1ngu/rmm/internal/ai"
	"github.com/p1ngu/rmm/internal/auth"
	"github.com/p1ngu/rmm/internal/config"
	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/hub"
	"github.com/p1ngu/rmm/internal/jobs"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/protocol"
	"github.com/p1ngu/rmm/internal/remote"
	"github.com/p1ngu/rmm/internal/store"
)

// TestRemoteE2EFullLifecycle exercises the complete server-side PR #313 flow
// against a real PostgreSQL database, real /ws/agent and /ws/remote WebSockets,
// real e2e.HandshakeAgent/HandshakeViewer, and the authenticated encrypted chat
// HTTP APIs (including key pinning, keyless-reconnect refusal, policy switching,
// E2E guest invitations, 3-party encrypted chat, key rotation, and immediate
// room suspension on guest removal).
func TestRemoteE2EFullLifecycle(t *testing.T) {
	dbURL := os.Getenv("RMM_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	st := newTestStore(t, dbURL)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	tech, err := st.CreateUser(ctx, "e2e-tech-"+uuid.NewString()[:8], "hash", models.RoleAdmin)
	must(err)
	techToken := auth.NewToken()
	must(st.CreateSession(ctx, tech.ID, auth.Hash(techToken), time.Now().Add(time.Hour)))
	asTech := "Bearer " + techToken

	enrollTok := "enroll-" + uuid.NewString()
	_, err = st.CreateEnrollToken(ctx, enrollTok, "e2e-lifecycle", 10, nil, nil, nil, tech.ID)
	must(err)

	h := hub.New()
	cfg := &config.Config{APIRateLimit: 100000, RemoteE2EPolicy: "preferred"}
	rm := remote.NewManager(st, h, "", "", "", false, false)
	chatEngine := ai.NewEngine(ai.NewClient("", "", ""), st, nil, nil, cfg)
	srv := New(cfg, st, h, jobs.New(st, h), rm, remote.NewRelay(), chatEngine, nil, nil)

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	wsBase := "ws" + strings.TrimPrefix(ts.URL, "http")

	httpCall := func(method, path, authz string, body any) (int, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, err := json.Marshal(body)
			must(err)
			rdr = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, ts.URL+path, rdr)
		must(err)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		must(err)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		must(err)
		return resp.StatusCode, raw
	}

	registerWS := func(req protocol.RegisterReq) (*websocket.Conn, protocol.Envelope) {
		t.Helper()
		c, _, err := websocket.DefaultDialer.Dial(wsBase+"/ws/agent", nil)
		must(err)
		data, _ := json.Marshal(req)
		frame, _ := json.Marshal(protocol.Envelope{Type: protocol.MsgRegister, Data: data})
		must(c.WriteMessage(websocket.TextMessage, frame))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, raw, err := c.ReadMessage()
		must(err)
		_ = c.SetReadDeadline(time.Time{})
		var env protocol.Envelope
		must(json.Unmarshal(raw, &env))
		return c, env
	}

	// ---- 1. Agent E2E enrollment, key pinning, and anti-downgrade reconnects ----
	ikPriv, ikPub, err := e2e.GenerateKeyPair()
	must(err)
	_, roguePub, err := e2e.GenerateKeyPair()
	must(err)

	c1, regEnv := registerWS(protocol.RegisterReq{
		EnrollToken:     enrollTok,
		Hostname:        "e2e-host-" + uuid.NewString()[:6],
		OS:              "linux",
		Arch:            "amd64",
		Version:         "0.13.0",
		DevicePublicKey: ikPub,
	})
	if regEnv.Type != protocol.MsgRegistered {
		t.Fatalf("E2E agent enrollment failed: %s %s", regEnv.Type, regEnv.Data)
	}
	var regResp protocol.RegisterResp
	must(json.Unmarshal(regEnv.Data, &regResp))
	pinnedID, pinnedTok := regResp.AgentID, regResp.AgentToken
	_ = c1.Close()

	// Verify device.e2e_key_pinned audit record.
	auditEntries, _, err := st.ListAudit(ctx, store.AuditFilter{Action: "device.e2e_key_pinned", Target: pinnedID, Limit: 5})
	must(err)
	if len(auditEntries) == 0 {
		t.Fatal("expected device.e2e_key_pinned audit entry on enrollment")
	}

	// Reconnect with mismatched key -> refused!
	cBadKey, badKeyEnv := registerWS(protocol.RegisterReq{
		AgentID: pinnedID, AgentToken: pinnedTok, Hostname: "e2e-host", OS: "linux", Arch: "amd64", Version: "0.13.0",
		DevicePublicKey: roguePub,
	})
	_ = cBadKey.Close()
	if badKeyEnv.Type != protocol.MsgError {
		t.Fatalf("mismatched public key reconnect was accepted: %s %s", badKeyEnv.Type, badKeyEnv.Data)
	}

	// Reconnect with empty key (keyless downgrade attack) -> refused!
	cKeyless, keylessEnv := registerWS(protocol.RegisterReq{
		AgentID: pinnedID, AgentToken: pinnedTok, Hostname: "e2e-host", OS: "linux", Arch: "amd64", Version: "0.13.0",
	})
	_ = cKeyless.Close()
	if keylessEnv.Type != protocol.MsgError {
		t.Fatalf("keyless reconnect on pinned device was accepted: %s %s", keylessEnv.Type, keylessEnv.Data)
	}

	// Reconnect with matching key -> stays online for the rest of the test!
	agentControlWS, okEnv := registerWS(protocol.RegisterReq{
		AgentID: pinnedID, AgentToken: pinnedTok, Hostname: "e2e-host", OS: "linux", Arch: "amd64", Version: "0.13.0",
		DevicePublicKey: ikPub,
	})
	defer agentControlWS.Close()
	if okEnv.Type != protocol.MsgRegistered {
		t.Fatalf("matching key reconnect failed: %s %s", okEnv.Type, okEnv.Data)
	}

	// Also enroll a legacy unpinned agent to verify policy transitions.
	legacyWS, legEnv := registerWS(protocol.RegisterReq{
		EnrollToken: enrollTok, Hostname: "legacy-host-" + uuid.NewString()[:6], OS: "linux", Arch: "amd64", Version: "0.12.0",
	})
	defer legacyWS.Close()
	if legEnv.Type != protocol.MsgRegistered {
		t.Fatalf("legacy enrollment failed: %s %s", legEnv.Type, legEnv.Data)
	}
	var legResp protocol.RegisterResp
	must(json.Unmarshal(legEnv.Data, &legResp))
	legacyID := legResp.AgentID

	// ---- 2. Policy enforcement & E2E session brokering ----
	code, body := httpCall(http.MethodPost, "/api/devices/"+legacyID+"/remote", asTech, map[string]any{"provider": "native"})
	if code != http.StatusCreated || !strings.Contains(string(body), `"e2e":false`) {
		t.Fatalf("legacy start under preferred: %d %s", code, body)
	}

	// Switch to e2e_policy=required + guest_access=true via PUT /api/config.
	code, body = httpCall(http.MethodPut, "/api/config", asTech, map[string]any{
		"remote": map[string]any{"e2e_policy": "required", "guest_access": true},
	})
	if code != http.StatusOK {
		t.Fatalf("PUT /api/config: %d %s", code, body)
	}
	code, body = httpCall(http.MethodPost, "/api/devices/"+legacyID+"/remote", asTech, map[string]any{"provider": "native"})
	if code != http.StatusConflict || !strings.Contains(string(body), "remote_agent_update_required") {
		t.Fatalf("legacy start under required: %d %s, want 409 remote_agent_update_required", code, body)
	}

	// Pinned device rejects missing or invalid viewer_key.
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote", asTech, map[string]any{"provider": "native"})
	if code != http.StatusBadRequest || !strings.Contains(string(body), "remote_e2e_required") {
		t.Fatalf("pinned start without viewer_key: %d %s", code, body)
	}
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote", asTech, map[string]any{"provider": "native", "viewer_key": "bad"})
	if code != http.StatusBadRequest {
		t.Fatalf("pinned start with bad viewer_key: %d %s", code, body)
	}

	techViewPriv, techViewPub, err := e2e.GenerateKeyPair()
	must(err)
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote", asTech, map[string]any{
		"provider": "native", "viewer_key": techViewPub,
	})
	if code != http.StatusCreated {
		t.Fatalf("pinned E2E start: %d %s", code, body)
	}
	var techSess struct {
		ID           string `json:"id"`
		ViewerTicket string `json:"viewer_ticket"`
		E2E          bool   `json:"e2e"`
		DevicePubKey string `json:"device_public_key"`
	}
	must(json.Unmarshal(body, &techSess))
	if !techSess.E2E || techSess.DevicePubKey != ikPub {
		t.Fatalf("unexpected E2E session response: %+v", techSess)
	}

	readRemoteStart := func() protocol.RemoteStartMsg {
		t.Helper()
		_ = agentControlWS.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer agentControlWS.SetReadDeadline(time.Time{})
		for {
			_, raw, err := agentControlWS.ReadMessage()
			must(err)
			var env protocol.Envelope
			must(json.Unmarshal(raw, &env))
			if env.Type == protocol.MsgRemoteStart {
				var rs protocol.RemoteStartMsg
				must(json.Unmarshal(env.Data, &rs))
				return rs
			}
		}
	}

	techStart := readRemoteStart()
	if !techStart.E2E || techStart.ViewerKey != techViewPub || techStart.SessionID != techSess.ID {
		t.Fatalf("agent got unexpected tech start: %+v", techStart)
	}

	// ---- 3. Real /ws/remote E2E handshake for technician ----
	dialRelayViewer := func(sessionID, ticket, authProto string) *websocket.Conn {
		t.Helper()
		d := *websocket.DefaultDialer
		d.Subprotocols = []string{relaySubprotocol, "rmm-ticket." + ticket, authProto}
		hdr := http.Header{"Origin": []string{ts.URL}}
		c, _, err := d.Dial(wsBase+"/ws/remote?session="+sessionID+"&role=viewer", hdr)
		must(err)
		return c
	}
	dialRelayAgent := func(sessionID, ticket string) *websocket.Conn {
		t.Helper()
		hdr := http.Header{"Authorization": []string{"Remote-Agent " + ticket}}
		c, _, err := websocket.DefaultDialer.Dial(wsBase+"/ws/remote?session="+sessionID+"&role=agent", hdr)
		must(err)
		return c
	}

	rawTechViewer := dialRelayViewer(techSess.ID, techSess.ViewerTicket, "rmm-auth."+techToken)
	defer rawTechViewer.Close()
	rawTechSidecar := dialRelayAgent(techSess.ID, techStart.AgentTicket)
	defer rawTechSidecar.Close()

	techAgentOpts, err := e2e.NewAgentHandshakeFromIdentity(techSess.ID, pinnedID, "desktop", "", techViewPub, ikPriv, ikPub, 5*time.Minute)
	must(err)
	sidecarCh := make(chan *e2e.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, herr := e2e.HandshakeAgent(rawTechSidecar, techAgentOpts)
		if herr != nil {
			errCh <- herr
			return
		}
		sidecarCh <- c
	}()
	techE2E, err := e2e.HandshakeViewer(rawTechViewer, e2e.ViewerHandshakeOpts{
		SessionID: techSess.ID, EKPriv: techViewPriv, ExpectedAgentID: pinnedID, ExpectedKind: "desktop", ExpectedIKPub: ikPub,
	})
	must(err)
	var techSidecarE2E *e2e.Conn
	select {
	case techSidecarE2E = <-sidecarCh:
	case herr := <-errCh:
		t.Fatalf("tech HandshakeAgent: %v", herr)
	}

	// Background sidecar reader (simulating cmd/rmm-remote media loop).
	sidecarIn := make(chan []byte, 16)
	go func() {
		for {
			_, data, rerr := techSidecarE2E.ReadMessage()
			if rerr != nil {
				return
			}
			sidecarIn <- data
		}
	}()

	// ---- 4. Encrypted guest share + multi-party group chat + rotation + removal ----
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-shares", asTech, map[string]any{"mode": "view", "minutes": 60})
	if code != http.StatusCreated {
		t.Fatalf("create E2E share: %d %s", code, body)
	}
	var shareCreated struct {
		Share        models.RemoteShare `json:"share"`
		Token        string             `json:"token"`
		Code         string             `json:"code"`
		DevicePubKey string             `json:"device_public_key"`
	}
	must(json.Unmarshal(body, &shareCreated))
	if shareCreated.DevicePubKey != ikPub {
		t.Fatalf("share create returned device_public_key=%q, want %q", shareCreated.DevicePubKey, ikPub)
	}

	aliceECDHPriv, aliceECDHPub, err := e2e.GenerateKeyPair()
	must(err)
	aliceSignPriv, aliceSignPub, err := e2e.GenerateKeyPair()
	must(err)

	// Guest join must supply both E2E public keys together and valid keys.
	code, _ = httpCall(http.MethodPost, "/api/guest/join", "", map[string]any{
		"token": shareCreated.Token, "code": shareCreated.Code, "name": "Alice", "guest_public_key": aliceECDHPub,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("guest join with single key: got %d, want 400", code)
	}
	code, body = httpCall(http.MethodPost, "/api/guest/join", "", map[string]any{
		"token": shareCreated.Token, "code": shareCreated.Code, "name": "Alice",
		"guest_public_key": aliceECDHPub, "guest_sign_key": aliceSignPub,
	})
	if code != http.StatusOK {
		t.Fatalf("guest E2E join: %d %s", code, body)
	}
	var guestJoined struct {
		RequestID  string `json:"request_id"`
		Credential string `json:"guest_credential"`
	}
	must(json.Unmarshal(body, &guestJoined))
	asAlice := "Guest " + guestJoined.Credential

	// Accept requires wrapped_chat_key + matching redeem_count.
	code, _ = httpCall(http.MethodPost, "/api/remote-shares/"+shareCreated.Share.ID+"/accept", asTech, nil)
	if code != http.StatusBadRequest {
		t.Fatalf("accept E2E guest without wrapped key: %d, want 400", code)
	}
	var chatKey1 [32]byte
	_, _ = io.ReadFull(rand.Reader, chatKey1[:])
	techSignPriv, techSignPub, err := e2e.GenerateKeyPair()
	must(err)
	const kid1 = "kid-epoch-1"
	grant1, err := e2e.SignChatGrant(techSignPriv, e2e.ChatGrant{
		Kid: kid1, AgentID: pinnedID, ShareID: shareCreated.Share.ID, Name: "Alice",
		GuestSignPub: aliceSignPub, Exp: shareCreated.Share.ExpiresAt.Unix(),
	})
	must(err)
	wrapped1, err := e2e.SealChatKeyForGuest(aliceECDHPub, e2e.WrappedGuestChatKey{
		Kid: kid1, K: base64.RawURLEncoding.EncodeToString(chatKey1[:]), TechPub: techSignPub,
		AgentID: pinnedID, ShareID: shareCreated.Share.ID, Name: "Alice",
		Exp: shareCreated.Share.ExpiresAt.Unix(), Grant: grant1, DevIK: ikPub,
	})
	must(err)

	code, _ = httpCall(http.MethodPost, "/api/remote-shares/"+shareCreated.Share.ID+"/accept", asTech, map[string]any{
		"wrapped_chat_key": wrapped1, "chat_key_id": kid1, "redeem_count": 99,
	})
	if code != http.StatusConflict {
		t.Fatalf("accept with stale redeem_count: %d, want 409", code)
	}
	code, body = httpCall(http.MethodPost, "/api/remote-shares/"+shareCreated.Share.ID+"/accept", asTech, map[string]any{
		"wrapped_chat_key": wrapped1, "chat_key_id": kid1, "redeem_count": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("accept E2E guest: %d %s", code, body)
	}

	// Initialize sidecar chat bridge (chat_init -> chat_init_ack -> chat_user_cert) over encrypted WS!
	chatInit, _ := json.Marshal(map[string]string{
		"t": "chat_init", "kid": kid1, "k": base64.RawURLEncoding.EncodeToString(chatKey1[:]), "tech_pub": techSignPub,
	})
	must(techE2E.WriteMessage(websocket.TextMessage, chatInit))
	_ = rawTechViewer.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, ackRaw, err := techE2E.ReadMessage()
	must(err)
	var ack struct {
		T       string `json:"t"`
		Kid     string `json:"kid"`
		UserPub string `json:"user_pub"`
	}
	must(json.Unmarshal(ackRaw, &ack))
	if ack.T != "chat_init_ack" || ack.Kid != kid1 {
		t.Fatalf("unexpected chat_init_ack: %s", ackRaw)
	}
	userCert, err := e2e.SignUserKeyCert(techSignPriv, kid1, pinnedID, ack.UserPub)
	must(err)
	certFrame, _ := json.Marshal(map[string]any{"t": "chat_user_cert", "kid": kid1, "cert": userCert})
	must(techE2E.WriteMessage(websocket.TextMessage, certFrame))

	// Guest brokers an E2E session (without viewer_key -> 400; with viewer_key -> 201).
	code, body = httpCall(http.MethodPost, "/api/guest/session", asAlice, nil)
	if code != http.StatusBadRequest || !strings.Contains(string(body), "remote_e2e_required") {
		t.Fatalf("guest session without viewer_key: %d %s", code, body)
	}
	aliceViewPriv, aliceViewPub, err := e2e.GenerateKeyPair()
	must(err)
	code, body = httpCall(http.MethodPost, "/api/guest/session", asAlice, map[string]any{"viewer_key": aliceViewPub})
	if code != http.StatusCreated {
		t.Fatalf("guest E2E session: %d %s", code, body)
	}
	var guestSess struct {
		ID           string `json:"id"`
		ViewerTicket string `json:"viewer_ticket"`
		E2E          bool   `json:"e2e"`
	}
	must(json.Unmarshal(body, &guestSess))
	if !guestSess.E2E {
		t.Fatal("guest session did not set e2e=true")
	}
	guestStart := readRemoteStart()
	if !guestStart.E2E || guestStart.GuestMode != "view" || !guestStart.NoChat || guestStart.AllowFiles == nil || *guestStart.AllowFiles || guestStart.ViewerKey != aliceViewPub {
		t.Fatalf("unexpected guest remote_start: %+v", guestStart)
	}

	// Complete real /ws/remote E2E handshake for guest using ExpectedInviteFP.
	rawAliceViewer := dialRelayViewer(guestSess.ID, guestSess.ViewerTicket, "rmm-guest."+guestJoined.Credential)
	defer rawAliceViewer.Close()
	rawAliceSidecar := dialRelayAgent(guestSess.ID, guestStart.AgentTicket)
	defer rawAliceSidecar.Close()

	guestAgentOpts, err := e2e.NewAgentHandshakeFromIdentity(guestSess.ID, pinnedID, "desktop", "view", aliceViewPub, ikPriv, ikPub, 5*time.Minute)
	must(err)
	gSidecarCh := make(chan *e2e.Conn, 1)
	go func() {
		c, herr := e2e.HandshakeAgent(rawAliceSidecar, guestAgentOpts)
		if herr != nil {
			errCh <- herr
			return
		}
		gSidecarCh <- c
	}()
	aliceE2E, err := e2e.HandshakeViewer(rawAliceViewer, e2e.ViewerHandshakeOpts{
		SessionID: guestSess.ID, EKPriv: aliceViewPriv, ExpectedKind: "desktop", ExpectedGuestMode: "view",
		ExpectedInviteFP: e2e.InviteFingerprint(ikPub),
	})
	must(err)
	defer aliceE2E.Close()
	var aliceSidecarE2E *e2e.Conn
	select {
	case aliceSidecarE2E = <-gSidecarCh:
	case herr := <-errCh:
		t.Fatalf("guest HandshakeAgent: %v", herr)
	}
	// View-only guest cannot inject a keystroke; only kf reaches sidecar.
	must(aliceE2E.WriteMessage(websocket.TextMessage, []byte(`{"t":"k","code":65,"down":true}`)))
	must(aliceE2E.WriteMessage(websocket.TextMessage, []byte(`{"t":"kf"}`)))
	_ = rawAliceSidecar.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, gotGuestFrame, err := aliceSidecarE2E.ReadMessage()
	must(err)
	if string(gotGuestFrame) != `{"t":"kf"}` {
		t.Fatalf("view-only guest got %q on sidecar, want kf only", gotGuestFrame)
	}

	// ---- 5. Authenticated encrypted 3-party group chat over HTTP API ----
	// Invalid source rejected with 400.
	code, _ = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-chat", asTech, map[string]any{
		"session_id": techSess.ID, "kid": kid1, "cursor": 0, "generation": 1, "source": "guest",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("invalid source on tech remote-chat: %d, want 400", code)
	}

	// Technician activates epoch 1 and posts encrypted tech message.
	techEnv, err := e2e.EncodeChatEnvelope(chatKey1, kid1, pinnedID, "tech", "", "Hello from tech", techSignPriv, 1, nil, nil)
	must(err)
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-chat", asTech, map[string]any{
		"session_id": techSess.ID, "kid": kid1, "cursor": 0, "generation": 1, "envelope": json.RawMessage(techEnv),
	})
	if code != http.StatusOK {
		t.Fatalf("tech remote-chat post: %d %s", code, body)
	}

	// Alice fetches wrapped key from /api/guest/request, unwraps, and polls /api/guest/chat.
	code, body = httpCall(http.MethodGet, "/api/guest/request", asAlice, nil)
	if code != http.StatusOK {
		t.Fatalf("guest request: %d %s", code, body)
	}
	var reqStatus struct {
		WrappedChatKey string `json:"wrapped_chat_key"`
		ChatKeyID      string `json:"chat_key_id"`
	}
	must(json.Unmarshal(body, &reqStatus))
	unwrapped, err := e2e.OpenChatKeyAsGuest(aliceECDHPriv, reqStatus.WrappedChatKey)
	must(err)
	if unwrapped.Kid != kid1 || unwrapped.Grant.Name != "Alice" {
		t.Fatalf("unwrapped guest key mismatch: %+v", unwrapped)
	}

	code, body = httpCall(http.MethodPost, "/api/guest/chat", asAlice, map[string]any{
		"session_id": guestSess.ID, "kid": kid1, "cursor": 0,
	})
	if code != http.StatusOK {
		t.Fatalf("guest chat poll: %d %s", code, body)
	}
	var chatResp struct {
		Lines []remoteChatLine `json:"lines"`
	}
	must(json.Unmarshal(body, &chatResp))
	if len(chatResp.Lines) != 1 || chatResp.Lines[0].From != "tech" {
		t.Fatalf("guest poll lines = %+v, want 1 tech line", chatResp.Lines)
	}
	decTech, err := e2e.DecodeChatEnvelope(chatResp.Lines[0].Envelope, chatKey1, kid1, pinnedID, techSignPub, nil)
	must(err)
	if decTech.From != "tech" || decTech.Text != "Hello from tech" {
		t.Fatalf("decrypted tech line = %+v", decTech)
	}

	// Alice replies via /api/guest/chat; immediate second send hits 429 too_soon!
	aliceEnv1, err := e2e.EncodeChatEnvelope(chatKey1, kid1, pinnedID, "guest", "", "Hello from Alice", aliceSignPriv, 1, &grant1, nil)
	must(err)
	code, body = httpCall(http.MethodPost, "/api/guest/chat", asAlice, map[string]any{
		"session_id": guestSess.ID, "kid": kid1, "cursor": 1, "envelope": json.RawMessage(aliceEnv1),
	})
	if code != http.StatusOK {
		t.Fatalf("guest chat send: %d %s", code, body)
	}
	aliceEnv2, err := e2e.EncodeChatEnvelope(chatKey1, kid1, pinnedID, "guest", "", "Too fast", aliceSignPriv, 2, &grant1, nil)
	must(err)
	code, body = httpCall(http.MethodPost, "/api/guest/chat", asAlice, map[string]any{
		"session_id": guestSess.ID, "kid": kid1, "cursor": 2, "envelope": json.RawMessage(aliceEnv2),
	})
	if code != http.StatusTooManyRequests || !strings.Contains(string(body), "too_soon") {
		t.Fatalf("rapid guest chat send = %d %s, want 429 too_soon", code, body)
	}

	// Technician polls, receives Alice's envelope, and bridges it to sidecar via chat_guest.
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-chat", asTech, map[string]any{
		"session_id": techSess.ID, "kid": kid1, "cursor": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("tech poll for guest line: %d %s", code, body)
	}
	must(json.Unmarshal(body, &chatResp))
	if len(chatResp.Lines) != 1 || chatResp.Lines[0].From != "guest" || chatResp.Lines[0].ShareID != shareCreated.Share.ID {
		t.Fatalf("tech poll lines = %+v", chatResp.Lines)
	}
	bridgeFrame, _ := json.Marshal(map[string]any{"t": "chat_guest", "share_id": shareCreated.Share.ID, "envelope": chatResp.Lines[0].Envelope})
	must(techE2E.WriteMessage(websocket.TextMessage, bridgeFrame))
	select {
	case synth := <-sidecarIn:
		if !strings.Contains(string(synth), `"from":"guest"`) || !strings.Contains(string(synth), "Hello from Alice") {
			t.Fatalf("sidecar received unexpected bridged chat: %s", synth)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sidecar did not receive bridged guest chat")
	}

	// Local endpoint user sends a chat line -> sidecar emits chat_group -> tech relays with source="user" -> Alice decrypts!
	must(techSidecarE2E.WriteMessage(websocket.TextMessage, []byte(`{"t":"chat","from":"user","text":"Hi from endpoint"}`)))
	_ = rawTechViewer.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err = techE2E.ReadMessage() // local {"t":"chat","from":"user",...}
	must(err)
	_, grpRaw, err := techE2E.ReadMessage()
	must(err)
	var grp struct {
		T        string          `json:"t"`
		Envelope json.RawMessage `json:"envelope"`
	}
	must(json.Unmarshal(grpRaw, &grp))
	if grp.T != "chat_group" {
		t.Fatalf("expected chat_group from sidecar, got %s", grpRaw)
	}
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-chat", asTech, map[string]any{
		"session_id": techSess.ID, "kid": kid1, "cursor": 2, "source": "user", "envelope": grp.Envelope,
	})
	if code != http.StatusOK {
		t.Fatalf("tech user-source chat post: %d %s", code, body)
	}
	code, body = httpCall(http.MethodPost, "/api/guest/chat", asAlice, map[string]any{
		"session_id": guestSess.ID, "kid": kid1, "cursor": 2,
	})
	if code != http.StatusOK {
		t.Fatalf("alice poll for user line: %d %s", code, body)
	}
	must(json.Unmarshal(body, &chatResp))
	if len(chatResp.Lines) != 1 || chatResp.Lines[0].From != "user" {
		t.Fatalf("alice user line = %+v", chatResp.Lines)
	}
	decUser, err := e2e.DecodeChatEnvelope(chatResp.Lines[0].Envelope, chatKey1, kid1, pinnedID, techSignPub, nil)
	must(err)
	if decUser.From != "user" || decUser.Text != "Hi from endpoint" {
		t.Fatalf("decrypted user line = %+v", decUser)
	}

	// ---- 6. Key rotation via PUT /api/remote-shares/{id}/chat-key & immediate suspension on removal ----
	var chatKey2 [32]byte
	_, _ = io.ReadFull(rand.Reader, chatKey2[:])
	const kid2 = "kid-epoch-2"
	grant2, err := e2e.SignChatGrant(techSignPriv, e2e.ChatGrant{
		Kid: kid2, AgentID: pinnedID, ShareID: shareCreated.Share.ID, Name: "Alice",
		GuestSignPub: aliceSignPub, Exp: shareCreated.Share.ExpiresAt.Unix(),
	})
	must(err)
	wrapped2, err := e2e.SealChatKeyForGuest(aliceECDHPub, e2e.WrappedGuestChatKey{
		Kid: kid2, K: base64.RawURLEncoding.EncodeToString(chatKey2[:]), TechPub: techSignPub,
		AgentID: pinnedID, ShareID: shareCreated.Share.ID, Name: "Alice",
		Exp: shareCreated.Share.ExpiresAt.Unix(), Grant: grant2, DevIK: ikPub,
	})
	must(err)

	code, body = httpCall(http.MethodPut, "/api/remote-shares/"+shareCreated.Share.ID+"/chat-key", asTech, map[string]any{
		"wrapped_chat_key": wrapped2, "chat_key_id": kid2, "redeem_count": 1,
	})
	if code != http.StatusOK {
		t.Fatalf("PUT /chat-key rotation: %d %s", code, body)
	}
	// Old epoch kid1 now conflicts; epoch 2 activates cleanly.
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-chat", asTech, map[string]any{
		"session_id": techSess.ID, "kid": kid1, "cursor": 0,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "chat_room_changed") {
		t.Fatalf("stale kid1 after rotation = %d %s, want 409 chat_room_changed", code, body)
	}
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-chat", asTech, map[string]any{
		"session_id": techSess.ID, "kid": kid2, "cursor": 0, "generation": 2,
	})
	if code != http.StatusOK {
		t.Fatalf("activate epoch 2: %d %s", code, body)
	}

	// Removing guest immediately suspends the chat room and disconnects guest.
	code, body = httpCall(http.MethodDelete, "/api/remote-shares/"+shareCreated.Share.ID, asTech, nil)
	if code != http.StatusOK {
		t.Fatalf("remove guest share: %d %s", code, body)
	}
	code, body = httpCall(http.MethodPost, "/api/devices/"+pinnedID+"/remote-chat", asTech, map[string]any{
		"session_id": techSess.ID, "kid": kid2, "cursor": 0,
	})
	if code != http.StatusConflict || !strings.Contains(string(body), "chat_room_changed") {
		t.Fatalf("room stayed active after guest removal: %d %s", code, body)
	}
	if srv.guests.connected(shareCreated.Share.ID) {
		t.Fatal("removed guest session remained tracked as connected")
	}

	// Closing technician WS invokes forgetChat cleanly.
	_ = techE2E.Close()
	_ = techSidecarE2E.Close()
}
