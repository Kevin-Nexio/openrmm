package e2e

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	handshakeTimeout   = 15 * time.Second
	handshakeReadLimit = 8192
	MaxFrameSize       = 32 << 20
	maxPayloadSize     = MaxFrameSize - HeaderSize - TagSize - 1
	guestInnerLimit    = 4096
	chVideo            = 0x01
)

// WSConn is the minimal WebSocket message interface shared by *websocket.Conn
// and *e2e.Conn so media, file-transfer, and terminal loops run unchanged.
type WSConn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	Close() error
}

// AgentHandshakeOpts configures the agent/sidecar end of an E2E relay session.
type AgentHandshakeOpts struct {
	SessionID string
	AgentID   string
	Kind      string
	GuestMode string // "" | "view" | "control"
	EKPriv    string
	ViewerKey string
	IKPub     string
	Exp       int64
	SigDel    string
}

// NewAgentHandshakeFromIdentity creates ephemeral ECDH parameters and signs a
// session delegation using the agent's durable identity keypair.
func NewAgentHandshakeFromIdentity(sessionID, agentID, kind, guestMode, viewerKey, ikPrivB64, ikPubB64 string, ttl time.Duration) (AgentHandshakeOpts, error) {
	if err := ValidatePublicKey(viewerKey); err != nil {
		return AgentHandshakeOpts{}, fmt.Errorf("e2e: invalid authorized viewer key: %w", err)
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	ekPriv, ekPub, err := GenerateKeyPair()
	if err != nil {
		return AgentHandshakeOpts{}, err
	}
	exp := time.Now().Add(ttl).Unix()
	normKind := NormalizeKind(kind)
	sig, err := SignDelegation(ikPrivB64, Delegation{
		SessionID: sessionID,
		AgentID:   agentID,
		Kind:      normKind,
		GuestMode: guestMode,
		EKPub:     ekPub,
		Exp:       exp,
	})
	if err != nil {
		return AgentHandshakeOpts{}, err
	}
	return AgentHandshakeOpts{
		SessionID: sessionID,
		AgentID:   agentID,
		Kind:      normKind,
		GuestMode: guestMode,
		EKPriv:    ekPriv,
		ViewerKey: viewerKey,
		IKPub:     ikPubB64,
		Exp:       exp,
		SigDel:    sig,
	}, nil
}

// ViewerHandshakeOpts configures the viewer end of an E2E relay session (used
// in Go integration tests; the browser viewer uses openrmm/src/remote-crypto.jsx).
type ViewerHandshakeOpts struct {
	SessionID         string
	EKPriv            string
	ExpectedAgentID   string // required when ExpectedGuestMode == ""
	ExpectedKind      string
	ExpectedGuestMode string // "" for technician, "view"|"control" for guest
	ExpectedIKPub     string // pinned IK_dev_pub (technician)
	ExpectedInviteFP  string // 128-bit fragment commitment (guest)
}

type helloFrame struct {
	T         string `json:"t"`
	V         int    `json:"v"`
	Role      string `json:"role"`
	AgentID   string `json:"agent_id,omitempty"`
	Kind      string `json:"kind,omitempty"`
	GuestMode string `json:"guest_mode,omitempty"`
	EK        string `json:"ek"`
	Nonce     string `json:"nonce"`
	IK        string `json:"ik,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Sig       string `json:"sig,omitempty"`
}

// Conn wraps a *websocket.Conn with AEAD 0xE0 framing, monotonic sequence
// numbers, endpoint-side GuestPolicy filtering, and multi-party E2E chat bridging.
type Conn struct {
	raw       *websocket.Conn
	sessionID string
	role      string // "agent" | "viewer"
	guestMode string // "" | "view" | "control"

	outAEAD cipher.AEAD
	outIV   [12]byte
	inAEAD  cipher.AEAD
	inIV    [12]byte

	writeMu    sync.Mutex
	nextOutSeq uint64
	nextInSeq  uint64

	peerIKPub string
	chat      *agentChatBridge
}

// PeerIdentityKey returns the authenticated device public key (IK_dev_pub).
func (c *Conn) PeerIdentityKey() string { return c.peerIKPub }

// HandshakeAgent performs the agent/sidecar side of the E2E handshake and
// confirms bidirectional key possession via seq=0 e2e_ready before returning.
func HandshakeAgent(raw *websocket.Conn, opts AgentHandshakeOpts) (*Conn, error) {
	opts.Kind = NormalizeKind(opts.Kind)
	if opts.SessionID == "" || opts.AgentID == "" {
		return nil, errors.New("e2e: session_id and agent_id are required")
	}
	if opts.Exp <= time.Now().Unix() {
		return nil, errors.New("e2e: expired agent delegation")
	}
	if opts.GuestMode != "" && opts.GuestMode != "view" && opts.GuestMode != "control" {
		return nil, errors.New("e2e: invalid guest_mode")
	}
	if err := ValidatePublicKey(opts.ViewerKey); err != nil {
		return nil, fmt.Errorf("e2e: invalid authorized viewer key: %w", err)
	}
	_, ekPriv, err := DecodePrivateKey(opts.EKPriv)
	if err != nil {
		return nil, err
	}
	ekPubRaw := ekPriv.PublicKey().Bytes()
	ekPubB64 := base64.RawURLEncoding.EncodeToString(ekPubRaw)
	ikPubRaw, _, err := DecodePublicKey(opts.IKPub)
	if err != nil {
		return nil, err
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(opts.SigDel)
	if err != nil || len(sigRaw) != sigRawLen {
		return nil, ErrInvalidSignature
	}
	if !VerifyDelegation(opts.IKPub, Delegation{
		SessionID: opts.SessionID,
		AgentID:   opts.AgentID,
		Kind:      opts.Kind,
		GuestMode: opts.GuestMode,
		EKPub:     ekPubB64,
		Exp:       opts.Exp,
	}, opts.SigDel) {
		return nil, errors.New("e2e: agent delegation self-check failed")
	}

	nonceB64, err := RandomBytesB64(nonceRawLen)
	if err != nil {
		return nil, err
	}
	nonceAgent, _ := base64.RawURLEncoding.DecodeString(nonceB64)

	raw.SetReadLimit(handshakeReadLimit)
	deadline := time.Now().Add(handshakeTimeout)
	_ = raw.SetReadDeadline(deadline)
	_ = raw.SetWriteDeadline(deadline)
	defer func() {
		_ = raw.SetReadDeadline(time.Time{})
		_ = raw.SetWriteDeadline(time.Time{})
	}()

	myHello, err := json.Marshal(helloFrame{
		T:         "e2e_hello",
		V:         1,
		Role:      "agent",
		AgentID:   opts.AgentID,
		Kind:      opts.Kind,
		GuestMode: opts.GuestMode,
		EK:        ekPubB64,
		Nonce:     nonceB64,
		IK:        opts.IKPub,
		Exp:       opts.Exp,
		Sig:       opts.SigDel,
	})
	if err != nil {
		return nil, err
	}
	if err := raw.WriteMessage(websocket.TextMessage, myHello); err != nil {
		return nil, fmt.Errorf("e2e: send agent hello: %w", err)
	}

	peerHello, err := readHello(raw, "viewer")
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if peerHello.EK != opts.ViewerKey {
		_ = raw.Close()
		return nil, errors.New("e2e: viewer key does not match the authorized key")
	}
	ekViewerRaw, ekViewerPub, err := DecodePublicKey(peerHello.EK)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("e2e: viewer ek: %w", err)
	}
	nonceViewer, err := base64.RawURLEncoding.DecodeString(peerHello.Nonce)
	if err != nil || len(nonceViewer) != nonceRawLen || base64.RawURLEncoding.EncodeToString(nonceViewer) != peerHello.Nonce {
		_ = raw.Close()
		return nil, errors.New("e2e: invalid viewer nonce")
	}

	shared, err := ekPriv.ECDH(ekViewerPub)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("e2e: ecdh: %w", err)
	}
	th := TranscriptHash(TranscriptInput{
		SessionID:   opts.SessionID,
		AgentID:     opts.AgentID,
		Kind:        opts.Kind,
		GuestMode:   opts.GuestMode,
		IKPubRaw:    ikPubRaw,
		EKViewerRaw: ekViewerRaw,
		NonceViewer: nonceViewer,
		EKAgentRaw:  ekPubRaw,
		NonceAgent:  nonceAgent,
		Exp:         opts.Exp,
		SigDelRaw:   sigRaw,
	})
	keys, err := DeriveSessionKeys(shared, th)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	outAEAD, err := newGCM(keys.A2VKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	inAEAD, err := newGCM(keys.V2AKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	c := &Conn{
		raw:       raw,
		sessionID: opts.SessionID,
		role:      "agent",
		guestMode: opts.GuestMode,
		outAEAD:   outAEAD,
		outIV:     keys.A2VIV,
		inAEAD:    inAEAD,
		inIV:      keys.V2AIV,
		peerIKPub: opts.IKPub,
	}
	if opts.GuestMode == "" && opts.Kind == "desktop" {
		c.chat = newAgentChatBridge(opts.AgentID)
	}
	if err := c.confirmReady(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	raw.SetReadLimit(MaxFrameSize)
	return c, nil
}

// HandshakeViewer performs the viewer side of the E2E handshake.
func HandshakeViewer(raw *websocket.Conn, opts ViewerHandshakeOpts) (*Conn, error) {
	opts.ExpectedKind = NormalizeKind(opts.ExpectedKind)
	if opts.SessionID == "" {
		return nil, errors.New("e2e: session_id is required")
	}
	if opts.ExpectedIKPub == "" && opts.ExpectedInviteFP == "" {
		return nil, errors.New("e2e: expected device identity or invite fingerprint is required")
	}
	_, ekPriv, err := DecodePrivateKey(opts.EKPriv)
	if err != nil {
		return nil, err
	}
	ekViewerRaw := ekPriv.PublicKey().Bytes()
	ekPubB64 := base64.RawURLEncoding.EncodeToString(ekViewerRaw)

	nonceB64, err := RandomBytesB64(nonceRawLen)
	if err != nil {
		return nil, err
	}
	nonceViewer, _ := base64.RawURLEncoding.DecodeString(nonceB64)

	raw.SetReadLimit(handshakeReadLimit)
	deadline := time.Now().Add(handshakeTimeout)
	_ = raw.SetReadDeadline(deadline)
	_ = raw.SetWriteDeadline(deadline)
	defer func() {
		_ = raw.SetReadDeadline(time.Time{})
		_ = raw.SetWriteDeadline(time.Time{})
	}()

	myHello, err := json.Marshal(helloFrame{
		T:     "e2e_hello",
		V:     1,
		Role:  "viewer",
		EK:    ekPubB64,
		Nonce: nonceB64,
	})
	if err != nil {
		return nil, err
	}
	if err := raw.WriteMessage(websocket.TextMessage, myHello); err != nil {
		return nil, fmt.Errorf("e2e: send viewer hello: %w", err)
	}

	peerHello, err := readHello(raw, "agent")
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if NormalizeKind(peerHello.Kind) != opts.ExpectedKind {
		_ = raw.Close()
		return nil, fmt.Errorf("e2e: unexpected session kind %q", peerHello.Kind)
	}
	if peerHello.GuestMode != opts.ExpectedGuestMode {
		_ = raw.Close()
		return nil, fmt.Errorf("e2e: unexpected guest_mode %q", peerHello.GuestMode)
	}
	if opts.ExpectedAgentID != "" && peerHello.AgentID != opts.ExpectedAgentID {
		_ = raw.Close()
		return nil, errors.New("e2e: agent_id mismatch")
	}
	if peerHello.AgentID == "" {
		_ = raw.Close()
		return nil, errors.New("e2e: missing agent_id")
	}
	ikPubRaw, _, err := DecodePublicKey(peerHello.IK)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	if opts.ExpectedIKPub != "" && peerHello.IK != opts.ExpectedIKPub {
		_ = raw.Close()
		return nil, errors.New("e2e: device identity key mismatch")
	}
	if opts.ExpectedInviteFP != "" && InviteFingerprint(peerHello.IK) != opts.ExpectedInviteFP {
		_ = raw.Close()
		return nil, errors.New("e2e: invite fingerprint mismatch")
	}
	ekAgentRaw, ekAgentPub, err := DecodePublicKey(peerHello.EK)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	nonceAgent, err := base64.RawURLEncoding.DecodeString(peerHello.Nonce)
	if err != nil || len(nonceAgent) != nonceRawLen || base64.RawURLEncoding.EncodeToString(nonceAgent) != peerHello.Nonce {
		_ = raw.Close()
		return nil, errors.New("e2e: invalid agent nonce")
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(peerHello.Sig)
	if err != nil || len(sigRaw) != sigRawLen {
		_ = raw.Close()
		return nil, ErrInvalidSignature
	}
	if peerHello.Exp <= time.Now().Unix() {
		_ = raw.Close()
		return nil, errors.New("e2e: expired agent delegation")
	}
	if !VerifyDelegation(peerHello.IK, Delegation{
		SessionID: opts.SessionID,
		AgentID:   peerHello.AgentID,
		Kind:      NormalizeKind(peerHello.Kind),
		GuestMode: peerHello.GuestMode,
		EKPub:     peerHello.EK,
		Exp:       peerHello.Exp,
	}, peerHello.Sig) {
		_ = raw.Close()
		return nil, errors.New("e2e: invalid agent delegation signature")
	}

	shared, err := ekPriv.ECDH(ekAgentPub)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	th := TranscriptHash(TranscriptInput{
		SessionID:   opts.SessionID,
		AgentID:     peerHello.AgentID,
		Kind:        NormalizeKind(peerHello.Kind),
		GuestMode:   peerHello.GuestMode,
		IKPubRaw:    ikPubRaw,
		EKViewerRaw: ekViewerRaw,
		NonceViewer: nonceViewer,
		EKAgentRaw:  ekAgentRaw,
		NonceAgent:  nonceAgent,
		Exp:         peerHello.Exp,
		SigDelRaw:   sigRaw,
	})
	keys, err := DeriveSessionKeys(shared, th)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	outAEAD, err := newGCM(keys.V2AKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	inAEAD, err := newGCM(keys.A2VKey)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	c := &Conn{
		raw:       raw,
		sessionID: opts.SessionID,
		role:      "viewer",
		outAEAD:   outAEAD,
		outIV:     keys.V2AIV,
		inAEAD:    inAEAD,
		inIV:      keys.A2VIV,
		peerIKPub: peerHello.IK,
	}
	if err := c.confirmReady(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	raw.SetReadLimit(MaxFrameSize)
	return c, nil
}

func readHello(raw *websocket.Conn, wantRole string) (helloFrame, error) {
	mt, data, err := raw.ReadMessage()
	if err != nil {
		return helloFrame{}, fmt.Errorf("e2e: read %s hello: %w", wantRole, err)
	}
	if mt != websocket.TextMessage || len(data) > 4096 {
		return helloFrame{}, errors.New("e2e: expected JSON e2e_hello frame")
	}
	var h helloFrame
	if err := json.Unmarshal(data, &h); err != nil || h.T != "e2e_hello" || h.V != 1 || h.Role != wantRole {
		return helloFrame{}, errors.New("e2e: malformed e2e_hello")
	}
	return h, nil
}

func (c *Conn) confirmReady() error {
	if err := c.sealAndSend(0, InnerText, []byte(`{"t":"e2e_ready"}`)); err != nil {
		return fmt.Errorf("e2e: send e2e_ready: %w", err)
	}
	mt, frame, err := c.raw.ReadMessage()
	if err != nil {
		return fmt.Errorf("e2e: read e2e_ready: %w", err)
	}
	if mt != websocket.BinaryMessage {
		return errors.New("e2e: expected encrypted e2e_ready")
	}
	innerType, plain, err := c.openFrame(frame, 0)
	if err != nil {
		return err
	}
	var ready struct {
		T string `json:"t"`
	}
	if innerType != InnerText || json.Unmarshal(plain, &ready) != nil || ready.T != "e2e_ready" {
		return errors.New("e2e: invalid e2e_ready")
	}
	c.nextOutSeq = 1
	c.nextInSeq = 1
	return nil
}

func (c *Conn) sealAndSend(seq uint64, innerType byte, payload []byte) error {
	plain := make([]byte, 1+len(payload))
	plain[0] = innerType
	copy(plain[1:], payload)

	hdr := make([]byte, HeaderSize, HeaderSize+len(plain)+TagSize)
	hdr[0] = FramePrefix
	binary.BigEndian.PutUint64(hdr[1:9], seq)

	nonce := xorNonce(c.outIV, seq)
	aad := frameAAD(seq, c.sessionID)
	wire := c.outAEAD.Seal(hdr, nonce[:], plain, aad)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.raw.WriteMessage(websocket.BinaryMessage, wire)
}

func (c *Conn) writeEncrypted(mt int, payload []byte) error {
	// Check before allocating or consuming an outbound sequence number.
	if len(payload) > maxPayloadSize {
		return errors.New("e2e: outbound message exceeds the frame limit")
	}
	var innerType byte
	switch mt {
	case websocket.TextMessage:
		innerType = InnerText
	case websocket.BinaryMessage:
		innerType = InnerBinary
	default:
		return errors.New("e2e: unsupported websocket message type")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.nextOutSeq == math.MaxUint64 {
		_ = c.raw.Close()
		return errors.New("e2e: outbound sequence exhausted")
	}
	seq := c.nextOutSeq
	c.nextOutSeq++

	plain := make([]byte, 1+len(payload))
	plain[0] = innerType
	copy(plain[1:], payload)

	hdr := make([]byte, HeaderSize, HeaderSize+len(plain)+TagSize)
	hdr[0] = FramePrefix
	binary.BigEndian.PutUint64(hdr[1:9], seq)

	nonce := xorNonce(c.outIV, seq)
	aad := frameAAD(seq, c.sessionID)
	wire := c.outAEAD.Seal(hdr, nonce[:], plain, aad)
	return c.raw.WriteMessage(websocket.BinaryMessage, wire)
}

func (c *Conn) openFrame(rawData []byte, wantSeq uint64) (byte, []byte, error) {
	if len(rawData) < HeaderSize+1+TagSize || rawData[0] != FramePrefix {
		return 0, nil, errors.New("e2e: invalid frame header")
	}
	seq := binary.BigEndian.Uint64(rawData[1:9])
	if seq != wantSeq {
		return 0, nil, fmt.Errorf("e2e: sequence mismatch (got %d, want %d)", seq, wantSeq)
	}
	nonce := xorNonce(c.inIV, seq)
	aad := frameAAD(seq, c.sessionID)
	plain, err := c.inAEAD.Open(nil, nonce[:], rawData[HeaderSize:], aad)
	if err != nil || len(plain) < 1 {
		return 0, nil, errors.New("e2e: frame authentication failed")
	}
	return plain[0], plain[1:], nil
}

// Group envelopes only cross a WebSocket within the authenticated peer stream.
type chatTransfer struct {
	T        string          `json:"t"`
	ShareID  string          `json:"share_id,omitempty"`
	Envelope json.RawMessage `json:"envelope"`
}

// WriteMessage encrypts data as a 0xE0 binary frame. In a guest session it
// enforces the outbound GuestPolicy allowlist prior to encryption; in a
// technician desktop session it also emits a signed e2e_chat envelope when the
// local OS user sends a chat line.
func (c *Conn) WriteMessage(mt int, data []byte) error {
	if c.role == "agent" && c.guestMode != "" {
		if !guestAllowFromAgent(mt, data) {
			return nil
		}
	}
	if err := c.writeEncrypted(mt, data); err != nil {
		return err
	}
	if c.role == "agent" && c.guestMode == "" && mt == websocket.TextMessage && c.chat != nil {
		if env, ok := c.chat.MaybeEncodeUserChat(data); ok {
			frame, err := json.Marshal(chatTransfer{T: "chat_group", Envelope: env})
			if err != nil {
				return err
			}
			return c.writeEncrypted(websocket.TextMessage, frame)
		}
	}
	return nil
}

// ReadMessage reads and authenticates the next inbound message. Unencrypted or
// out-of-order frames immediately close the underlying connection.
func (c *Conn) ReadMessage() (int, []byte, error) {
	for {
		mt, rawData, err := c.raw.ReadMessage()
		if err != nil {
			return 0, nil, err
		}
		if mt != websocket.BinaryMessage {
			_ = c.raw.Close()
			return 0, nil, errors.New("e2e: unexpected websocket message type")
		}
		if c.nextInSeq == math.MaxUint64 {
			_ = c.raw.Close()
			return 0, nil, errors.New("e2e: inbound sequence exhausted")
		}
		innerType, payload, err := c.openFrame(rawData, c.nextInSeq)
		if err != nil {
			_ = c.raw.Close()
			return 0, nil, err
		}
		c.nextInSeq++

		var innerMT int
		switch innerType {
		case InnerText:
			innerMT = websocket.TextMessage
		case InnerBinary:
			innerMT = websocket.BinaryMessage
		default:
			_ = c.raw.Close()
			return 0, nil, errors.New("e2e: unknown inner frame type")
		}

		if c.role == "agent" && c.guestMode != "" {
			if !guestAllowFromViewer(c.guestMode == "control", innerMT, payload) {
				continue
			}
		}
		if c.role == "agent" && c.guestMode == "" && innerMT == websocket.TextMessage && c.chat != nil {
			var transfer chatTransfer
			if json.Unmarshal(payload, &transfer) == nil && transfer.T == "chat_guest" {
				if msg, ok := c.chat.DecodeGuestEnvelope(transfer.Envelope, transfer.ShareID); ok {
					data, err := json.Marshal(map[string]string{
						"t": "chat", "from": "guest", "name": msg.Name, "text": msg.Text,
					})
					return websocket.TextMessage, data, err
				}
				continue
			}
			if handled, reply := c.chat.HandleControl(payload); handled {
				if len(reply) > 0 {
					_ = c.writeEncrypted(websocket.TextMessage, reply)
				}
				continue
			}
		}
		return innerMT, payload, nil
	}
}

// Close closes the underlying WebSocket connection.
func (c *Conn) Close() error {
	return c.raw.Close()
}

// guestAllowFromViewer enforces the exact same allowlist as remote.GuestPolicy
// after decrypting an E2E guest frame on the endpoint.
func guestAllowFromViewer(control bool, mt int, data []byte) bool {
	if mt != websocket.TextMessage || len(data) > guestInnerLimit {
		return false
	}
	var e struct {
		T string `json:"t"`
	}
	if json.Unmarshal(data, &e) != nil {
		return false
	}
	switch e.T {
	case "kf", "mon":
		return true
	case "m", "b", "w", "k":
		return control
	}
	return false
}

func guestAllowFromAgent(mt int, data []byte) bool {
	if mt == websocket.BinaryMessage {
		return len(data) > 0 && data[0] == chVideo
	}
	if mt != websocket.TextMessage {
		return false
	}
	var e struct {
		T string `json:"t"`
	}
	if json.Unmarshal(data, &e) != nil {
		return false
	}
	switch e.T {
	case "hello", "monitors", "notice":
		return true
	}
	return false
}
