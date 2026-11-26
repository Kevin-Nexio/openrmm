package e2e

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	chatTextMax      = 1000
	chatGuestNameMax = 60
	maxChatSenders   = 256
	maxChatSequence  = 1<<53 - 1
)

// ChatEnvelope is a signed group message carried over the authenticated
// application channel or inside a peer-to-peer encrypted frame.
type ChatEnvelope struct {
	T   string `json:"t"`
	V   int    `json:"v"`
	Kid string `json:"kid"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

// ChatGrant is signed by the technician's ephemeral chat signing key (SK_tech)
// when accepting a guest. It binds the guest's signing key and display name so
// a guest can never spoof "tech", "user", or another guest's name.
type ChatGrant struct {
	Kid          string `json:"kid"`
	AgentID      string `json:"agent_id"`
	ShareID      string `json:"share_id"`
	Name         string `json:"name"`
	GuestSignPub string `json:"guest_sign_pub"`
	Exp          int64  `json:"exp"`
	Sig          string `json:"sig"`
}

// UserKeyCert certifies the local endpoint chat window's ephemeral signing key
// (PK_user) under the technician's chat signing key (SK_tech).
type UserKeyCert struct {
	Kid     string `json:"kid"`
	AgentID string `json:"agent_id"`
	UserPub string `json:"user_pub"`
	Sig     string `json:"sig"`
}

// ChatInnerPayload is encrypted inside ChatEnvelope.CT under K_chat.
type ChatInnerPayload struct {
	From     string       `json:"from"` // "tech" | "user" | "guest"
	Name     string       `json:"name,omitempty"`
	Text     string       `json:"text"`
	Sequence uint64       `json:"seq"`
	Sig      string       `json:"sig"`
	Grant    *ChatGrant   `json:"grant,omitempty"`
	UserCert *UserKeyCert `json:"user_cert,omitempty"`
}

// WrappedGuestChatKey is the plaintext JSON sealed to a guest's ECDH public key.
type WrappedGuestChatKey struct {
	V       int       `json:"v"`
	Kid     string    `json:"kid"`
	K       string    `json:"k"`
	TechPub string    `json:"tech_pub"`
	AgentID string    `json:"agent_id"`
	ShareID string    `json:"share_id"`
	Name    string    `json:"name"`
	Exp     int64     `json:"exp"`
	Grant   ChatGrant `json:"grant"`
	DevIK   string    `json:"dev_ik"`
}

type sealedGuestBlob struct {
	V   int    `json:"v"`
	EPK string `json:"epk"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
}

// CleanOneLine strips control characters and line breaks, collapses whitespace
// to single spaces, and caps length at max runes.
func CleanOneLine(raw string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range strings.TrimSpace(raw) {
		switch {
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r) || r == unicode.ReplacementChar || !unicode.IsPrint(r):
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	runes := []rune(b.String())
	if len(runes) > max {
		runes = runes[:max]
	}
	return strings.TrimSpace(string(runes))
}

// IsChatEnvelope reports whether raw is a syntactically valid e2e_chat text frame.
func IsChatEnvelope(raw []byte) bool {
	if len(raw) > 8192 {
		return false
	}
	var env ChatEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return false
	}
	return env.T == "e2e_chat" && env.V == 1 && env.Kid != "" && env.IV != "" && env.CT != ""
}

func chatAAD(kid, agentID string) []byte {
	buf := make([]byte, 0, 64+len(kid)+len(agentID))
	buf = append(buf, "rmm-e2e-chat-v1\x00"...)
	buf = appendLPString(buf, kid)
	buf = appendLPString(buf, agentID)
	return buf
}

func userCertBytes(kid, agentID string, userPubRaw []byte) []byte {
	buf := make([]byte, 0, 64+len(kid)+len(agentID)+len(userPubRaw))
	buf = append(buf, "rmm-chat-user-v1\x00"...)
	buf = appendLPString(buf, kid)
	buf = appendLPString(buf, agentID)
	buf = appendLP(buf, userPubRaw)
	return buf
}

// SignUserKeyCert signs a certificate authorizing PK_user to speak as "user" in kid.
func SignUserKeyCert(techSignPrivB64, kid, agentID, userPubB64 string) (UserKeyCert, error) {
	rawPub, _, err := DecodePublicKey(userPubB64)
	if err != nil {
		return UserKeyCert{}, err
	}
	sig, err := SignP256(techSignPrivB64, userCertBytes(kid, agentID, rawPub))
	if err != nil {
		return UserKeyCert{}, err
	}
	return UserKeyCert{Kid: kid, AgentID: agentID, UserPub: userPubB64, Sig: sig}, nil
}

// VerifyUserKeyCert checks a UserKeyCert against techSignPubB64.
func VerifyUserKeyCert(techSignPubB64 string, cert UserKeyCert) bool {
	rawPub, _, err := DecodePublicKey(cert.UserPub)
	if err != nil {
		return false
	}
	return VerifyP256(techSignPubB64, userCertBytes(cert.Kid, cert.AgentID, rawPub), cert.Sig)
}

func chatGrantBytes(g ChatGrant, guestPubRaw []byte) []byte {
	buf := make([]byte, 0, 128+len(g.Name))
	buf = append(buf, "rmm-chat-grant-v1\x00"...)
	buf = appendLPString(buf, g.Kid)
	buf = appendLPString(buf, g.AgentID)
	buf = appendLPString(buf, g.ShareID)
	buf = appendLPString(buf, g.Name)
	buf = appendLP(buf, guestPubRaw)
	buf = appendU64(buf, uint64(g.Exp))
	return buf
}

// SignChatGrant creates a technician-signed authorization for a guest's chat key.
func SignChatGrant(techSignPrivB64 string, g ChatGrant) (ChatGrant, error) {
	g.Name = CleanOneLine(g.Name, chatGuestNameMax)
	if g.Name == "" || g.Kid == "" || g.AgentID == "" || g.ShareID == "" || g.Exp <= 0 {
		return ChatGrant{}, errors.New("e2e: incomplete chat grant")
	}
	guestRaw, _, err := DecodePublicKey(g.GuestSignPub)
	if err != nil {
		return ChatGrant{}, err
	}
	sig, err := SignP256(techSignPrivB64, chatGrantBytes(g, guestRaw))
	if err != nil {
		return ChatGrant{}, err
	}
	g.Sig = sig
	return g, nil
}

// VerifyChatGrant validates a ChatGrant against techSignPubB64.
func VerifyChatGrant(techSignPubB64 string, g ChatGrant) bool {
	if g.Kid == "" || g.AgentID == "" || g.ShareID == "" || g.Exp <= 0 {
		return false
	}
	if CleanOneLine(g.Name, chatGuestNameMax) != g.Name || g.Name == "" {
		return false
	}
	guestRaw, _, err := DecodePublicKey(g.GuestSignPub)
	if err != nil {
		return false
	}
	return VerifyP256(techSignPubB64, chatGrantBytes(g, guestRaw), g.Sig)
}

func chatMsgSigBytes(kid, agentID, from, name, text string, seq uint64) []byte {
	buf := make([]byte, 0, 128)
	buf = append(buf, "rmm-chat-msg-v2\x00"...)
	buf = appendLPString(buf, kid)
	buf = appendLPString(buf, agentID)
	buf = appendLPString(buf, from)
	buf = appendLPString(buf, name)
	buf = appendLPString(buf, text)
	buf = appendU64(buf, seq)
	return buf
}

// EncodeChatEnvelope signs and encrypts a multi-party chat message.
func EncodeChatEnvelope(chatKey [32]byte, kid, agentID, from, name, text, signPrivB64 string, seq uint64, grant *ChatGrant, userCert *UserKeyCert) ([]byte, error) {
	cleanText := CleanOneLine(text, chatTextMax)
	if cleanText == "" {
		return nil, errors.New("e2e: empty chat message")
	}
	cleanName := ""
	if from == "guest" {
		if grant == nil {
			return nil, errors.New("e2e: guest chat requires grant")
		}
		cleanName = grant.Name
	} else if from == "user" && userCert == nil {
		return nil, errors.New("e2e: user chat requires user_cert")
	} else if from != "tech" && from != "user" {
		return nil, errors.New("e2e: invalid chat sender role")
	}

	if seq == 0 || seq > maxChatSequence {
		return nil, errors.New("e2e: invalid chat sequence")
	}
	sig, err := SignP256(signPrivB64, chatMsgSigBytes(kid, agentID, from, cleanName, cleanText, seq))
	if err != nil {
		return nil, err
	}
	inner, err := json.Marshal(ChatInnerPayload{
		From:     from,
		Name:     cleanName,
		Text:     cleanText,
		Sequence: seq,
		Sig:      sig,
		Grant:    grant,
		UserCert: userCert,
	})
	if err != nil {
		return nil, err
	}

	aead, err := newGCM(chatKey)
	if err != nil {
		return nil, err
	}
	var iv [12]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, iv[:], inner, chatAAD(kid, agentID))
	env, err := json.Marshal(ChatEnvelope{
		T:   "e2e_chat",
		V:   1,
		Kid: kid,
		IV:  base64.RawURLEncoding.EncodeToString(iv[:]),
		CT:  base64.RawURLEncoding.EncodeToString(ct),
	})
	return env, err
}

// VerifiedChatMessage is a decrypted, sender-authenticated chat message.
type VerifiedChatMessage struct {
	From      string
	Name      string
	Text      string
	Sequence  uint64
	SenderKey string
	ShareID   string
}

// DecodeChatEnvelope decrypts and verifies an e2e_chat JSON frame against
// chatKey and techSignPubB64.
func DecodeChatEnvelope(raw []byte, chatKey [32]byte, expectedKid, expectedAgentID, techSignPubB64 string, revoked map[string]bool) (*VerifiedChatMessage, error) {
	if len(raw) > 8192 {
		return nil, errors.New("e2e: chat frame too large")
	}
	var env ChatEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.T != "e2e_chat" || env.V != 1 {
		return nil, errors.New("e2e: not an e2e_chat envelope")
	}
	if env.Kid != expectedKid || expectedKid == "" {
		return nil, errors.New("e2e: unexpected chat key id")
	}
	iv, err := base64.RawURLEncoding.DecodeString(env.IV)
	if err != nil || len(iv) != 12 {
		return nil, errors.New("e2e: invalid chat iv")
	}
	ct, err := base64.RawURLEncoding.DecodeString(env.CT)
	if err != nil || len(ct) < TagSize {
		return nil, errors.New("e2e: invalid chat ciphertext")
	}
	aead, err := newGCM(chatKey)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, iv, ct, chatAAD(expectedKid, expectedAgentID))
	if err != nil {
		return nil, errors.New("e2e: chat decryption failed")
	}
	var inner ChatInnerPayload
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, errors.New("e2e: invalid inner chat payload")
	}
	cleanText := CleanOneLine(inner.Text, chatTextMax)
	if cleanText == "" || inner.Sequence == 0 || inner.Sequence > maxChatSequence {
		return nil, errors.New("e2e: empty or invalid chat message")
	}

	switch inner.From {
	case "tech":
		if !VerifyP256(techSignPubB64, chatMsgSigBytes(expectedKid, expectedAgentID, "tech", "", cleanText, inner.Sequence), inner.Sig) {
			return nil, errors.New("e2e: invalid tech chat signature")
		}
		return &VerifiedChatMessage{From: "tech", Text: cleanText, Sequence: inner.Sequence, SenderKey: techSignPubB64}, nil

	case "user":
		if inner.UserCert == nil || inner.UserCert.Kid != expectedKid || inner.UserCert.AgentID != expectedAgentID {
			return nil, errors.New("e2e: missing or mismatched user_cert")
		}
		if !VerifyUserKeyCert(techSignPubB64, *inner.UserCert) {
			return nil, errors.New("e2e: invalid user_cert signature")
		}
		if !VerifyP256(inner.UserCert.UserPub, chatMsgSigBytes(expectedKid, expectedAgentID, "user", "", cleanText, inner.Sequence), inner.Sig) {
			return nil, errors.New("e2e: invalid user chat signature")
		}
		return &VerifiedChatMessage{From: "user", Text: cleanText, Sequence: inner.Sequence, SenderKey: inner.UserCert.UserPub}, nil

	case "guest":
		if inner.Grant == nil || inner.Grant.Kid != expectedKid || inner.Grant.AgentID != expectedAgentID || inner.Grant.Exp <= time.Now().Unix() {
			return nil, errors.New("e2e: missing or mismatched guest grant")
		}
		if revoked != nil && revoked[inner.Grant.ShareID] {
			return nil, errors.New("e2e: guest grant revoked")
		}
		if !VerifyChatGrant(techSignPubB64, *inner.Grant) {
			return nil, errors.New("e2e: invalid guest grant signature")
		}
		if !VerifyP256(inner.Grant.GuestSignPub, chatMsgSigBytes(expectedKid, expectedAgentID, "guest", inner.Grant.Name, cleanText, inner.Sequence), inner.Sig) {
			return nil, errors.New("e2e: invalid guest chat signature")
		}
		return &VerifiedChatMessage{
			From:      "guest",
			Name:      inner.Grant.Name,
			Text:      cleanText,
			Sequence:  inner.Sequence,
			SenderKey: inner.Grant.GuestSignPub,
			ShareID:   inner.Grant.ShareID,
		}, nil

	default:
		return nil, errors.New("e2e: unknown chat sender")
	}
}

// SealChatKeyForGuest encrypts WrappedGuestChatKey to guestECDHPubB64 using an
// ephemeral P-256 ECDH keypair and HKDF-SHA256 ("rmm-chat-wrap-v1").
func SealChatKeyForGuest(guestECDHPubB64 string, payload WrappedGuestChatKey) (string, error) {
	_, guestPub, err := DecodePublicKey(guestECDHPubB64)
	if err != nil {
		return "", err
	}
	ephemPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := ephemPriv.ECDH(guestPub)
	if err != nil {
		return "", err
	}
	ephemPubRaw := ephemPriv.PublicKey().Bytes()
	wrapKeySlice, err := hkdf.Key(sha256.New, shared, ephemPubRaw, "rmm-chat-wrap-v1", 32)
	if err != nil {
		return "", err
	}
	var wrapKey [32]byte
	copy(wrapKey[:], wrapKeySlice)
	aead, err := newGCM(wrapKey)
	if err != nil {
		return "", err
	}
	var iv [12]byte
	if _, err := io.ReadFull(rand.Reader, iv[:]); err != nil {
		return "", err
	}
	payload.V = 1
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	aad := append([]byte("rmm-chat-wrap-v1\x00"), ephemPubRaw...)
	ct := aead.Seal(nil, iv[:], plain, aad)
	blob, err := json.Marshal(sealedGuestBlob{
		V:   1,
		EPK: base64.RawURLEncoding.EncodeToString(ephemPubRaw),
		IV:  base64.RawURLEncoding.EncodeToString(iv[:]),
		CT:  base64.RawURLEncoding.EncodeToString(ct),
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(blob), nil
}

// OpenChatKeyAsGuest decrypts a wrapped_chat_key using the guest's ECDH private key.
func OpenChatKeyAsGuest(guestECDHPrivB64, wrappedB64 string) (*WrappedGuestChatKey, error) {
	_, guestPriv, err := DecodePrivateKey(guestECDHPrivB64)
	if err != nil {
		return nil, err
	}
	rawBlob, err := base64.RawURLEncoding.DecodeString(wrappedB64)
	if err != nil {
		return nil, errors.New("e2e: invalid wrapped_chat_key encoding")
	}
	var blob sealedGuestBlob
	if err := json.Unmarshal(rawBlob, &blob); err != nil || blob.V != 1 {
		return nil, errors.New("e2e: invalid wrapped_chat_key payload")
	}
	ephemRaw, ephemPub, err := DecodePublicKey(blob.EPK)
	if err != nil {
		return nil, err
	}
	iv, err := base64.RawURLEncoding.DecodeString(blob.IV)
	if err != nil || len(iv) != 12 {
		return nil, errors.New("e2e: invalid wrapped_chat_key iv")
	}
	ct, err := base64.RawURLEncoding.DecodeString(blob.CT)
	if err != nil || len(ct) < TagSize {
		return nil, errors.New("e2e: invalid wrapped_chat_key ciphertext")
	}
	shared, err := guestPriv.ECDH(ephemPub)
	if err != nil {
		return nil, err
	}
	wrapKeySlice, err := hkdf.Key(sha256.New, shared, ephemRaw, "rmm-chat-wrap-v1", 32)
	if err != nil {
		return nil, err
	}
	var wrapKey [32]byte
	copy(wrapKey[:], wrapKeySlice)
	aead, err := newGCM(wrapKey)
	if err != nil {
		return nil, err
	}
	aad := append([]byte("rmm-chat-wrap-v1\x00"), ephemRaw...)
	plain, err := aead.Open(nil, iv, ct, aad)
	if err != nil {
		return nil, errors.New("e2e: could not unwrap guest chat key")
	}
	var out WrappedGuestChatKey
	if err := json.Unmarshal(plain, &out); err != nil || out.V != 1 {
		return nil, errors.New("e2e: invalid unwrapped guest chat key")
	}
	if !VerifyChatGrant(out.TechPub, out.Grant) {
		return nil, errors.New("e2e: invalid grant inside wrapped chat key")
	}
	return &out, nil
}

// agentChatBridge manages the technician room key (K_chat) and local user
// signing certificate inside the technician's sidecar e2e.Conn.
type agentChatBridge struct {
	mu       sync.Mutex
	agentID  string
	kid      string
	chatKey  [32]byte
	hasKey   bool
	techPub  string
	userPriv string
	userPub  string
	userCert *UserKeyCert
	revoked  map[string]bool
	seen     map[string]uint64
	userSeq  uint64
}

func newAgentChatBridge(agentID string) *agentChatBridge {
	return &agentChatBridge{
		agentID: agentID,
		revoked: map[string]bool{},
		seen:    make(map[string]uint64),
	}
}

// HandleControl processes 0xE0 control frames from the technician viewer
// ("chat_init", "chat_user_cert", "chat_revoke"). Returns handled=true when
// the message is an internal chat control frame that should not be passed up.
func (b *agentChatBridge) HandleControl(data []byte) (handled bool, reply []byte) {
	var head struct {
		T string `json:"t"`
	}
	if json.Unmarshal(data, &head) != nil {
		return false, nil
	}
	switch head.T {
	case "chat_init":
		var m struct {
			Kid     string `json:"kid"`
			K       string `json:"k"`
			TechPub string `json:"tech_pub"`
		}
		if json.Unmarshal(data, &m) != nil || m.Kid == "" || len(m.Kid) > 64 {
			return true, nil
		}
		rawKey, err := base64.RawURLEncoding.DecodeString(m.K)
		if err != nil || len(rawKey) != 32 || ValidatePublicKey(m.TechPub) != nil {
			return true, nil
		}
		userPriv, userPub, err := GenerateKeyPair()
		if err != nil {
			return true, nil
		}
		b.mu.Lock()
		b.kid = m.Kid
		copy(b.chatKey[:], rawKey)
		b.hasKey = true
		b.techPub = m.TechPub
		b.userPriv = userPriv
		b.userPub = userPub
		b.userCert = nil
		b.revoked = map[string]bool{}
		b.seen = make(map[string]uint64)
		b.userSeq = 0
		b.mu.Unlock()
		ack, _ := json.Marshal(map[string]string{
			"t":        "chat_init_ack",
			"kid":      m.Kid,
			"user_pub": userPub,
		})
		return true, ack

	case "chat_user_cert":
		var m struct {
			Kid  string      `json:"kid"`
			Cert UserKeyCert `json:"cert"`
		}
		if json.Unmarshal(data, &m) != nil {
			return true, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if !b.hasKey || m.Kid != b.kid || m.Cert.Kid != b.kid || m.Cert.AgentID != b.agentID || m.Cert.UserPub != b.userPub {
			return true, nil
		}
		if VerifyUserKeyCert(b.techPub, m.Cert) {
			certCopy := m.Cert
			b.userCert = &certCopy
		}
		return true, nil

	case "chat_revoke":
		var m struct {
			ShareID string `json:"share_id"`
		}
		if json.Unmarshal(data, &m) == nil && m.ShareID != "" {
			b.mu.Lock()
			b.revoked[m.ShareID] = true
			b.mu.Unlock()
		}
		return true, nil

	default:
		return false, nil
	}
}

// DecodeGuestEnvelope decrypts and verifies an incoming group envelope
// for the local OS chat window on the technician's sidecar.
func (b *agentChatBridge) DecodeGuestEnvelope(raw []byte, shareID string) (*VerifiedChatMessage, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.hasKey || b.agentID == "" {
		return nil, false
	}
	msg, err := DecodeChatEnvelope(raw, b.chatKey, b.kid, b.agentID, b.techPub, b.revoked)
	if err != nil || msg.From != "guest" || msg.ShareID != shareID {
		return nil, false
	}
	last, known := b.seen[msg.SenderKey]
	if msg.Sequence <= last || (!known && len(b.seen) >= maxChatSenders) {
		return nil, false
	}
	b.seen[msg.SenderKey] = msg.Sequence
	return msg, true
}

// MaybeEncodeUserChat checks whether an outbound inner JSON message is a chat
// line typed by the person at the endpoint ({"t":"chat","from":"user","text":...})
// and, if the technician chat bridge has a certified user key, returns a signed
// envelope to deliver inside the encrypted technician connection.
func (b *agentChatBridge) MaybeEncodeUserChat(innerJSON []byte) ([]byte, bool) {
	var m struct {
		T    string `json:"t"`
		From string `json:"from"`
		Text string `json:"text"`
	}
	if json.Unmarshal(innerJSON, &m) != nil || m.T != "chat" || m.From != "user" || m.Text == "" {
		return nil, false
	}
	b.mu.Lock()
	if !b.hasKey || b.userCert == nil || b.userPriv == "" || b.agentID == "" {
		b.mu.Unlock()
		return nil, false
	}
	chatKey := b.chatKey
	kid := b.kid
	agentID := b.agentID
	userPriv := b.userPriv
	certCopy := *b.userCert
	b.userSeq++
	seq := b.userSeq
	b.mu.Unlock()

	env, err := EncodeChatEnvelope(chatKey, kid, agentID, "user", "", m.Text, userPriv, seq, nil, &certCopy)
	if err != nil {
		return nil, false
	}
	return env, true
}
