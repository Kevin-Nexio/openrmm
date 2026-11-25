// Package e2e implements end-to-end encryption for native remote sessions
// (desktop, file transfer, elevated terminal, and multi-party guest chat)
// using the rmm-e2e-p256-aes256gcm-v1 suite.
//
// Every primitive comes from the Go standard library (crypto/ecdh, crypto/ecdsa,
// crypto/hkdf, crypto/aes, crypto/cipher) and matches browser SubtleCrypto
// byte-for-byte without external dependencies or CGO.
package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	// Suite identifies the wire cryptographic suite.
	Suite = "rmm-e2e-p256-aes256gcm-v1"

	// FramePrefix marks an encrypted 1-to-1 session frame on /ws/remote.
	FramePrefix byte = 0xE0

	// Inner frame type markers inside a decrypted 0xE0 payload.
	InnerText   byte = 0x01
	InnerBinary byte = 0x02

	// HeaderSize is [0xE0] (1B) + seq uint64 big-endian (8B).
	HeaderSize = 9
	// TagSize is the AES-256-GCM authentication tag length.
	TagSize = 16

	pubKeyRawLen  = 65
	privKeyRawLen = 32
	sigRawLen     = 64
	nonceRawLen   = 32
)

var (
	ErrInvalidPublicKey  = errors.New("e2e: invalid P-256 public key")
	ErrInvalidPrivateKey = errors.New("e2e: invalid P-256 private key")
	ErrInvalidSignature  = errors.New("e2e: invalid P-256 signature")
)

// SessionParams is the one-time 0600 JSON file the agent passes to rmm-remote
// via -session so tickets and ephemeral E2E delegation secrets never appear in
// process arguments or environment variables.
type SessionParams struct {
	Relay     string `json:"relay"`
	Ticket    string `json:"ticket,omitempty"`
	FilesOnly bool   `json:"files_only,omitempty"`
	NoFiles   bool   `json:"no_files,omitempty"`
	NoChat    bool   `json:"no_chat,omitempty"`

	E2E       bool   `json:"e2e,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	Kind      string `json:"kind,omitempty"`
	GuestMode string `json:"guest_mode,omitempty"`
	EKPriv    string `json:"ek_priv,omitempty"`
	ViewerKey string `json:"viewer_key,omitempty"`
	IKPub     string `json:"ik_pub,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	SigDel    string `json:"sig_del,omitempty"`
}

// Delegation binds an ephemeral session ECDH public key to a specific session,
// device, module kind, and guest restriction under the agent's durable identity.
type Delegation struct {
	SessionID string
	AgentID   string
	Kind      string
	GuestMode string
	EKPub     string
	Exp       int64
}

// SessionKeys holds unidirectional AES-256-GCM keys and 12-byte base IVs.
type SessionKeys struct {
	V2AKey [32]byte
	V2AIV  [12]byte
	A2VKey [32]byte
	A2VIV  [12]byte
}

// NormalizeKind maps an empty RemoteStartMsg.Kind to "desktop".
func NormalizeKind(kind string) string {
	if kind == "" {
		return "desktop"
	}
	return kind
}

// GenerateKeyPair creates a new P-256 keypair encoded with canonical base64url
// (unpadded): privB64 is the 32-byte scalar and pubB64 is the 65-byte
// uncompressed SEC1 public point (0x04 || X || Y).
func GenerateKeyPair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		nil
}

// RandomBytesB64 generates n cryptographically random bytes as base64url.
func RandomBytesB64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// DecodePublicKey validates and decodes a canonical base64url 65-byte
// uncompressed P-256 public key.
func DecodePublicKey(pubB64 string) ([]byte, *ecdh.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(raw) != pubKeyRawLen || raw[0] != 0x04 {
		return nil, nil, ErrInvalidPublicKey
	}
	// Reject non-canonical base64 trailing bits so string equality matches key equality.
	if base64.RawURLEncoding.EncodeToString(raw) != pubB64 {
		return nil, nil, ErrInvalidPublicKey
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, nil, ErrInvalidPublicKey
	}
	return raw, pub, nil
}

// ValidatePublicKey checks that pubB64 is a canonical on-curve P-256 public key.
func ValidatePublicKey(pubB64 string) error {
	_, _, err := DecodePublicKey(pubB64)
	return err
}

// DecodePrivateKey validates and decodes a canonical base64url 32-byte P-256 private scalar.
func DecodePrivateKey(privB64 string) ([]byte, *ecdh.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(privB64)
	if err != nil || len(raw) != privKeyRawLen {
		return nil, nil, ErrInvalidPrivateKey
	}
	if base64.RawURLEncoding.EncodeToString(raw) != privB64 {
		return nil, nil, ErrInvalidPrivateKey
	}
	priv, err := ecdh.P256().NewPrivateKey(raw)
	if err != nil {
		return nil, nil, ErrInvalidPrivateKey
	}
	return raw, priv, nil
}

// PublicKeyFromPrivate derives the canonical base64url public key from privB64.
func PublicKeyFromPrivate(privB64 string) (string, error) {
	_, priv, err := DecodePrivateKey(privB64)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func toECDSAPublicKey(raw65 []byte) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw65[1:33]),
		Y:     new(big.Int).SetBytes(raw65[33:65]),
	}
}

func parseECDSAPrivateKey(privB64 string) (*ecdsa.PrivateKey, error) {
	raw, ecdhPriv, err := DecodePrivateKey(privB64)
	if err != nil {
		return nil, err
	}
	pubRaw := ecdhPriv.PublicKey().Bytes()
	return &ecdsa.PrivateKey{
		PublicKey: *toECDSAPublicKey(pubRaw),
		D:         new(big.Int).SetBytes(raw),
	}, nil
}

// DisplayFingerprint formats the first 64 bits of SHA-256(pubRaw65) as
// XXXX-XXXX-XXXX-XXXX uppercase hex, or "" if pubB64 is invalid.
func DisplayFingerprint(pubB64 string) string {
	raw, _, err := DecodePublicKey(pubB64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%04X-%04X-%04X-%04X",
		binary.BigEndian.Uint16(sum[0:2]),
		binary.BigEndian.Uint16(sum[2:4]),
		binary.BigEndian.Uint16(sum[4:6]),
		binary.BigEndian.Uint16(sum[6:8]),
	)
}

// InviteFingerprint returns base64url(SHA-256(pubRaw65)[0:16]) (128-bit
// commitment placed in the /join#<token>.<fp> URL fragment), or "" if invalid.
func InviteFingerprint(pubB64 string) string {
	raw, _, err := DecodePublicKey(pubB64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[0:16])
}

// SignP256 signs msg with ECDSA-P256-SHA256 in 64-byte IEEE P1363 format (r || s),
// matching WebCrypto crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}).
func SignP256(privB64 string, msg []byte) (string, error) {
	priv, err := parseECDSAPrivateKey(privB64)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	var sig [sigRawLen]byte
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	return base64.RawURLEncoding.EncodeToString(sig[:]), nil
}

// VerifyP256 verifies a 64-byte IEEE P1363 ECDSA-P256-SHA256 signature.
func VerifyP256(pubB64 string, msg []byte, sigB64 string) bool {
	pubRaw, _, err := DecodePublicKey(pubB64)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != sigRawLen {
		return false
	}
	if base64.RawURLEncoding.EncodeToString(sig) != sigB64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	digest := sha256.Sum256(msg)
	return ecdsa.Verify(toECDSAPublicKey(pubRaw), digest[:], r, s)
}

func appendLP(dst, b []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	dst = append(dst, n[:]...)
	return append(dst, b...)
}

func appendLPString(dst []byte, s string) []byte {
	return appendLP(dst, []byte(s))
}

func appendU64(dst []byte, v uint64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	return append(dst, n[:]...)
}

// DelegationBytes builds the canonical length-prefixed binary tuple signed by IK_dev.
func DelegationBytes(d Delegation) ([]byte, error) {
	ekRaw, _, err := DecodePublicKey(d.EKPub)
	if err != nil {
		return nil, err
	}
	if d.Exp < 0 {
		return nil, errors.New("e2e: negative delegation expiry")
	}
	buf := make([]byte, 0, 192)
	buf = append(buf, "rmm-e2e-del-v1\x00"...)
	buf = appendLPString(buf, d.SessionID)
	buf = appendLPString(buf, d.AgentID)
	buf = appendLPString(buf, NormalizeKind(d.Kind))
	buf = appendLPString(buf, d.GuestMode)
	buf = appendLP(buf, ekRaw)
	buf = appendU64(buf, uint64(d.Exp))
	return buf, nil
}

// SignDelegation signs a session delegation tuple using the agent's private key.
func SignDelegation(ikPrivB64 string, d Delegation) (string, error) {
	msg, err := DelegationBytes(d)
	if err != nil {
		return "", err
	}
	return SignP256(ikPrivB64, msg)
}

// VerifyDelegation verifies a session delegation signature against ikPubB64.
func VerifyDelegation(ikPubB64 string, d Delegation, sigB64 string) bool {
	msg, err := DelegationBytes(d)
	if err != nil {
		return false
	}
	return VerifyP256(ikPubB64, msg, sigB64)
}

// TranscriptInput binds every parameter of the viewer<->agent handshake.
type TranscriptInput struct {
	SessionID   string
	AgentID     string
	Kind        string
	GuestMode   string
	IKPubRaw    []byte
	EKViewerRaw []byte
	NonceViewer []byte
	EKAgentRaw  []byte
	NonceAgent  []byte
	Exp         int64
	SigDelRaw   []byte
}

// TranscriptHash computes the SHA-256 hash over the canonical handshake tuple.
func TranscriptHash(in TranscriptInput) [32]byte {
	buf := make([]byte, 0, 512)
	buf = append(buf, "rmm-e2e-hs-v1\x00"...)
	buf = appendLPString(buf, in.SessionID)
	buf = appendLPString(buf, in.AgentID)
	buf = appendLPString(buf, NormalizeKind(in.Kind))
	buf = appendLPString(buf, in.GuestMode)
	buf = appendLP(buf, in.IKPubRaw)
	buf = appendLP(buf, in.EKViewerRaw)
	buf = appendLP(buf, in.NonceViewer)
	buf = appendLP(buf, in.EKAgentRaw)
	buf = appendLP(buf, in.NonceAgent)
	buf = appendU64(buf, uint64(in.Exp))
	buf = appendLP(buf, in.SigDelRaw)
	return sha256.Sum256(buf)
}

// DeriveSessionKeys derives distinct viewer->agent and agent->viewer keys + IVs
// from the ECDH shared secret Z and transcript hash th via HKDF-SHA256.
func DeriveSessionKeys(sharedSecret []byte, th [32]byte) (SessionKeys, error) {
	var out SessionKeys
	if len(sharedSecret) != 32 {
		return out, errors.New("e2e: invalid shared secret length")
	}
	v2aK, err := hkdf.Key(sha256.New, sharedSecret, th[:], "rmm-e2e-v1 k v2a", 32)
	if err != nil {
		return out, err
	}
	v2aIV, err := hkdf.Key(sha256.New, sharedSecret, th[:], "rmm-e2e-v1 iv v2a", 12)
	if err != nil {
		return out, err
	}
	a2vK, err := hkdf.Key(sha256.New, sharedSecret, th[:], "rmm-e2e-v1 k a2v", 32)
	if err != nil {
		return out, err
	}
	a2vIV, err := hkdf.Key(sha256.New, sharedSecret, th[:], "rmm-e2e-v1 iv a2v", 12)
	if err != nil {
		return out, err
	}
	copy(out.V2AKey[:], v2aK)
	copy(out.V2AIV[:], v2aIV)
	copy(out.A2VKey[:], a2vK)
	copy(out.A2VIV[:], a2vIV)
	return out, nil
}

func newGCM(key [32]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func xorNonce(baseIV [12]byte, seq uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:], baseIV[:])
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= sb[i]
	}
	return nonce
}

func frameAAD(seq uint64, sessionID string) []byte {
	aad := make([]byte, HeaderSize+len(sessionID))
	aad[0] = FramePrefix
	binary.BigEndian.PutUint64(aad[1:9], seq)
	copy(aad[9:], sessionID)
	return aad
}
