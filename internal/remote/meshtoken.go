package remote

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MeshAccountName is a MeshCentral account name as MeshCentral's user ids
// ("user/<domain>/<name>") hold it. MeshCentral lower-cases the accounts it
// makes itself (local accounts, Windows sign-in, --user), but an account that
// signs in through a provider keeps the provider's identifier as it came:
// "~oidc:<sub>", "~saml:<nameID>", "~google:<id>", "~github:<id>" and the
// like. So a name that starts with '~' keeps its case, and any other is
// lower-cased; surrounding spaces are dropped.
func MeshAccountName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "~") {
		return name
	}
	return strings.ToLower(name)
}

// meshLoginTokenMinutes is how long a minted login token is accepted. The
// console opens the MeshCentral link in a new tab as soon as the session is
// made, so a few minutes is plenty; MeshCentral reads the cookie's "expire"
// in place of its own 60-minute timeout. It must never be 0: to MeshCentral
// an expire of 0 means the cookie never expires.
const meshLoginTokenMinutes = 5

// meshLoginToken builds a MeshCentral login token for ?login=, a Go port of
// MeshCentral's encodeCookie (AES-256-GCM). The server must run with
// "AllowLoginToken": true, and tokenKeyHex must be the server's loginTokenKey.
//
// Format (matching MeshCentral): AES-256-GCM with the first 32 bytes of the key,
// output = iv(12) || authTag(16) || ciphertext, base64 with '+'->'@' and '/'->'$'.
// The payload is what MeshCentral's own --logintoken mints, {u, a: 3}, plus the
// time encodeCookie adds: MeshCentral's root handler signs the browser in only
// when a === 3 and u names a user ("user/<domain>/<name>", the name as
// MeshAccountName gives it). On top of that the token is single use
// ("once": MeshCentral rejects a second use of the same value) and short lived
// ("expire", minutes). A first version sent {"userid", "domainid"}, which
// MeshCentral decrypted but never matched to a user, so the browser stayed on
// the sign-in page.
func meshLoginToken(tokenKeyHex, meshUser string) (string, error) {
	key, err := hex.DecodeString(strings.TrimSpace(tokenKeyHex))
	if err != nil {
		return "", fmt.Errorf("mesh token key is not valid hex: %w", err)
	}
	if len(key) < 32 {
		return "", fmt.Errorf("mesh token key too short (need >= 32 bytes, got %d)", len(key))
	}

	name := MeshAccountName(meshUser)
	if name == "" || strings.Contains(name, "/") {
		// The name comes from configuration; it is not echoed back to whoever
		// opened the session.
		return "", fmt.Errorf("the MeshCentral account name is empty or holds '/', which a MeshCentral user id cannot")
	}
	once := make([]byte, 16)
	if _, err := rand.Read(once); err != nil {
		return "", err
	}
	payload := map[string]any{
		"a":      3, // MeshCentral's login-token cookie
		"u":      "user//" + name,
		"once":   hex.EncodeToString(once),
		"expire": meshLoginTokenMinutes,
		"time":   time.Now().Unix(),
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block) // 12-byte nonce, 16-byte tag (MeshCentral defaults)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	// Go's Seal returns ciphertext||tag; MeshCentral expects iv||tag||ciphertext.
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	ct, tag := sealed[:len(sealed)-gcm.Overhead()], sealed[len(sealed)-gcm.Overhead():]
	out := make([]byte, 0, len(iv)+len(tag)+len(ct))
	out = append(out, iv...)
	out = append(out, tag...)
	out = append(out, ct...)

	b64 := base64.StdEncoding.EncodeToString(out)
	return strings.NewReplacer("+", "@", "/", "$").Replace(b64), nil
}
