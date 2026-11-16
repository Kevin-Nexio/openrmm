package remote

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const testMeshKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// decodeMeshToken reverses the token the way MeshCentral's decodeCookieAESGCM
// does: '@'->'+' and '$'->'/', base64, then iv(12) || tag(16) || ciphertext
// under AES-256-GCM with the first 32 bytes of the key.
func decodeMeshToken(t *testing.T, tok string) map[string]any {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.NewReplacer("@", "+", "$", "/").Replace(tok))
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if len(raw) < 12+16 {
		t.Fatalf("token too short: %d", len(raw))
	}
	iv, tag, ct := raw[:12], raw[12:28], raw[28:]
	key, _ := hex.DecodeString(testMeshKeyHex)
	block, _ := aes.NewCipher(key[:32])
	gcm, _ := cipher.NewGCM(block)
	// Go expects ciphertext||tag; the token carries iv||tag||ciphertext.
	plain, err := gcm.Open(nil, iv, append(append([]byte{}, ct...), tag...), nil)
	if err != nil {
		t.Fatalf("gcm open: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatalf("json: %v", err)
	}
	return payload
}

// The token is what MeshCentral's root handler signs in with (?login=): a === 3
// and u naming "user/<domain>/<name>" for the default domain, as MeshCentral's
// own --logintoken mints it. It is single use (once) and short lived (expire,
// never 0, which MeshCentral reads as "never expires"). The first version's
// {"userid","domainid"} — decrypted by MeshCentral but matched to no user —
// is gone.
func TestMeshLoginTokenIsWhatMeshCentralSignsInWith(t *testing.T) {
	before := time.Now().Unix()
	tok, err := meshLoginToken(testMeshKeyHex, "admin")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	p := decodeMeshToken(t, tok)
	if p["a"] != float64(3) {
		t.Fatalf("a = %v, want 3", p["a"])
	}
	u, ok := p["u"].(string)
	if !ok || u != "user//admin" {
		t.Fatalf("u = %v, want user//admin", p["u"])
	}
	// MeshCentral's root handler also requires u.split('/')[1] == domain.id ("" by default).
	if parts := strings.Split(u, "/"); len(parts) != 3 || parts[1] != "" {
		t.Fatalf("u %q is not in the default domain", u)
	}
	if once, _ := p["once"].(string); len(once) != 32 {
		t.Fatalf("once = %v, want 32 hex characters", p["once"])
	} else if _, err := hex.DecodeString(once); err != nil {
		t.Fatalf("once is not hex: %v", once)
	}
	if p["expire"] != float64(meshLoginTokenMinutes) || meshLoginTokenMinutes <= 0 {
		t.Fatalf("expire = %v, want %d (and never 0)", p["expire"], meshLoginTokenMinutes)
	}
	at, ok := p["time"].(float64)
	if !ok || int64(at) < before || int64(at) > time.Now().Unix() {
		t.Fatalf("time = %v, want the Unix second it was made", p["time"])
	}
	for _, stale := range []string{"userid", "domainid"} {
		if _, ok := p[stale]; ok {
			t.Fatalf("payload still carries %q: %v", stale, p)
		}
	}
}

// MeshCentral lower-cases the accounts it makes, but keeps the provider's id
// as it came for an account that signs in through a provider (~oidc:, ~saml:,
// ~google:, …): lower-casing that id would name no account.
func TestMeshAccountNameFollowsMeshCentral(t *testing.T) {
	for in, want := range map[string]string{
		"  Admin.Ops ":                "admin.ops",
		"Tech.One@Example.com":        "tech.one@example.com",
		"~oidc:00uAbC123":             "~oidc:00uAbC123",
		" ~saml:Jane.Doe@Example.com": "~saml:Jane.Doe@Example.com",
		"~google:1077":                "~google:1077",
		"~":                           "~",
		"":                            "",
	} {
		if got := MeshAccountName(in); got != want {
			t.Fatalf("MeshAccountName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The shared account name is saved as typed, so the token applies the same
// rule, and every token gets its own once value.
func TestMeshLoginTokenNormalisesTheAccountAndIsUniquePerToken(t *testing.T) {
	a, err := meshLoginToken(testMeshKeyHex, "  Admin.Ops ")
	if err != nil {
		t.Fatal(err)
	}
	b, err := meshLoginToken(testMeshKeyHex, "admin.ops")
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := decodeMeshToken(t, a), decodeMeshToken(t, b)
	if pa["u"] != "user//admin.ops" || pb["u"] != "user//admin.ops" {
		t.Fatalf("u = %v / %v, want user//admin.ops", pa["u"], pb["u"])
	}
	if pa["once"] == pb["once"] {
		t.Fatal("two tokens share a once value")
	}
	c, err := meshLoginToken(testMeshKeyHex, "~oidc:00uAbC123")
	if err != nil {
		t.Fatal(err)
	}
	if u := decodeMeshToken(t, c)["u"]; u != "user//~oidc:00uAbC123" {
		t.Fatalf("u = %v, want the provider account with its case kept", u)
	}
}

// A name MeshCentral could not hold as an account — empty, or with a '/'
// that would move it to another domain in the user id — is refused, and so is
// a key that is not hex or too short.
func TestMeshLoginTokenRefusesNamesThatAreNotAccounts(t *testing.T) {
	for _, bad := range []string{"", "   ", "evil/admin", "/admin"} {
		if _, err := meshLoginToken(testMeshKeyHex, bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	for _, bad := range []string{"zz", "0011"} {
		if _, err := meshLoginToken(bad, "admin"); err == nil {
			t.Fatalf("key %q accepted", bad)
		}
	}
}
