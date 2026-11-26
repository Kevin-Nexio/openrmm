package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOAuthRequiresHTTPSMCPOrigin(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_MCP_OAUTH_ENABLED", "true")
	t.Setenv("RMM_MCP_PUBLIC_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("OAuth started without an MCP public URL")
	}

	t.Setenv("RMM_MCP_PUBLIC_URL", "http://mcp.example.test")
	if _, err := Load(); err == nil {
		t.Fatal("OAuth started with a non-HTTPS MCP public URL")
	}

	t.Setenv("RMM_MCP_PUBLIC_URL", "https://mcp.example.test/")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MCPPublicURL != "https://mcp.example.test" {
		t.Fatalf("MCPPublicURL = %q", cfg.MCPPublicURL)
	}
}

func TestConsoleIngressEnforcementRequiresTrustedProxy(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_MCP_OAUTH_ENABLED", "false")
	t.Setenv("RMM_ENFORCE_CONSOLE_RELAY_INGRESS", "true")
	t.Setenv("RMM_TRUST_PROXY_HEADERS", "false")
	if _, err := Load(); err == nil {
		t.Fatal("console relay enforcement started without a trusted proxy")
	}

	t.Setenv("RMM_TRUST_PROXY_HEADERS", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("Load with trusted proxy: %v", err)
	}
}

func TestLoadReadsFileBackedSecrets(t *testing.T) {
	dir := t.TempDir()
	writeSecret := func(name, value string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Setenv("RMM_ADMIN_TOKEN_FILE", writeSecret("admin", strings.Repeat("a", 32)))
	t.Setenv("RMM_SETTINGS_ENCRYPTION_KEY_FILE", writeSecret("settings", strings.Repeat("s", 32)))
	t.Setenv("RMM_DATABASE_PASSWORD_FILE", writeSecret("database", "p@ss/word"))
	t.Setenv("RMM_DATABASE_URL", "postgres://rmm@postgres:5432/rmm?sslmode=disable")
	t.Setenv("RMM_REQUIRE_SETTINGS_ENCRYPTION_KEY", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SettingsEncryptionKey != strings.Repeat("s", 32) {
		t.Fatal("settings encryption key was not read from its secret file")
	}
	if cfg.DatabaseURL != "postgres://rmm:p%40ss%2Fword@postgres:5432/rmm?sslmode=disable" {
		t.Fatalf("DatabaseURL = %q", cfg.DatabaseURL)
	}
}

func TestLoadRequiresDedicatedSettingsKeyWhenConfigured(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_SETTINGS_ENCRYPTION_KEY", "")
	t.Setenv("RMM_REQUIRE_SETTINGS_ENCRYPTION_KEY", "true")
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted a missing production settings encryption key")
	}
}

func TestOIDCRequiresIssuerClientAndHTTPS(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_OIDC_ENABLED", "true")

	if _, err := Load(); err == nil {
		t.Fatal("single sign-on started with no issuer")
	}

	t.Setenv("RMM_OIDC_ISSUER", "https://idp.example.test")
	if _, err := Load(); err == nil {
		t.Fatal("single sign-on started with no client id")
	}

	// Discovery, the token exchange and the JWKS fetch all use this URL. Plain
	// HTTP would put the client secret and the authorization code on the wire.
	t.Setenv("RMM_OIDC_CLIENT_ID", "rmm-console")
	t.Setenv("RMM_OIDC_ISSUER", "http://idp.example.test")
	if _, err := Load(); err == nil {
		t.Fatal("single sign-on started against a plain-HTTP issuer")
	}

	t.Setenv("RMM_OIDC_ISSUER", "https://idp.example.test/")
	t.Setenv("RMM_PUBLIC_URL", "https://rmm.example.test")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDCIssuer != "https://idp.example.test" {
		t.Errorf("issuer = %q, want the trailing slash trimmed to match discovery", cfg.OIDCIssuer)
	}
	// Derived rather than demanded: one fewer thing to get wrong, and it has to
	// match what was registered with the provider.
	if want := "https://rmm.example.test/api/auth/oidc/callback"; cfg.OIDCRedirectURL != want {
		t.Errorf("redirect URL = %q, want %q", cfg.OIDCRedirectURL, want)
	}
}

// Without the openid scope a provider returns no ID token at all, and there is
// nothing to verify. Adding it back beats failing at the first sign-in with a
// message nobody can act on.
func TestOIDCAlwaysRequestsTheOpenIDScope(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_OIDC_ENABLED", "true")
	t.Setenv("RMM_OIDC_ISSUER", "https://idp.example.test")
	t.Setenv("RMM_OIDC_CLIENT_ID", "rmm-console")
	t.Setenv("RMM_PUBLIC_URL", "https://rmm.example.test")
	t.Setenv("RMM_OIDC_SCOPES", "profile,email")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.OIDCScopes) == 0 || cfg.OIDCScopes[0] != "openid" {
		t.Errorf("scopes = %v, want openid first", cfg.OIDCScopes)
	}
}

func TestOIDCAuthenticationContextSettings(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_OIDC_ENABLED", "false")
	t.Setenv("RMM_OIDC_ACR_VALUES", " urn:example:acr:mfa, another-context ,")
	t.Setenv("RMM_OIDC_REQUIRED_AMR", " otp, mfa ,")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.OIDCACRValues, "|"); got != "urn:example:acr:mfa|another-context" {
		t.Fatalf("ACR = %q", got)
	}
	if got := strings.Join(cfg.OIDCRequiredAMR, "|"); got != "otp|mfa" {
		t.Fatalf("AMR = %q", got)
	}
}

// Auto-provisioning plus an admin default would make everyone the provider will
// authenticate an administrator here — for a Google Workspace or Entra tenant,
// the whole company. Refuse the combination rather than log a warning nobody
// reads.
func TestOIDCRefusesAutoProvisionedAdmins(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_OIDC_ENABLED", "true")
	t.Setenv("RMM_OIDC_ISSUER", "https://idp.example.test")
	t.Setenv("RMM_OIDC_CLIENT_ID", "rmm-console")
	t.Setenv("RMM_PUBLIC_URL", "https://rmm.example.test")
	t.Setenv("RMM_OIDC_AUTO_PROVISION", "true")
	t.Setenv("RMM_OIDC_DEFAULT_ROLE", "admin")

	if _, err := Load(); err == nil {
		t.Fatal("auto-provisioning into the admin role was accepted")
	}

	t.Setenv("RMM_OIDC_DEFAULT_ROLE", "readonly")
	if _, err := Load(); err != nil {
		t.Fatalf("Load with a safe default role: %v", err)
	}
}

// Off is off: nothing about a half-configured provider should stop the server
// from starting when the feature was never turned on.
func TestOIDCDisabledIgnoresItsOwnSettings(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_OIDC_ENABLED", "false")
	t.Setenv("RMM_OIDC_ISSUER", "http://not-even-https")
	t.Setenv("RMM_OIDC_CLIENT_ID", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OIDCEnabled {
		t.Error("OIDC reported as enabled")
	}
}

// The console builds its install command from these keys, and the installers
// refuse a production install without one, so a malformed value must stop the
// server rather than reach a technician's clipboard.
// The ad-hoc macOS bundle is offered unless the operator turns it off.
func TestMacOSAdhocBundle(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	for value, want := range map[string]bool{"": true, "true": true, "false": false} {
		t.Setenv("RMM_MACOS_ADHOC_BUNDLE", value)
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.MacOSAdhocBundle != want {
			t.Errorf("RMM_MACOS_ADHOC_BUNDLE=%q: offered=%v, want %v", value, c.MacOSAdhocBundle, want)
		}
	}
}

func TestUpdatePublicKeys(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	keyA := base64.StdEncoding.EncodeToString(make([]byte, 32))
	keyB := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))

	t.Setenv("RMM_UPDATE_PUBLIC_KEY", "")
	c, err := Load()
	if err != nil || len(c.UpdatePublicKeys) != 0 {
		t.Fatalf("unset: keys=%v err=%v", c.UpdatePublicKeys, err)
	}

	// A rotation carries two, in whatever separator the installers accept;
	// a repeated key is listed once.
	t.Setenv("RMM_UPDATE_PUBLIC_KEY", keyA+", "+keyB+";"+keyA)
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.UpdatePublicKeys, ","); got != keyA+","+keyB {
		t.Fatalf("keys = %q", got)
	}

	// Hex included: a 64-character hex key is valid base64 of the wrong length,
	// and the agent would reject it after the install command was copied.
	hexKey := strings.Repeat("ab", 32)
	for _, bad := range []string{"not-a-key", base64.StdEncoding.EncodeToString(make([]byte, 31)), keyA + ",zz", hexKey} {
		t.Setenv("RMM_UPDATE_PUBLIC_KEY", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "RMM_UPDATE_PUBLIC_KEY") {
			t.Fatalf("%q: err = %v, want a refusal naming RMM_UPDATE_PUBLIC_KEY", bad, err)
		}
	}
}

// RMM_MANIFEST_PUBLIC_KEY: base64 SPKI DER ECDSA P-256 keys, separated like the
// update keys. Anything else stops the server, rather than reaching an install
// command that fails on every Mac without OpenSSL 3.
func TestManifestPublicKeys(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_UPDATE_PUBLIC_KEY", "")
	spki := func(curve elliptic.Curve) string {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}
	keyA, keyB := spki(elliptic.P256()), spki(elliptic.P256())

	t.Setenv("RMM_MANIFEST_PUBLIC_KEY", "")
	c, err := Load()
	if err != nil || len(c.ManifestPublicKeys) != 0 {
		t.Fatalf("unset: keys=%v err=%v", c.ManifestPublicKeys, err)
	}
	t.Setenv("RMM_MANIFEST_PUBLIC_KEY", keyA+", "+keyB+";"+keyA)
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.ManifestPublicKeys, ","); got != keyA+","+keyB {
		t.Fatalf("keys = %q", got)
	}

	ed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, bad := range []string{"not-a-key", ed, spki(elliptic.P384()), keyA + ",zz"} {
		t.Setenv("RMM_MANIFEST_PUBLIC_KEY", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "RMM_MANIFEST_PUBLIC_KEY") {
			t.Fatalf("%q: err = %v, want a refusal naming RMM_MANIFEST_PUBLIC_KEY", bad, err)
		}
	}
}

// The single sign-on button is shown unless RMM_OIDC_SHOW_BUTTON=false: the
// first login step sends linked and marked accounts to the provider, and the
// button is how a local account does its first single sign-on.
func TestOIDCShowButton(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	for value, want := range map[string]bool{"": true, "true": true, "false": false} {
		t.Setenv("RMM_OIDC_SHOW_BUTTON", value)
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.OIDCShowButton != want {
			t.Errorf("RMM_OIDC_SHOW_BUTTON=%q: %v, want %v", value, c.OIDCShowButton, want)
		}
	}
}

// Reset, confirmation and export tokens ride on links built from the console
// origin: a value that is not an absolute http(s) base refuses to start rather
// than mail broken or misdirected links.
func TestConsolePublicURLMustBeAnAbsoluteBase(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	for _, bad := range []string{
		"console.example.test",
		"javascript:alert(1)",
		"ftp://console.example.test",
		"https://",
		"https://user:pass@console.example.test",
		"https://console.example.test/?next=x",
		"https://console.example.test/#x",
		"https://console.example.test?",
		"https://console.example.test#",
		"https://console.example.test:99999",
		"https://console.example.test/..//evil.test",
		"https://console.example.test//evil.test",
		"https://console.example.test/%2e%2e/console",
		`https://console.example.test\@evil.test`,
		" https://console.example.test",
	} {
		t.Setenv("RMM_CONSOLE_PUBLIC_URL", bad)
		if _, err := Load(); err == nil {
			t.Errorf("RMM_CONSOLE_PUBLIC_URL=%q was accepted", bad)
		}
	}
	for _, good := range []string{"https://console.example.test/", "https://example.test/rmm", "https://example.test/rmm/console/", "http://localhost:5173", "https://[::1]:8443"} {
		t.Setenv("RMM_CONSOLE_PUBLIC_URL", good)
		if _, err := Load(); err != nil {
			t.Errorf("RMM_CONSOLE_PUBLIC_URL=%q refused: %v", good, err)
		}
	}
}

// The single sign-on callback is a console page. On a split ingress the agents
// origin answers 404 for it, so the default follows the console origin; an
// explicit RMM_OIDC_REDIRECT_URL and a single-origin installation are unchanged.
func TestOIDCCallbackDefaultsToTheConsoleOrigin(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	t.Setenv("RMM_OIDC_ENABLED", "true")
	t.Setenv("RMM_OIDC_ISSUER", "https://idp.example.test")
	t.Setenv("RMM_OIDC_CLIENT_ID", "rmm-console")
	t.Setenv("RMM_PUBLIC_URL", "https://agents.example.test")
	load := func() string {
		t.Helper()
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return cfg.OIDCRedirectURL
	}
	if got := load(); got != "https://agents.example.test/api/auth/oidc/callback" {
		t.Errorf("single-origin callback = %q", got)
	}
	t.Setenv("RMM_CONSOLE_PUBLIC_URL", "https://console.example.test")
	if got := load(); got != "https://console.example.test/api/auth/oidc/callback" {
		t.Errorf("split-ingress callback = %q, want the console origin", got)
	}
	// A console under a base path: the callback is an /api route, which nginx
	// serves at the origin root.
	t.Setenv("RMM_CONSOLE_PUBLIC_URL", "https://console.example.test/console/")
	if got := load(); got != "https://console.example.test/api/auth/oidc/callback" {
		t.Errorf("base-path callback = %q, want the console origin", got)
	}
	t.Setenv("RMM_OIDC_REDIRECT_URL", "https://sso.example.test/api/auth/oidc/callback")
	if got := load(); got != "https://sso.example.test/api/auth/oidc/callback" {
		t.Errorf("explicit callback = %q, want it kept", got)
	}
}

// Console pages keep the console's base path; /api routes answer at the
// origin root. Without RMM_CONSOLE_PUBLIC_URL both stay RMM_PUBLIC_URL.
func TestConsolePageAndAPIBases(t *testing.T) {
	c := &Config{PublicURL: "https://agents.example.test", ConsolePublicURL: "https://example.test/console"}
	if got := c.NotificationConsoleURL(); got != "https://example.test/console" {
		t.Errorf("page base = %q", got)
	}
	if got := c.ConsoleAPIBase(); got != "https://example.test" {
		t.Errorf("API base = %q, want the origin", got)
	}
	c = &Config{PublicURL: "https://rmm.example.test/"}
	if got := c.ConsoleAPIBase(); got != "https://rmm.example.test" {
		t.Errorf("single-origin API base = %q", got)
	}
}

func TestRemoteE2EPolicy(t *testing.T) {
	t.Setenv("RMM_ADMIN_TOKEN", strings.Repeat("a", 32))
	for value, want := range map[string]string{
		"":            "preferred",
		"preferred":   "preferred",
		"required":    "required",
		" REQUIRED ":  "required",
		" Preferred ": "preferred",
	} {
		t.Setenv("RMM_REMOTE_E2E_POLICY", value)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("RMM_REMOTE_E2E_POLICY=%q: unexpected error: %v", value, err)
		}
		if cfg.RemoteE2EPolicy != want {
			t.Errorf("RMM_REMOTE_E2E_POLICY=%q: got %q, want %q", value, cfg.RemoteE2EPolicy, want)
		}
	}
	for _, bad := range []string{"off", "disabled", "optional", "legacy"} {
		t.Setenv("RMM_REMOTE_E2E_POLICY", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "RMM_REMOTE_E2E_POLICY") {
			t.Errorf("RMM_REMOTE_E2E_POLICY=%q: err = %v, want refusal naming RMM_REMOTE_E2E_POLICY", bad, err)
		}
	}
}
