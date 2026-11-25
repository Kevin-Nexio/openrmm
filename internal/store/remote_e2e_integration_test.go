package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/e2e"
)

func TestVerifyOrPinAgentPublicKeyIntegration(t *testing.T) {
	url := os.Getenv("RMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st := newIsolatedStore(t, "store_e2e_pin", url)

	agent, err := st.CreateAgent(ctx, "e2e-host-"+uuid.NewString(), "linux", "amd64", "0.12.3", "tok-"+uuid.NewString(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, key1, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, key2, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Legacy agent with no pinned key yet may reconnect without a key.
	pinned, err := st.VerifyOrPinAgentPublicKey(ctx, agent.ID, "")
	if err != nil || pinned {
		t.Fatalf("legacy empty reconnect = (%v, %v), want (false, nil)", pinned, err)
	}

	// First non-empty registration pins the device key.
	pinned, err = st.VerifyOrPinAgentPublicKey(ctx, agent.ID, key1)
	if err != nil || !pinned {
		t.Fatalf("first pin = (%v, %v), want (true, nil)", pinned, err)
	}
	got, err := st.GetAgent(ctx, agent.ID)
	if err != nil || got.DevicePublicKey != key1 {
		t.Fatalf("stored key after pin = %q, err=%v, want %q", got.DevicePublicKey, err, key1)
	}

	// Subsequent registration with the same key succeeds without re-pinning.
	pinned, err = st.VerifyOrPinAgentPublicKey(ctx, agent.ID, key1)
	if err != nil || pinned {
		t.Fatalf("matching reconnect = (%v, %v), want (false, nil)", pinned, err)
	}

	// A different key must fail with ErrAgentKeyMismatch and preserve key1.
	pinned, err = st.VerifyOrPinAgentPublicKey(ctx, agent.ID, key2)
	if !errors.Is(err, ErrAgentKeyMismatch) || pinned {
		t.Fatalf("mismatched key = (%v, %v), want (false, ErrAgentKeyMismatch)", pinned, err)
	}

	// An empty key after pinning must also fail with ErrAgentKeyMismatch (anti-downgrade).
	pinned, err = st.VerifyOrPinAgentPublicKey(ctx, agent.ID, "")
	if !errors.Is(err, ErrAgentKeyMismatch) || pinned {
		t.Fatalf("empty key after pin = (%v, %v), want (false, ErrAgentKeyMismatch)", pinned, err)
	}
	got, err = st.GetAgent(ctx, agent.ID)
	if err != nil || got.DevicePublicKey != key1 {
		t.Fatalf("stored key mutated after rejections = %q, err=%v, want %q", got.DevicePublicKey, err, key1)
	}

	// A revoked agent must fail with ErrNotFound.
	if err := st.RevokeAgent(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyOrPinAgentPublicKey(ctx, agent.ID, key1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked agent = %v, want ErrNotFound", err)
	}
}
