package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/models"
)

// A key other than the pinned one is recorded for review, never pinned on the
// device's word; an administrator approves exactly the presented key.
func TestAgentDeviceKeyReviewIntegration(t *testing.T) {
	url := os.Getenv("RMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st := newIsolatedStore(t, "store_e2e_keys", url)

	agent, err := st.CreateAgent(ctx, "e2e-host-"+uuid.NewString(), "linux", "amd64", "0.13.0", "tok-"+uuid.NewString(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gen := func() string {
		_, pub, err := e2e.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	key1, key2, key3 := gen(), gen(), gen()
	check := func(p DeviceKeyPresentation, wantEvent, wantIssue string) DeviceKeyOutcome {
		t.Helper()
		out, err := st.CheckAgentDeviceKey(ctx, agent.ID, p, "203.0.113.7", "0.13.0")
		if err != nil {
			t.Fatal(err)
		}
		if out.Event != wantEvent || out.Issue != wantIssue {
			t.Fatalf("outcome = %+v, want event %q issue %q", out, wantEvent, wantIssue)
		}
		return out
	}
	stored := func() *models.Agent {
		t.Helper()
		a, err := st.GetAgent(ctx, agent.ID)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	check(DeviceKeyPresentation{}, DeviceKeyEventNone, "")
	check(DeviceKeyPresentation{Key: key1}, DeviceKeyEventPinned, "")
	check(DeviceKeyPresentation{Key: key1}, DeviceKeyEventNone, "")

	// A different key: recorded with where it came from, key1 still pinned.
	check(DeviceKeyPresentation{Key: key2}, DeviceKeyEventIssue, models.DeviceKeyChanged)
	check(DeviceKeyPresentation{Key: key2}, DeviceKeyEventIssueSeen, models.DeviceKeyChanged)
	a := stored()
	if a.DevicePublicKey != key1 || a.PendingDevicePublicKey != key2 || a.DeviceKeyIssueCount != 2 ||
		a.DeviceKeyIssueIP != "203.0.113.7" || a.DeviceKeyIssueVersion != "0.13.0" || a.DeviceKeyIssueSince == nil || a.DeviceKeyIssueSeenAt == nil {
		t.Fatalf("stored change = %+v", a)
	}

	// Approving anything but the exact presented key is refused.
	if _, err := st.ApproveAgentDeviceKey(ctx, agent.ID, key3, "admin"); !errors.Is(err, ErrDeviceKeyNotPending) {
		t.Fatalf("approve a key the device never presented = %v, want ErrDeviceKeyNotPending", err)
	}
	previous, err := st.ApproveAgentDeviceKey(ctx, agent.ID, key2, "admin")
	if err != nil || previous != key1 {
		t.Fatalf("approve = (%q, %v), want (key1, nil)", previous, err)
	}
	a = stored()
	if a.DevicePublicKey != key2 || a.DeviceKeyIssue != "" || a.PendingDevicePublicKey != "" || a.DeviceKeyChangedBy != "admin" || a.DeviceKeyChangedAt == nil {
		t.Fatalf("after approve = %+v", a)
	}
	if _, err := st.ApproveAgentDeviceKey(ctx, agent.ID, key2, "admin"); !errors.Is(err, ErrDeviceKeyNotPending) {
		t.Fatalf("approve twice = %v, want ErrDeviceKeyNotPending", err)
	}

	// The old key coming back is a change again, then the new one too: two machines.
	check(DeviceKeyPresentation{Key: key1}, DeviceKeyEventIssue, models.DeviceKeyChanged)
	check(DeviceKeyPresentation{Key: key2}, DeviceKeyEventIssue, models.DeviceKeyDuplicate)
	if _, err := st.ApproveAgentDeviceKey(ctx, agent.ID, key1, "admin"); !errors.Is(err, ErrDeviceKeyNotPending) {
		t.Fatalf("approve during duplicate = %v, want ErrDeviceKeyNotPending", err)
	}
	issue, pinned, pending, err := st.DismissAgentDeviceKeyIssue(ctx, agent.ID)
	if err != nil || issue != models.DeviceKeyDuplicate || pinned != key2 || pending != key1 {
		t.Fatalf("dismiss = (%q, %q, %q, %v)", issue, pinned, pending, err)
	}
	if _, _, _, err := st.DismissAgentDeviceKeyIssue(ctx, agent.ID); !errors.Is(err, ErrDeviceKeyNoIssue) {
		t.Fatalf("dismiss with no issue = %v, want ErrDeviceKeyNoIssue", err)
	}

	// Missing and outdated keys resolve on their own when the pinned key returns.
	check(DeviceKeyPresentation{Unavailable: true}, DeviceKeyEventIssue, models.DeviceKeyMissing)
	check(DeviceKeyPresentation{Key: key2}, DeviceKeyEventResolved, "")
	check(DeviceKeyPresentation{}, DeviceKeyEventIssue, models.DeviceKeyOutdated)
	check(DeviceKeyPresentation{Key: key2}, DeviceKeyEventResolved, "")

	// Duplicate connections are raised once.
	raised, err := st.MarkAgentDeviceDuplicate(ctx, agent.ID, "198.51.100.2", "0.13.0")
	if err != nil || !raised {
		t.Fatalf("first duplicate mark = (%v, %v), want (true, nil)", raised, err)
	}
	raised, err = st.MarkAgentDeviceDuplicate(ctx, agent.ID, "198.51.100.3", "0.13.0")
	if err != nil || raised {
		t.Fatalf("second duplicate mark = (%v, %v), want (false, nil)", raised, err)
	}
	if a := stored(); a.DeviceKeyIssue != models.DeviceKeyDuplicate || a.DevicePublicKey != key2 {
		t.Fatalf("after duplicate mark = %+v", a)
	}

	// A revoked agent is not found.
	if err := st.RevokeAgent(ctx, agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CheckAgentDeviceKey(ctx, agent.ID, DeviceKeyPresentation{Key: key2}, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked agent = %v, want ErrNotFound", err)
	}
}
