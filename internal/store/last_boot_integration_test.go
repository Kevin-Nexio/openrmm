package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Runs in the PostgreSQL CI job. The last boot is the time the server stores an
// inventory minus the uptime reported in it: set by the first snapshot, kept
// while later snapshots only drift by seconds, moved by a reboot, and left alone
// by a snapshot without a usable uptime. Migration 036 fills it in from the
// snapshots stored before it existed.
func TestLastBootFromInventoryIntegration(t *testing.T) {
	url := os.Getenv("RMM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("RMM_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st := newIsolatedStore(t, "last_boot", url)

	agent := func(host string) string {
		t.Helper()
		a, err := st.CreateAgent(ctx, host, "windows", "amd64", "0.11.4", "hash-"+uuid.NewString(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	inventory := func(id, uptime string) {
		t.Helper()
		if err := st.UpsertInventory(ctx, id, []byte(`{"hostname":"pc","uptime_sec":`+uptime+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	boot := func(id string) *time.Time {
		t.Helper()
		a, err := st.GetAgent(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return a.LastBootAt
	}
	near := func(got *time.Time, want time.Time) bool {
		return got != nil && got.Sub(want).Abs() < time.Minute
	}

	pc := agent("PC-" + uuid.NewString()[:8])
	if b := boot(pc); b != nil {
		t.Fatalf("before any inventory: %v", b)
	}
	inventory(pc, "3600")
	first := boot(pc)
	if !near(first, time.Now().Add(-time.Hour)) {
		t.Fatalf("first snapshot: last boot %v, want about an hour ago", first)
	}

	// A later snapshot a few seconds off does not rewrite it.
	inventory(pc, "3630")
	if b := boot(pc); b == nil || !b.Equal(*first) {
		t.Fatalf("drift moved the last boot: %v, was %v", b, first)
	}

	// Snapshots without a usable uptime leave it alone.
	for _, bad := range []string{`"60"`, `null`, `-5`, `999999999999`} {
		inventory(pc, bad)
		if b := boot(pc); b == nil || !b.Equal(*first) {
			t.Fatalf("uptime %s changed the last boot: %v", bad, b)
		}
	}
	if err := st.UpsertInventory(ctx, pc, []byte(`{"hostname":"pc"}`)); err != nil {
		t.Fatal(err)
	}
	if b := boot(pc); b == nil || !b.Equal(*first) {
		t.Fatalf("a snapshot without uptime changed the last boot: %v", b)
	}

	// A reboot moves it.
	inventory(pc, "60")
	if b := boot(pc); !near(b, time.Now().Add(-time.Minute)) || !b.After(*first) {
		t.Fatalf("after a reboot: last boot %v, want about a minute ago", b)
	}

	// Migration 036 fills it in from a stored snapshot, skips an unusable
	// uptime and keeps a value already there.
	stored := agent("OLD-" + uuid.NewString()[:8])
	text := agent("TEXT-" + uuid.NewString()[:8])
	collected := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for id, data := range map[string]string{stored: `{"uptime_sec":7200}`, text: `{"uptime_sec":"7200"}`} {
		if _, err := st.pool.Exec(ctx, `INSERT INTO inventory (agent_id, data, collected_at) VALUES ($1,$2,$3)
			ON CONFLICT (agent_id) DO UPDATE SET data=EXCLUDED.data, collected_at=EXCLUDED.collected_at`, id, data, collected); err != nil {
			t.Fatal(err)
		}
	}
	kept := *boot(pc)
	if _, err := st.pool.Exec(ctx, migrationV36SQL); err != nil {
		t.Fatalf("migration 036 again: %v", err)
	}
	if b := boot(stored); b == nil || !b.Equal(collected.Add(-2*time.Hour)) {
		t.Fatalf("backfilled: %v, want %v", b, collected.Add(-2*time.Hour))
	}
	if b := boot(text); b != nil {
		t.Fatalf("a text uptime was backfilled: %v", b)
	}
	if b := boot(pc); b == nil || !b.Equal(kept) {
		t.Fatalf("the backfill overwrote a last boot: %v, was %v", b, kept)
	}
}
