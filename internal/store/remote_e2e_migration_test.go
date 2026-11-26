package store

import (
	"context"
	"slices"
	"testing"
)

func TestRemoteEncryptionMigrationPreservesLegacySessionsIntegration(t *testing.T) {
	st := newMigrationTestStore(t, databaseURLOrSkip(t))
	ctx := context.Background()
	idx := slices.IndexFunc(migrations, func(m migration) bool { return m.version == 42 })
	if idx < 0 {
		t.Fatal("migration 042 is not registered")
	}
	if err := st.migrate(ctx, migrations[:idx]); err != nil {
		t.Fatal(err)
	}

	// Use the historical schema so the fixture does not require E2E columns.
	agentID, sessionID := newID(), newID()
	if _, err := st.pool.Exec(ctx, `INSERT INTO agents (id, hostname, os, arch, version, token_hash)
		VALUES ($1,'legacy-agent','linux','amd64','0.12.3','test-hash')`, agentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO remote_sessions (id, agent_id, token, expires_at)
		VALUES ($1,$2,'',now() + interval '1 hour')`, sessionID, agentID); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	agent, err := st.GetAgent(ctx, agentID)
	if err != nil || agent.DevicePublicKey != "" || agent.Hostname != "legacy-agent" {
		t.Fatalf("legacy agent after migration: %+v, %v", agent, err)
	}
	session, err := st.GetRemoteSessionForAuthorization(ctx, sessionID)
	if err != nil || session.E2E || session.AgentID != agentID {
		t.Fatalf("legacy session after migration: %+v, %v", session, err)
	}
}
