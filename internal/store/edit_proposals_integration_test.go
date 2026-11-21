package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/models"
)

// A decision has exclusive ownership of the row until it commits or rolls
// back. A second connection cannot decide or replace it, even if it would use
// the same audit actor. Rollback releases ownership without a lease timeout.
func TestEditProposalDecisionLockIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	ctx := f.ctx
	draft := &models.EditProposal{Kind: models.EditPolicy, TargetID: newID(), BaseHash: "h",
		Changes: json.RawMessage(`{"fields":{"name":"x"}}`), Reason: "r", ProposedBy: "ai:t"}
	p, err := f.store.CreateEditProposal(ctx, draft)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := errors.New("rollback test decision")
	err = f.store.InConfigTransaction(ctx, func(tx *Store) error {
		if _, err := tx.LockEditProposal(ctx, p.ID); err != nil {
			return err
		}
		// This uses another pool connection, not a savepoint of the owner.
		second := f.store.InConfigTransaction(ctx, func(other *Store) error {
			if _, err := other.LockEditProposal(ctx, p.ID); err != nil {
				return err
			}
			return other.FinishEditProposal(ctx, p.ID, models.EditRejected, "api", "")
		})
		if !errors.Is(second, ErrConflict) {
			t.Fatalf("concurrent decision = %v, want conflict", second)
		}
		if _, err := f.store.CreateEditProposal(ctx, draft); !errors.Is(err, ErrConflict) {
			t.Fatalf("concurrent replacement = %v, want conflict", err)
		}
		if err := tx.FinishEditProposal(ctx, p.ID, models.EditApplied, "api", "discarded"); err != nil {
			return err
		}
		return rolledBack
	})
	if !errors.Is(err, rolledBack) {
		t.Fatalf("first decision = %v", err)
	}
	err = f.store.InConfigTransaction(ctx, func(tx *Store) error {
		got, err := tx.LockEditProposal(ctx, p.ID)
		if err != nil {
			return err
		}
		if got.Status != models.EditPending || got.DecidedBy != "" {
			t.Fatalf("rolled-back decision persisted: %+v", got)
		}
		return tx.FinishEditProposal(ctx, p.ID, models.EditApplied, "api", "done")
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.GetEditProposal(ctx, p.ID); err != nil || got.Status != models.EditApplied || got.Outcome != "done" {
		t.Fatalf("committed decision = %+v, %v", got, err)
	}
}

func TestLegacyEditProposalClaimExpiresIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	ctx := f.ctx
	p, err := f.store.CreateEditProposal(ctx, &models.EditProposal{Kind: models.EditPolicy, TargetID: newID(), BaseHash: "h",
		Changes: json.RawMessage(`{"fields":{"name":"x"}}`), Reason: "r", ProposedBy: "ai:t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.pool.Exec(ctx, "UPDATE edit_proposals SET decided_by='legacy', claimed_at=now() WHERE id=$1", p.ID); err != nil {
		t.Fatal(err)
	}
	decide := func(tx *Store) error {
		if _, err := tx.LockEditProposal(ctx, p.ID); err != nil {
			return err
		}
		return tx.FinishEditProposal(ctx, p.ID, models.EditApplied, "reviewer", "done")
	}
	if err := f.store.InConfigTransaction(ctx, decide); !errors.Is(err, ErrConflict) {
		t.Fatalf("active legacy claim = %v, want conflict", err)
	}
	if _, err := f.store.pool.Exec(ctx, "UPDATE edit_proposals SET claimed_at=now()-interval '1 hour' WHERE id=$1", p.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.InConfigTransaction(ctx, decide); err != nil {
		t.Fatalf("expired legacy claim = %v", err)
	}
}

// A checked configuration's current definition and links must remain stable
// until the decision is committed. These rows also cover non-HTTP writers,
// such as direct deletion by a cascading foreign key.
func TestConfigTargetLocksDefinitionAndLinksIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	task, err := f.store.CreateTask(f.ctx, &models.Task{Name: "Scheduled test", Shell: "bash", Script: "true",
		IntervalSec: 3600, ScheduleKind: models.ScheduleInterval, Attachments: models.OnAgent(&f.agentA.ID)})
	if err != nil {
		t.Fatal(err)
	}
	err = f.store.InConfigTransaction(f.ctx, func(tx *Store) error {
		if err := tx.LockConfigTarget(f.ctx, models.EditTask, task.ID, true); err != nil {
			return err
		}
		// Runtime rows that reference the task use key-share locks, which
		// are compatible with a configuration edit that leaves the id alone.
		if _, err := f.store.pool.Exec(f.ctx, "SELECT 1 FROM tasks WHERE id=$1 FOR KEY SHARE NOWAIT", task.ID); err != nil {
			t.Fatalf("key-share lock blocked alongside a configuration edit: %v", err)
		}
		for _, lock := range []struct{ query, id string }{
			{"SELECT 1 FROM tasks WHERE id=$1 FOR UPDATE NOWAIT", task.ID},
			{"SELECT 1 FROM task_attachments WHERE task_id=$1 FOR UPDATE NOWAIT", task.ID},
			{"SELECT 1 FROM agents WHERE id=$1 FOR NO KEY UPDATE NOWAIT", f.agentA.ID},
		} {
			_, err := f.store.pool.Exec(f.ctx, lock.query, lock.id)
			if !errors.Is(configLockError(err), ErrConflict) {
				t.Fatalf("another connection acquired a protected row, err = %v", err)
			}
		}
		attachCtx, cancel := context.WithTimeout(f.ctx, 250*time.Millisecond)
		defer cancel()
		if err := f.store.AttachTask(attachCtx, task.ID, models.Attachment{AgentID: &f.agentB.ID}); err == nil || attachCtx.Err() == nil {
			t.Fatalf("another connection attached while the definition was locked: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.AttachTask(context.Background(), task.ID, models.Attachment{AgentID: &f.agentB.ID}); err != nil {
		t.Fatalf("attaching after the lock was released: %v", err)
	}
}
