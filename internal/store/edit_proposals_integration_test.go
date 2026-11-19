package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/p1ngu/rmm/internal/models"
)

// Runs in the PostgreSQL CI job. A claim to apply an edit proposal blocks
// other approvers only while it can still be running: after 15 minutes (a
// crash mid-apply) anyone may claim or decide it.
func TestEditProposalClaimExpiresIntegration(t *testing.T) {
	f := newPolicyFixture(t)
	ctx := context.Background()
	p, err := f.store.CreateEditProposal(ctx, &models.EditProposal{Kind: models.EditPolicy, TargetID: newID(), BaseHash: "h",
		Changes: json.RawMessage(`{"fields":{"name":"x"}}`), Reason: "r", ProposedBy: "ai:t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ClaimEditProposal(ctx, p.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ClaimEditProposal(ctx, p.ID, "bob"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second claim = %v", err)
	}
	if err := f.store.FinishEditProposal(ctx, p.ID, models.EditRejected, "bob", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("another approver decided a claimed proposal: %v", err)
	}
	if _, err := f.store.pool.Exec(ctx, `UPDATE edit_proposals SET claimed_at = now() - interval '1 hour' WHERE id=$1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ClaimEditProposal(ctx, p.ID, "bob"); err != nil {
		t.Fatalf("a stale claim still blocks: %v", err)
	}
	if err := f.store.FinishEditProposal(ctx, p.ID, models.EditApplied, "bob", "done"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.GetEditProposal(ctx, p.ID); got.Status != models.EditApplied || got.DecidedBy != "bob" {
		t.Fatalf("after finishing = %+v", got)
	}
}
