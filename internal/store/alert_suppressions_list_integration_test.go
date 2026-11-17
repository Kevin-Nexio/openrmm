package store

import (
	"context"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/models"
)

// An unrestricted principal has no scope user. The list used to send that empty
// string as $1, which PostgreSQL reads as a uuid, so it failed for every
// administrator; a scoped reader, the only case tested, never saw the error.
func TestAlertSuppressionsListForUnscopedPrincipalIntegration(t *testing.T) {
	f := newAlertReliabilityFixture(t, "unscoped suppression list")
	ctx := context.Background()
	sup := &models.AlertSuppression{Kind: "maintenance", ScopeType: models.ScopeAgent, ScopeID: f.agent.ID,
		StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour), Reason: "unscoped list", CreatedBy: "admin"}
	if err := f.store.CreateAlertSuppression(ctx, sup); err != nil {
		t.Fatal(err)
	}
	listed := func(rows []models.AlertSuppression) bool {
		for _, row := range rows {
			if row.ID == sup.ID {
				return true
			}
		}
		return false
	}
	for _, activeOnly := range []bool{true, false} {
		rows, err := f.store.ListAlertSuppressions(ctx, "", false, activeOnly)
		if err != nil {
			t.Fatalf("unscoped list (active only %v): %v", activeOnly, err)
		}
		if !listed(rows) {
			t.Fatalf("unscoped list (active only %v) misses the suppression: %+v", activeOnly, rows)
		}
	}
	// The scoped path is unchanged: a reader of this agent sees it.
	reader, err := f.store.CreateUserWithScopes(ctx, "unscoped-list-reader", "hash", models.RoleTech,
		[]models.UserScope{{ScopeType: models.ScopeAgent, ScopeID: f.agent.ID}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.store.ListAlertSuppressions(ctx, reader.ID, true, true)
	if err != nil || !listed(rows) {
		t.Fatalf("scoped reader of the agent: %+v %v", rows, err)
	}
}
