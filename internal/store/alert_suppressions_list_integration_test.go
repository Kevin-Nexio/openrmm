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

// The active filter ($3) on the unscoped path: a canceled window leaves the
// active list, stays in the full one with its cancellation, and an active one
// is in both.
func TestAlertSuppressionsActiveFilterForUnscopedPrincipalIntegration(t *testing.T) {
	f := newAlertReliabilityFixture(t, "unscoped suppression filter")
	ctx := context.Background()
	window := func(reason string) *models.AlertSuppression {
		t.Helper()
		sup := &models.AlertSuppression{Kind: models.SuppressionSilence, ScopeType: models.ScopeAgent, ScopeID: f.agent.ID,
			StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour), Reason: reason, CreatedBy: "admin"}
		if err := f.store.CreateAlertSuppression(ctx, sup); err != nil {
			t.Fatal(err)
		}
		return sup
	}
	active, canceled := window("still on"), window("called off")
	if err := f.store.CancelAlertSuppression(ctx, canceled.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	find := func(rows []models.AlertSuppression, id string) *models.AlertSuppression {
		for i := range rows {
			if rows[i].ID == id {
				return &rows[i]
			}
		}
		return nil
	}
	onlyActive, err := f.store.ListAlertSuppressions(ctx, "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if find(onlyActive, active.ID) == nil || find(onlyActive, canceled.ID) != nil {
		t.Fatalf("active list: want the active window and not the canceled one: %+v", onlyActive)
	}
	all, err := f.store.ListAlertSuppressions(ctx, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	gone := find(all, canceled.ID)
	if find(all, active.ID) == nil || gone == nil || gone.CanceledAt == nil || gone.CanceledBy != "admin" {
		t.Fatalf("full list: want both windows, the canceled one with its cancellation: %+v", all)
	}
}
