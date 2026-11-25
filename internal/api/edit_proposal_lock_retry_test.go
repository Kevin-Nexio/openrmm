package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/ai"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// Policy activation/assignment can briefly own a policy while a reviewed
// shared-check edit tries to lock it. That conflict must not consume the
// proposal, including when an earlier step of the edit already succeeded.
func TestOverrideEditProposalLockConflictCanBeRetriedIntegration(t *testing.T) {
	for _, step := range []string{"update", "attach"} {
		t.Run(step, func(t *testing.T) {
			f := newScriptFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			client, err := f.store.CreateClient(ctx, "retry client")
			if err != nil {
				t.Fatal(err)
			}
			policy := func(name string) *models.Policy {
				t.Helper()
				p, err := f.store.CreatePolicy(ctx, name, "", "")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.store.AssignPolicy(ctx, p.ID, models.ScopeClient, client.ID); err != nil {
					t.Fatal(err)
				}
				return p
			}
			current, target := policy("current"), policy("new attachment")
			check, err := f.store.CreateCheck(ctx, &models.Check{Attachments: models.OnPolicy(&current.ID), Type: models.CheckConnectivity, Name: "original", Config: json.RawMessage(`{"override_parent":true}`), Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			args := map[string]any{"id": check.ID, "reason": "reviewed change", "fields": map[string]any{"name": "reviewed name"}}
			lockPolicy := current.ID
			if step == "attach" {
				args["attach"] = []map[string]string{{"policy_id": target.ID}}
				lockPolicy = target.ID
			}
			raw, _ := json.Marshal(args)
			result := ai.Execute(ctx, ai.ToolContext{Store: f.store, Actor: "reviewer-test"}, "propose_check_edit", raw)
			var proposal struct {
				ID string `json:"proposal_id"`
			}
			if err := json.Unmarshal([]byte(result.Output), &proposal); err != nil || proposal.ID == "" {
				t.Fatalf("proposal: %s %v", result.Output, err)
			}
			locked, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				finished <- f.store.InConfigTransaction(ctx, func(tx *store.Store) error {
					if err := tx.LockConfigTarget(ctx, models.EditPolicy, lockPolicy, false); err != nil {
						return err
					}
					close(locked)
					select {
					case <-release:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
			}()
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			select {
			case <-locked:
			case err := <-finished:
				t.Fatalf("lock failed: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			path := "/api/edit-proposals/" + proposal.ID + "/apply"
			response := f.do("POST", path, "")
			if response.Code != 409 || !strings.Contains(response.Body.String(), `"code":"configuration_busy"`) {
				t.Fatalf("conflict response=%d %s", response.Code, response.Body.String())
			}
			pending, err := f.store.GetEditProposal(ctx, proposal.ID)
			if err != nil || pending.Status != models.EditPending || pending.Outcome != "" {
				t.Fatalf("conflict consumed proposal: %+v %v", pending, err)
			}
			unchanged, err := f.store.GetCheck(ctx, check.ID)
			if err != nil || unchanged.Name != "original" || len(unchanged.Attachments) != 1 {
				t.Fatalf("conflict kept partial edit: %+v %v", unchanged, err)
			}
			close(release)
			released = true
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			response = f.do("POST", path, "")
			if response.Code != 200 {
				t.Fatalf("retry=%d %s", response.Code, response.Body.String())
			}
			applied, err := f.store.GetEditProposal(ctx, proposal.ID)
			if err != nil || applied.Status != models.EditApplied {
				t.Fatalf("retry decision: %+v %v", applied, err)
			}
			updated, err := f.store.GetCheck(ctx, check.ID)
			wantAttachments := 1
			if step == "attach" {
				wantAttachments = 2
			}
			if err != nil || updated.Name != "reviewed name" || len(updated.Attachments) != wantAttachments {
				t.Fatalf("retry result: %+v %v", updated, err)
			}
		})
	}
}
