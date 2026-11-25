package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/models"
)

func TestExplicitRuleOverridesIntegration(t *testing.T) {
	f := newAlertReliabilityFixture(t, "explicit overrides")
	ctx := context.Background()
	policy := func(scope, id string) *models.Policy {
		t.Helper()
		p, err := f.store.CreatePolicy(ctx, scope, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.AssignPolicy(ctx, p.ID, scope, id); err != nil {
			t.Fatal(err)
		}
		return p
	}
	create := func(p *models.Policy, kind, cfg string, enabled bool) *models.Check {
		t.Helper()
		c := &models.Check{Attachments: models.OnPolicy(&p.ID), Type: kind, Name: kind, Config: json.RawMessage(cfg), Enabled: enabled}
		if err := models.ValidateCheck(c); err != nil {
			t.Fatal(err)
		}
		out, err := f.store.CreateCheck(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	winner := func(want string) {
		t.Helper()
		r, err := f.store.GoverningRuleForAgent(ctx, models.CheckConnectivity, f.agent.ID)
		if err != nil || r.CheckID != want {
			t.Fatalf("winner=%+v error=%v want=%s", r, err, want)
		}
		all, err := f.store.GoverningRules(ctx, models.CheckConnectivity)
		if err != nil || all[f.agent.ID].CheckID != want {
			t.Fatalf("fleet resolver differs: %v %v", all, err)
		}
	}
	client := policy("client", f.client.ID)
	site := policy("site", f.site.ID)
	parent := create(client, models.CheckConnectivity, `{"after_min":60}`, true)
	child := create(site, models.CheckConnectivity, `{"after_min":3}`, true)
	winner(parent.ID) // unchanged ordinary Client versus Site
	child.Config = json.RawMessage(`{"override_parent":true,"mode":"ignore"}`)
	if err := models.ValidateCheck(child); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpdateCheck(ctx, child); err != nil {
		t.Fatal(err)
	}
	winner(child.ID)
	parent.Config = json.RawMessage(`{"override_parent":true,"after_min":3}`)
	if err := models.ValidateCheck(parent); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpdateCheck(ctx, parent); err != nil {
		t.Fatal(err)
	}
	winner(child.ID) // Site explicit beats Client explicit, even ignore
	create(site, models.CheckPatchFailure, `{"override_parent":true}`, true)
	winner(child.ID)
	if err := f.store.AddExclusion(ctx, false, site.ID, f.agent.ID, "test"); err != nil {
		t.Fatal(err)
	}
	winner(parent.ID)
	if _, err := f.store.RemoveExclusion(ctx, false, site.ID, f.agent.ID); err != nil {
		t.Fatal(err)
	}
	winner(child.ID)
	if _, err := f.store.pool.Exec(ctx, `UPDATE policy_assignments SET os='windows' WHERE policy_id=$1`, site.ID); err != nil {
		t.Fatal(err)
	}
	winner(parent.ID)
	if _, err := f.store.pool.Exec(ctx, `UPDATE policy_assignments SET os='', role='server' WHERE policy_id=$1`, site.ID); err != nil {
		t.Fatal(err)
	}
	winner(parent.ID)
	if _, err := f.store.pool.Exec(ctx, `UPDATE policy_assignments SET role='' WHERE policy_id=$1`, site.ID); err != nil {
		t.Fatal(err)
	}
	winner(child.ID)
	if _, err := f.store.pool.Exec(ctx, `UPDATE policies SET enabled=false WHERE id=$1`, site.ID); err != nil {
		t.Fatal(err)
	}
	winner(parent.ID)
	if _, err := f.store.pool.Exec(ctx, `UPDATE policies SET enabled=true WHERE id=$1`, site.ID); err != nil {
		t.Fatal(err)
	}
	winner(child.ID)
	child.Enabled = false
	if err := f.store.UpdateCheck(ctx, child); err != nil {
		t.Fatal(err)
	}
	winner(parent.ID)
	proposal := create(site, models.CheckConnectivity, `{"override_parent":true,"after_min":3}`, false)
	if _, err := f.store.pool.Exec(ctx, `UPDATE checks SET proposed_by='ai:test' WHERE id=$1`, proposal.ID); err != nil {
		t.Fatal(err)
	}
	winner(parent.ID)
	child.Enabled = true
	if err := f.store.UpdateCheck(ctx, child); err != nil {
		t.Fatal(err)
	}
	winner(child.ID)
	twin := create(site, models.CheckConnectivity, `{"override_parent":true,"mode":"ignore"}`, true)
	want := child.ID
	if twin.ID < want {
		want = twin.ID
	}
	winner(want)
	if err := f.store.DeleteCheck(ctx, twin.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeleteCheck(ctx, child.ID); err != nil {
		t.Fatal(err)
	}
	winner(parent.ID)
}

func TestRuleOverrideTargetAndScopedManagementIntegration(t *testing.T) {
	f := newAlertReliabilityFixture(t, "override targets")
	ctx := context.Background()
	p, err := f.store.CreatePolicy(ctx, "exceptions", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssignPolicy(ctx, p.ID, "site", f.site.ID); err != nil {
		t.Fatal(err)
	}
	user, err := f.store.CreateUserWithScopes(ctx, "override-manager", "hash", models.RoleAdmin, []models.UserScope{{ScopeType: "site", ScopeID: f.site.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := f.store.PolicyManageAllowedForUser(ctx, user.ID, p.ID); err != nil || !ok {
		t.Fatalf("ordinary rights: %v %v", ok, err)
	}
	c, err := f.store.CreateCheck(ctx, &models.Check{Attachments: models.OnPolicy(&p.ID), Type: models.CheckConnectivity, Name: "exception", Config: json.RawMessage(`{"override_parent":true}`), Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := f.store.PolicyManageAllowedForUser(ctx, user.ID, p.ID); err != nil || ok {
		t.Fatalf("exception rights: %v %v", ok, err)
	}
	for _, target := range []struct{ kind, id string }{{"global", models.GlobalScopeID}, {"group", f.group.ID}, {"agent", f.agent.ID}} {
		if _, err := f.store.AssignPolicy(ctx, p.ID, target.kind, target.id); err == nil {
			t.Fatalf("accepted %s", target.kind)
		}
	}
	if err := f.store.DeleteCheck(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.store.PolicyManageAllowedForUser(ctx, user.ID, p.ID); err != nil || !ok {
		t.Fatalf("ordinary rights not restored: %v %v", ok, err)
	}
	if _, err := f.store.AssignPolicy(ctx, p.ID, "agent", f.agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateCheck(ctx, c); err == nil {
		t.Fatal("accepted exception on mixed policy")
	}
	if err := f.store.SetAlertRuleDefault(ctx, models.CheckConnectivity, models.ServerRuleConfig{Mode: "ignore", OverrideParent: true}, "test"); err == nil {
		t.Fatal("accepted fleet override")
	}
}

func TestRuleOverrideAssignmentSerializationIntegration(t *testing.T) {
	f := newAlertReliabilityFixture(t, "override locking")
	ctx := context.Background()
	for _, mutation := range []string{"create", "update", "assign"} {
		t.Run(mutation, func(t *testing.T) {
			p, err := f.store.CreatePolicy(ctx, mutation, "", "")
			if err != nil {
				t.Fatal(err)
			}
			c := &models.Check{Attachments: models.OnPolicy(&p.ID), Type: models.CheckConnectivity, Name: "exception", Config: json.RawMessage(`{"override_parent":true}`)}
			if mutation == "update" {
				c.Config = json.RawMessage(`{}`)
				c, err = f.store.CreateCheck(ctx, c)
				if err != nil {
					t.Fatal(err)
				}
				c.Config = json.RawMessage(`{"override_parent":true}`)
			}
			tx, err := f.store.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if err := lockRulePolicy(ctx, tx, p.ID); err != nil {
				t.Fatal(err)
			}
			if mutation == "assign" {
				if err := insertCheck(ctx, tx, c); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := tx.Exec(ctx, `INSERT INTO policy_assignments(id,policy_id,scope_type,scope_id) VALUES($1,$2,'agent',$3)`, newID(), p.ID, f.agent.ID); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				switch mutation {
				case "create":
					_, err := f.store.CreateCheck(ctx, c)
					done <- err
				case "update":
					done <- f.store.UpdateCheck(ctx, c)
				case "assign":
					_, err := f.store.AssignPolicy(ctx, p.ID, "agent", f.agent.ID)
					done <- err
				}
			}()
			conflicted := false
			select {
			case err := <-done:
				if mutation == "assign" || !errors.Is(err, ErrConflict) {
					t.Fatalf("mutation did not honor policy lock: %v", err)
				}
				conflicted = true // check-first edits must not deadlock with activation
			case <-time.After(50 * time.Millisecond):
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if conflicted {
				return
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("concurrent incompatible scope and exception both committed")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("mutation remained blocked")
			}
		})
	}
}
