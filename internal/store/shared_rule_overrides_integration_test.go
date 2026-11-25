package store

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/p1ngu/rmm/internal/models"
)

// Shared checks may reach several policies, but an explicit parent replacement
// must never acquire a device attachment or a policy with a broader target.
func TestSharedRuleOverrideAttachmentBoundariesIntegration(t *testing.T) {
	f := newAlertReliabilityFixture(t, "shared overrides")
	ctx := context.Background()
	policy := func(name, scope, id string) *models.Policy {
		t.Helper()
		p, err := f.store.CreatePolicy(ctx, name, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if scope != "" {
			if _, err = f.store.AssignPolicy(ctx, p.ID, scope, id); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	client := policy("client", models.ScopeClient, f.client.ID)
	site := policy("site", models.ScopeSite, f.site.ID)
	global := policy("global", models.ScopeGlobal, models.GlobalScopeID)
	create := func(atts []models.Attachment, override bool) (*models.Check, error) {
		config := json.RawMessage(`{}`)
		if override {
			config = json.RawMessage(`{"override_parent":true}`)
		}
		return f.store.CreateCheck(ctx, &models.Check{Attachments: atts, Type: models.CheckConnectivity, Name: "shared rule", Config: config, Enabled: true})
	}
	valid := []models.Attachment{{PolicyID: &client.ID}, {PolicyID: &site.ID}}
	c, err := create(valid, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, atts := range [][]models.Attachment{
		models.OnAgent(&f.agent.ID),
		models.OnPolicy(&global.ID),
		{{PolicyID: &client.ID}, {AgentID: &f.agent.ID}},
		{{PolicyID: &client.ID}, {PolicyID: &global.ID}},
	} {
		if _, err := create(atts, true); err == nil {
			t.Fatalf("created override on invalid attachments: %+v", atts)
		}
	}
	for _, a := range []models.Attachment{{AgentID: &f.agent.ID}, {PolicyID: &global.ID}} {
		if err := f.store.AttachCheck(ctx, c.ID, a); err == nil {
			t.Fatalf("attached override to invalid target: %+v", a)
		}
	}
	// Updates must validate persisted links, not a request hiding a bad target.
	ordinary, err := create([]models.Attachment{{PolicyID: &client.ID}, {PolicyID: &global.ID}}, false)
	if err != nil {
		t.Fatal(err)
	}
	ordinary.Config = json.RawMessage(`{"override_parent":true}`)
	ordinary.Attachments = models.OnPolicy(&client.ID)
	if err := f.store.UpdateCheck(ctx, ordinary); err == nil {
		t.Fatal("update ignored a persisted global attachment")
	}
	stored, err := f.store.GetCheck(ctx, ordinary.ID)
	if err != nil || stored.OverridesParent() {
		t.Fatalf("refused update changed check: %+v %v", stored, err)
	}
	// Copying a valid shared rule keeps the restriction on both copies.
	cp, err := f.store.CopyCheckFor(ctx, c.ID, models.Attachment{PolicyID: &site.ID}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if !cp.OverridesParent() || len(cp.Attachments) != 1 || cp.Attachments[0].PolicyID == nil || *cp.Attachments[0].PolicyID != site.ID {
		t.Fatalf("invalid copy: %+v", cp)
	}
	original, err := f.store.GetCheck(ctx, c.ID)
	if err != nil || len(original.Attachments) != 1 || *original.Attachments[0].PolicyID != client.ID {
		t.Fatalf("invalid original after copy: %+v %v", original, err)
	}
	for _, p := range []*models.Policy{client, site} {
		if _, err := f.store.AssignPolicy(ctx, p.ID, models.ScopeGlobal, models.GlobalScopeID); err == nil {
			t.Fatal("reassigned override policy globally")
		}
	}
	// All linked policies count, including disabled and pending rules.
	if found, err := f.store.PolicyHasRuleOverrides(ctx, site.ID); err != nil || !found {
		t.Fatalf("copied override not detected: %v %v", found, err)
	}
}
