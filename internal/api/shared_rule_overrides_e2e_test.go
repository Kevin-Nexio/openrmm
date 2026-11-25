package api

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/p1ngu/rmm/internal/models"
)

func TestSharedRuleOverrideAPIRejectsBroaderAttachmentsE2E(t *testing.T) {
	f := newPolicyAPIFixture(t)
	ctx := context.Background()
	client, err := f.store.CreateClient(ctx, "shared override client")
	if err != nil {
		t.Fatal(err)
	}
	site, err := f.store.CreateSite(ctx, client.ID, "shared override site")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := f.store.CreateAgent(ctx, "override agent", "linux", "amd64", "1.0.0", "test", &site.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	makePolicy := func(name, scope, id string) *models.Policy {
		t.Helper()
		p, err := f.store.CreatePolicy(ctx, name, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.AssignPolicy(ctx, p.ID, scope, id); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := makePolicy("client policy", "client", client.ID)
	second := makePolicy("site policy", "site", site.ID)
	broad := makePolicy("global policy", "global", models.GlobalScopeID)
	request := func(method, path, body string, want int) []byte {
		t.Helper()
		r := f.do(method, path, body)
		if r.Code != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, r.Code, want, r.Body.String())
		}
		return r.Body.Bytes()
	}
	var c models.Check
	body := fmt.Sprintf(`{"attachments":[{"policy_id":%q},{"policy_id":%q}],"name":"shared replacement","type":"connectivity","config":{"override_parent":true}}`, p.ID, second.ID)
	if err := json.Unmarshal(request("POST", "/api/checks", body, 201), &c); err != nil {
		t.Fatal(err)
	}
	request("POST", "/api/checks/"+c.ID+"/attachments", fmt.Sprintf(`{"agent_id":%q}`, agent.ID), 400)
	request("POST", "/api/checks/"+c.ID+"/attachments", fmt.Sprintf(`{"policy_id":%q}`, broad.ID), 400)
	request("PUT", "/api/checks/"+c.ID, fmt.Sprintf(`{"name":"edited shared replacement","type":"connectivity","config":{"override_parent":true,"mode":"ignore"}}`), 200)
	request("POST", "/api/policies/"+second.ID+"/assignments", fmt.Sprintf(`{"scope_type":"global","scope_id":%q}`, models.GlobalScopeID), 400)
	stored, err := f.store.GetCheck(ctx, c.ID)
	if err != nil || len(stored.Attachments) != 2 || !stored.OverridesParent() {
		t.Fatalf("refused operation altered attachments: %+v %v", stored, err)
	}
}
