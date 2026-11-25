package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/auth"
	"github.com/p1ngu/rmm/internal/models"
)

func TestRuleOverrideAuthorizationAndActivationE2E(t *testing.T) {
	f := newPolicyAPIFixture(t)
	ctx := context.Background()
	client, err := f.store.CreateClient(ctx, "override client")
	if err != nil {
		t.Fatal(err)
	}
	site, err := f.store.CreateSite(ctx, client.ID, "override site")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := f.store.CreateAgent(ctx, "override-pc", "linux", "amd64", "1.0.0", "test", &site.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := f.store.CreatePolicy(ctx, "override policy", "", "")
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := f.store.AssignPolicy(ctx, policy.ID, "site", site.ID)
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/policies/" + policy.ID
	request := func(method, path, body string, want int) []byte {
		t.Helper()
		r := f.do(method, path, body)
		if r.Code != want {
			t.Fatalf("%s %s: %d want %d %s", method, path, r.Code, want, r.Body.String())
		}
		return r.Body.Bytes()
	}
	normal := `{"policy_id":"` + policy.ID + `","name":"connectivity","type":"connectivity","enabled":false,"config":{"mode":"ignore"}}`
	var check models.Check
	if err := json.Unmarshal(request("POST", "/api/checks", normal, 201), &check); err != nil {
		t.Fatal(err)
	}
	oldReview, err := f.store.PolicyReview(ctx, policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	explicit := strings.Replace(normal, `"mode":"ignore"`, `"mode":"ignore","override_parent":true`, 1)
	request("PUT", "/api/checks/"+check.ID, explicit, 200)
	stored, err := f.store.GetCheck(ctx, check.ID)
	if err != nil || stored.Enabled {
		t.Fatalf("saving activated rule: %v %v", stored, err)
	}
	request("POST", base+"/activate", `{"fingerprint":"`+oldReview.Fingerprint+`"}`, 409)
	if audit := f.audit("alert_rule.update"); audit == nil || !strings.Contains(string(audit.Detail), `"override_parent": true`) && !strings.Contains(string(audit.Detail), `"override_parent":true`) {
		t.Fatalf("override missing from audit: %+v", audit)
	}
	request("PUT", "/api/alert-defaults/connectivity", `{"override_parent":true}`, 400)
	request("POST", "/api/checks", `{"agent_id":"`+agent.ID+`","type":"connectivity","name":"bad","config":{"override_parent":true}}`, 400)
	request("POST", base+"/assignments", `{"scope_type":"agent","scope_id":"`+agent.ID+`"}`, 400)
	adminToken := f.token
	scoped, err := f.store.CreateUserWithScopes(ctx, "override-scoped", "hash", models.RoleAdmin, []models.UserScope{{ScopeType: "site", ScopeID: site.ID}})
	if err != nil {
		t.Fatal(err)
	}
	f.token = auth.NewToken()
	scopedToken := f.token
	if err := f.store.CreateSession(ctx, scoped.ID, auth.Hash(f.token), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/checks", explicit},
		{"PUT", "/api/checks/" + check.ID, explicit},
		{"PUT", "/api/checks/" + check.ID, normal},
		{"PUT", "/api/checks/" + check.ID, strings.Replace(explicit, `"enabled":false`, `"enabled":true`, 1)},
		{"PUT", "/api/checks/" + check.ID, strings.Replace(explicit, `"ignore"`, `"alert"`, 1)},
		{"DELETE", "/api/checks/" + check.ID, ""},
		{"PUT", base, `{"name":"changed"}`},
		{"DELETE", base, ""},
		{"POST", base + "/activate", `{"fingerprint":"` + oldReview.Fingerprint + `"}`},
		{"POST", base + "/deactivate", `{}`},
		{"POST", base + "/assignments", `{"scope_type":"site","scope_id":"` + site.ID + `","os":"linux","role":"server"}`},
		{"DELETE", "/api/policies/assignments/" + assignment.ID, ""},
		{"POST", base + "/exclusions", `{"agent_id":"` + agent.ID + `"}`},
		{"DELETE", base + "/exclusions/" + agent.ID, ""},
		{"POST", "/api/checks", normal}, // preserve existing API ordinary-policy boundary
	} {
		request(tc.method, tc.path, tc.body, http.StatusForbidden)
	}
	request("GET", base+"/review", "", 200)
	f.token = adminToken
	request("PUT", "/api/checks/"+check.ID, strings.Replace(explicit, `"enabled":false`, `"enabled":true`, 1), 200)
	f.token = scopedToken
	var effective struct {
		Checks []deviceCheck `json:"checks"`
	}
	if err := json.Unmarshal(request("GET", "/api/devices/"+agent.ID+"/checks", "", 200), &effective); err != nil {
		t.Fatal(err)
	}
	if len(effective.Checks) != 1 || effective.Checks[0].Governing == nil || !*effective.Checks[0].Governing || !effective.Checks[0].OverridesParent() {
		t.Fatalf("scoped effective rule: %+v", effective.Checks)
	}
}
