package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/models"
)

// Runs in the PostgreSQL CI job. Checks and tasks attached to several
// policies and devices, through the REST API:
//   - the one-owner body (agent_id / policy_id) still creates one attachment;
//   - a restricted user sees a shared item and only its attachments in scope,
//     and may change, attach, detach, copy, delete or silence it only when
//     every attachment is a device in their scope;
//   - an edit naming other targets is refused; attachments change through
//     their own endpoints, which an AI proposal awaiting review refuses.
func TestSharedMonitoringAPIAccessE2EIntegration(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	mk := func(company string, hosts ...string) (string, []string) {
		t.Helper()
		c, err := f.store.CreateClient(ctx, company+"-"+uuid.NewString()[:8])
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.CreateSite(ctx, c.ID, "HQ")
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, h := range hosts {
			a, err := f.store.CreateAgent(ctx, h+"-"+uuid.NewString()[:8], "linux", "amd64", "0.11.4", "tok-"+uuid.NewString(), &s.ID, nil)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, a.ID)
		}
		return c.ID, ids
	}
	clientA, a := mk("A", "A1", "A2")
	_, b := mk("B", "B1")
	policy, err := f.store.CreatePolicy(ctx, "Baseline-"+uuid.NewString()[:8], "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssignPolicy(ctx, policy.ID, models.ScopeClient, clientA); err != nil {
		t.Fatal(err)
	}
	decodeCheck := func(body string) models.Check {
		t.Helper()
		var c models.Check
		if err := json.Unmarshal([]byte(body), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	keys := func(atts []models.Attachment) string {
		var out []string
		for _, x := range atts {
			out = append(out, x.Key())
		}
		return strings.Join(out, ",")
	}
	expect := func(rec interface{ Result() *http.Response }, code int, what string) {
		t.Helper()
		if got := rec.Result().StatusCode; got != code {
			t.Fatalf("%s = %d, want %d", what, got, code)
		}
	}

	// Admin: the one-owner body still works and still reads back as one owner.
	rec := f.do("POST", "/api/checks", `{"agent_id":"`+a[0]+`","type":"script","config":{"shell":"bash","script":"true"},"name":"memory"}`)
	if rec.Code != 201 {
		t.Fatalf("create with agent_id = %d %s", rec.Code, rec.Body.String())
	}
	shared := decodeCheck(rec.Body.String())
	if keys(shared.Attachments) != "agent:"+a[0] || shared.SingleAgentID == nil || *shared.SingleAgentID != a[0] {
		t.Fatalf("one-owner create = %+v", shared)
	}
	expect(f.do("POST", "/api/checks", `{"agent_id":"`+a[0]+`","policy_id":"`+policy.ID+`","type":"script","config":{"shell":"bash","script":"true"}}`), 400, "both owner fields")
	rec = f.do("POST", "/api/checks/"+shared.ID+"/attachments", `{"agent_id":"`+b[0]+`"}`)
	expect(rec, 200, "attach B1")
	if got := decodeCheck(rec.Body.String()); len(got.Attachments) != 2 || got.SingleAgentID != nil {
		t.Fatalf("after attaching = %+v", got)
	}
	expect(f.do("POST", "/api/checks/"+shared.ID+"/attachments", `{"agent_id":"`+b[0]+`"}`), 409, "attach twice")
	rec = f.do("POST", "/api/checks", `{"attachments":[{"policy_id":"`+policy.ID+`"},{"agent_id":"`+b[0]+`"}],"type":"script","config":{"shell":"bash","script":"true"},"name":"cpu"}`)
	expect(rec, 201, "create with attachments")
	mixed := decodeCheck(rec.Body.String())
	expect(f.do("PUT", "/api/checks/"+mixed.ID, `{"policy_id":"`+policy.ID+`","type":"script","config":{"shell":"bash","script":"true"},"name":"cpu"}`), 400, "edit naming other targets")
	expect(f.do("POST", "/api/checks", `{"attachments":[{"policy_id":"`+policy.ID+`","agent_id":"`+b[0]+`"}],"type":"script","config":{"shell":"bash","script":"true"}}`), 400, "attachment naming both")

	// A restricted technician on client A.
	restore := f.asUser(t, "", []string{models.PermChecksView, models.PermChecksManage, models.PermTasksView, models.PermTasksManage,
		models.PermAlertsView, models.PermAlertsManage, models.PermDevicesView, models.PermPoliciesView},
		[]models.UserScope{{ScopeType: models.ScopeClient, ScopeID: clientA}})
	rec = f.do("GET", "/api/checks", "")
	expect(rec, 200, "list as restricted")
	var listed struct {
		Checks []models.Check `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, c := range listed.Checks {
		seen[c.ID] = keys(c.Attachments)
		if strings.Contains(rec.Body.String(), b[0]) {
			t.Fatalf("an out-of-scope device's id leaked into the list: %s", rec.Body.String())
		}
	}
	if seen[shared.ID] != "agent:"+a[0] || seen[mixed.ID] != "policy:"+policy.ID {
		t.Fatalf("restricted view = %v", seen)
	}
	// The policy's review names only what this user may see of a check it
	// shares: not the device in client B it is also attached to.
	rec = f.do("GET", "/api/policies/"+policy.ID+"/review", "")
	expect(rec, 200, "restricted policy review")
	if !strings.Contains(rec.Body.String(), mixed.ID) || strings.Contains(rec.Body.String(), b[0]) || strings.Contains(rec.Body.String(), "B1-") {
		t.Fatalf("the review leaks a device outside scope: %s", rec.Body.String())
	}
	for _, step := range []struct{ method, path, body, what string }{
		{"PUT", "/api/checks/" + shared.ID, `{"type":"script","config":{"shell":"bash","script":"true"},"name":"renamed"}`, "edit a check that also applies outside scope"},
		{"DELETE", "/api/checks/" + shared.ID, "", "delete it"},
		{"POST", "/api/checks/" + shared.ID + "/attachments", `{"agent_id":"` + a[1] + `"}`, "attach to it"},
		{"DELETE", "/api/checks/" + shared.ID + "/attachments/device/" + a[0], "", "detach from it"},
		{"POST", "/api/checks/" + shared.ID + "/copy", `{"agent_id":"` + a[0] + `"}`, "copy it"},
		{"PUT", "/api/checks/" + mixed.ID, `{"type":"script","config":{"shell":"bash","script":"true"},"name":"x"}`, "edit a policy's check"},
		{"POST", "/api/checks", `{"policy_id":"` + policy.ID + `","type":"script","config":{"shell":"bash","script":"true"}}`, "create for a policy"},
		{"POST", "/api/checks", `{"attachments":[],"type":"script","config":{"shell":"bash","script":"true"}}`, "create applying nowhere"},
		{"POST", "/api/alert-suppressions", `{"kind":"silence","scope_type":"check","scope_id":"` + shared.ID + `","ends_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","reason":"x"}`, "silence it"},
	} {
		expect(f.do(step.method, step.path, step.body), 403, step.what)
	}
	rec = f.do("POST", "/api/checks", `{"attachments":[{"agent_id":"`+a[0]+`"},{"agent_id":"`+a[1]+`"}],"type":"script","config":{"shell":"bash","script":"true"},"name":"mine"}`)
	expect(rec, 201, "create on two devices in scope")
	mine := decodeCheck(rec.Body.String())
	expect(f.do("POST", "/api/checks/"+mine.ID+"/attachments", `{"agent_id":"`+b[0]+`"}`), 403, "attach a device outside scope")
	expect(f.do("POST", "/api/alert-suppressions", `{"kind":"silence","scope_type":"check","scope_id":"`+mine.ID+`","ends_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`","reason":"mine"}`), 201, "silence a check of their own")
	expect(f.do("DELETE", "/api/checks/"+mine.ID+"/attachments/device/"+a[1], ""), 200, "detach within scope")
	restore()

	// Once the admin takes it off B1, the technician may change it.
	expect(f.do("DELETE", "/api/checks/"+shared.ID+"/attachments/device/"+b[0], ""), 200, "admin detaches B1")
	restore = f.asUser(t, "", []string{models.PermChecksView, models.PermChecksManage}, []models.UserScope{{ScopeType: models.ScopeClient, ScopeID: clientA}})
	expect(f.do("PUT", "/api/checks/"+shared.ID, `{"type":"script","config":{"shell":"bash","script":"true"},"name":"renamed"}`), 200, "edit once every attachment is in scope")
	restore()

	// Make a copy for one attachment: the copy takes it, the original keeps the rest.
	rec = f.do("POST", "/api/checks/"+mixed.ID+"/copy", `{"policy_id":"`+policy.ID+`"}`)
	expect(rec, 201, "copy for the policy")
	if cp := decodeCheck(rec.Body.String()); keys(cp.Attachments) != "policy:"+policy.ID || cp.ID == mixed.ID {
		t.Fatalf("copy = %+v", cp)
	}
	rec = f.do("GET", "/api/checks/"+mixed.ID+"/attachments", "")
	expect(rec, 200, "list attachments")
	var att struct {
		Attachments []models.Attachment `json:"attachments"`
		Devices     int                 `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &att); err != nil || keys(att.Attachments) != "agent:"+b[0] || att.Devices != 1 {
		t.Fatalf("original after the copy = %+v %v", att, err)
	}

	// An AI proposal awaiting review stays on its one attachment.
	proposal, err := f.store.CreateCheck(ctx, &models.Check{Attachments: models.OnPolicy(&policy.ID), Type: models.CheckMemory, Name: "proposal", IntervalSec: 300, ProposedBy: "ai:test"})
	if err != nil {
		t.Fatal(err)
	}
	expect(f.do("POST", "/api/checks/"+proposal.ID+"/attachments", `{"agent_id":"`+a[0]+`"}`), 409, "attach a pending proposal elsewhere")

	// Tasks: one per device in scope, and "run now" counts only those.
	rec = f.do("POST", "/api/tasks", `{"attachments":[{"agent_id":"`+a[0]+`"},{"agent_id":"`+b[0]+`"}],"name":"reboot","shell":"bash","script":"true","schedule_kind":"interval","interval_sec":3600}`)
	expect(rec, 201, "create a task on two devices")
	var task models.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	countTargets := func() int {
		t.Helper()
		rec := f.do("GET", "/api/tasks/"+task.ID+"/targets", "")
		expect(rec, 200, "task targets")
		var out struct {
			Count int `json:"count"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Count
	}
	if n := countTargets(); n != 2 {
		t.Fatalf("admin run-now targets = %d, want 2", n)
	}
	restore = f.asUser(t, "", []string{models.PermTasksView, models.PermTasksManage}, []models.UserScope{{ScopeType: models.ScopeClient, ScopeID: clientA}})
	if n := countTargets(); n != 1 {
		t.Fatalf("restricted run-now targets = %d, want 1", n)
	}
	rec = f.do("GET", "/api/tasks", "")
	if strings.Contains(rec.Body.String(), b[0]) {
		t.Fatalf("an out-of-scope device leaked into the task list: %s", rec.Body.String())
	}
	expect(f.do("PUT", "/api/tasks/"+task.ID, `{"name":"x","shell":"bash","script":"true","schedule_kind":"interval","interval_sec":3600}`), 403, "edit a task that also runs outside scope")
	restore()
}

// Runs in the PostgreSQL CI job. The console switches a check or task on and
// off by sending back what it read with enabled flipped. For an item on one
// target that body names it twice, in attachments and in the agent_id or
// policy_id kept for older clients, and the edit must still be accepted
// (enabling an AI proposal goes the same way). A body naming another target
// is still refused.
func TestMonitoringEditAcceptsWhatItReadE2EIntegration(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	c, err := f.store.CreateClient(ctx, "Echo-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.store.CreateSite(ctx, c.ID, "HQ")
	if err != nil {
		t.Fatal(err)
	}
	var agents []string
	for _, h := range []string{"E1", "E2"} {
		a, err := f.store.CreateAgent(ctx, h+"-"+uuid.NewString()[:8], "linux", "amd64", "0.11.4", "tok-"+uuid.NewString(), &s.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		agents = append(agents, a.ID)
	}
	policy, err := f.store.CreatePolicy(ctx, "Echo-"+uuid.NewString()[:8], "", "")
	if err != nil {
		t.Fatal(err)
	}
	create := func(path, body string) map[string]any {
		t.Helper()
		rec := f.do("POST", path, body)
		if rec.Code != 201 {
			t.Fatalf("create %s = %d %s", path, rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	put := func(path string, obj map[string]any, change func(map[string]any)) int {
		t.Helper()
		body := map[string]any{}
		for k, v := range obj {
			body[k] = v
		}
		change(body)
		b, _ := json.Marshal(body)
		return f.do("PUT", path, string(b)).Code
	}
	check := `"type":"script","config":{"shell":"bash","script":"true"},"name":"echo"`
	task := `"name":"echo","shell":"bash","script":"true","schedule_kind":"interval","interval_sec":3600`
	for _, tc := range []struct{ what, path, body, single, other string }{
		{"check on a device", "/api/checks", `{"agent_id":"` + agents[0] + `",` + check + `}`, "agent_id", agents[1]},
		{"check on a policy", "/api/checks", `{"policy_id":"` + policy.ID + `",` + check + `}`, "policy_id", agents[1]},
		{"task on a device", "/api/tasks", `{"agent_id":"` + agents[0] + `",` + task + `}`, "agent_id", agents[1]},
		{"shared task", "/api/tasks", `{"attachments":[{"agent_id":"` + agents[0] + `"},{"policy_id":"` + policy.ID + `"}],` + task + `}`, "", agents[1]},
	} {
		obj := create(tc.path, tc.body)
		path := tc.path + "/" + obj["id"].(string)
		if tc.single != "" && obj[tc.single] == nil {
			t.Fatalf("%s: the read lacks %s: %v", tc.what, tc.single, obj)
		}
		if code := put(path, obj, func(b map[string]any) { b["enabled"] = false }); code != 200 {
			t.Fatalf("%s: sending back what was read = %d, want 200", tc.what, code)
		}
		if code := put(path, obj, func(b map[string]any) {
			b["attachments"] = []map[string]string{{"agent_id": tc.other}}
		}); code != 400 {
			t.Fatalf("%s: other attachments = %d, want 400", tc.what, code)
		}
		if tc.single != "" {
			if code := put(path, obj, func(b map[string]any) { b["agent_id"] = tc.other; b["policy_id"] = nil }); code != 400 {
				t.Fatalf("%s: other agent_id beside the same attachments = %d, want 400", tc.what, code)
			}
		} else if code := put(path, obj, func(b map[string]any) { b["agent_id"] = agents[0] }); code != 400 {
			t.Fatalf("%s: one owner field on a shared item = %d, want 400", tc.what, code)
		}
	}
}
