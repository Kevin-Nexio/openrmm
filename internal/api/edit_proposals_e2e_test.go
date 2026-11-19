package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/ai"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// Runs in the PostgreSQL CI job. Edits the assistant proposes, from the tool
// call to the change: the proposal changes nothing; the review shows the
// object now and as the proposal would leave it; applying it makes the edit as
// the person who applies it, through the console's own handlers, and records
// it; a proposal made stale by a later edit, a rejected one, or one whose step
// the server refuses does not apply; and deciding takes the permission an edit
// by hand takes.
func TestEditProposalsE2EIntegration(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	tc := ai.ToolContext{Store: f.store, Actor: "e2e-admin"}
	propose := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(args)
		res := ai.Execute(ctx, tc, tool, b)
		var out map[string]any
		if err := json.Unmarshal([]byte(res.Output), &out); err != nil {
			t.Fatalf("%s output %q: %v", tool, res.Output, err)
		}
		if e, ok := out["error"]; ok {
			t.Fatalf("%s: %v", tool, e)
		}
		return out
	}
	refused := func(tool string, args map[string]any, want string) {
		t.Helper()
		b, _ := json.Marshal(args)
		res := ai.Execute(ctx, tc, tool, b)
		if !strings.Contains(res.Output, want) {
			t.Fatalf("%s = %s, want an error about %q", tool, res.Output, want)
		}
	}
	status := func(id string) string {
		t.Helper()
		p, err := f.store.GetEditProposal(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return p.Status
	}

	client, err := f.store.CreateClient(ctx, "Edits-"+uuid.NewString()[:8])
	if err != nil {
		t.Fatal(err)
	}
	site, err := f.store.CreateSite(ctx, client.ID, "HQ")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := f.store.CreateAgent(ctx, "EDIT-PC-"+uuid.NewString()[:6], "linux", "amd64", "0.11.4", "tok-"+uuid.NewString(), &site.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := f.store.CreatePolicy(ctx, "Servers-"+uuid.NewString()[:6], "old description", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssignPolicy(ctx, policy.ID, models.ScopeSite, site.ID); err != nil {
		t.Fatal(err)
	}
	check, err := f.store.CreateCheck(ctx, &models.Check{Attachments: models.OnAgent(&pc.ID), Type: models.CheckScript, Name: "probe",
		Config: json.RawMessage(`{"shell":"bash","script":"true"}`), IntervalSec: 300, TimeoutSec: 30, FailureCount: 2, RecoveryCount: 2, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	// The assistant reads it and proposes; nothing changes yet.
	read := propose("get_editable_object", map[string]any{"kind": "check", "id": check.ID})
	if read["name"] != "probe" {
		t.Fatalf("get_editable_object = %v", read)
	}
	out := propose("propose_check_edit", map[string]any{"id": check.ID, "reason": "every ten minutes is enough",
		"fields": map[string]any{"interval_sec": 600, "name": "probe (10 min)"}, "attach": []map[string]any{{"policy_id": policy.ID}}})
	proposalID := out["proposal_id"].(string)
	if same, _ := f.store.GetCheck(ctx, check.ID); same.IntervalSec != 300 || len(same.Attachments) != 1 {
		t.Fatalf("a proposal changed the check: %+v", same)
	}
	refused("propose_check_edit", map[string]any{"id": check.ID, "reason": "x", "fields": map[string]any{"approved_by": "me"}}, "cannot be changed")
	refused("propose_policy_edit", map[string]any{"id": policy.ID, "reason": "x", "fields": map[string]any{"enabled": true}}, "activation review")

	rec := f.do("GET", "/api/edit-proposals?kind=check&status=pending", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), proposalID) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	rec = f.do("GET", "/api/edit-proposals/"+proposalID, "")
	var detail struct {
		Current  models.EditView   `json:"current"`
		Proposed models.EditView   `json:"proposed"`
		Stale    bool              `json:"stale"`
		Names    map[string]string `json:"names"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil || rec.Code != 200 {
		t.Fatalf("detail = %d %s", rec.Code, rec.Body)
	}
	if detail.Stale || detail.Current.Fields["interval_sec"] != float64(300) || detail.Proposed.Fields["interval_sec"] != float64(600) ||
		len(detail.Proposed.Attachments) != 2 || detail.Names["policy:"+policy.ID] != policy.Name || detail.Names["agent:"+pc.ID] != pc.Hostname {
		t.Fatalf("review = %+v", detail)
	}

	// Deciding takes checks.manage.
	restore := f.asUser(t, "", []string{models.PermChecksView}, nil)
	if rec := f.do("POST", "/api/edit-proposals/"+proposalID+"/apply", ""); rec.Code != 403 {
		t.Fatalf("apply without checks.manage = %d", rec.Code)
	}
	restore()

	rec = f.do("POST", "/api/edit-proposals/"+proposalID+"/apply", "")
	if rec.Code != 200 {
		t.Fatalf("apply = %d %s", rec.Code, rec.Body)
	}
	applied, _ := f.store.GetCheck(ctx, check.ID)
	if applied.IntervalSec != 600 || applied.Name != "probe (10 min)" || len(applied.Attachments) != 2 {
		t.Fatalf("after applying = %+v", applied)
	}
	if status(proposalID) != models.EditApplied {
		t.Fatalf("status = %s", status(proposalID))
	}
	if rec := f.do("POST", "/api/edit-proposals/"+proposalID+"/apply", ""); rec.Code != 409 {
		t.Fatalf("applying twice = %d", rec.Code)
	}
	entries, _, err := f.store.ListAudit(ctx, store.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "check.edit.apply" && e.Target == check.ID && strings.Contains(string(e.Detail), proposalID) {
			found = true
		}
	}
	if !found {
		t.Fatal("applying the proposal was not audited")
	}

	// A later edit makes an open proposal stale; a newer proposal supersedes.
	first := propose("propose_check_edit", map[string]any{"id": check.ID, "reason": "a", "fields": map[string]any{"interval_sec": 900}})["proposal_id"].(string)
	second := propose("propose_check_edit", map[string]any{"id": check.ID, "reason": "b", "fields": map[string]any{"interval_sec": 1200}})["proposal_id"].(string)
	if status(first) != models.EditSuperseded {
		t.Fatalf("first proposal = %s, want superseded", status(first))
	}
	if rec := f.do("PUT", "/api/checks/"+check.ID, `{"type":"script","name":"by hand","config":{"shell":"bash","script":"true"},"interval_sec":300,"timeout_sec":30,"failure_count":2,"recovery_count":2}`); rec.Code != 200 {
		t.Fatalf("edit by hand = %d %s", rec.Code, rec.Body)
	}
	if rec := f.do("POST", "/api/edit-proposals/"+second+"/apply", ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "stale") {
		t.Fatalf("stale apply = %d %s", rec.Code, rec.Body)
	}
	if status(second) != models.EditStale {
		t.Fatalf("second proposal = %s", status(second))
	}

	// Rejected proposals do not apply.
	third := propose("propose_check_edit", map[string]any{"id": check.ID, "reason": "c", "fields": map[string]any{"enabled": false}})["proposal_id"].(string)
	if rec := f.do("POST", "/api/edit-proposals/"+third+"/reject", ""); rec.Code != 200 {
		t.Fatalf("reject = %d", rec.Code)
	}
	if rec := f.do("POST", "/api/edit-proposals/"+third+"/apply", ""); rec.Code != 409 {
		t.Fatalf("apply after reject = %d", rec.Code)
	}

	// A step the server refuses fails the proposal and says which.
	ghost := uuid.NewString()
	failing := propose("propose_check_edit", map[string]any{"id": check.ID, "reason": "d", "attach": []map[string]any{{"agent_id": ghost}}})["proposal_id"].(string)
	if rec := f.do("POST", "/api/edit-proposals/"+failing+"/apply", ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "attach agent:"+ghost) {
		t.Fatalf("failing step = %d %s", rec.Code, rec.Body)
	}
	if status(failing) != models.EditFailed {
		t.Fatalf("failing proposal = %s", status(failing))
	}

	// A policy: rename, switch off, assign, exclude, and drop an assignment named by its scope.
	pol := propose("propose_policy_edit", map[string]any{"id": policy.ID, "reason": "tidy up",
		"fields":             map[string]any{"name": policy.Name + " (Linux)", "enabled": false},
		"add_assignments":    []map[string]any{{"scope_type": "client", "scope_id": client.ID, "os": "linux"}},
		"remove_assignments": []map[string]any{{"scope_type": "site", "scope_id": site.ID}},
		"exclude_devices":    []string{pc.ID},
	})["proposal_id"].(string)
	if rec := f.do("POST", "/api/edit-proposals/"+pol+"/apply", ""); rec.Code != 200 {
		t.Fatalf("policy apply = %d %s", rec.Code, rec.Body)
	}
	after, err := f.store.EditTarget(ctx, models.EditPolicy, policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.View.Fields["name"] != policy.Name+" (Linux)" || after.View.Fields["enabled"] != false || after.View.Fields["description"] != "old description" ||
		len(after.View.Assignments) != 1 || after.View.Assignments[0].ScopeType != "client" || after.View.Assignments[0].OS != "linux" ||
		len(after.View.Exclusions) != 1 || after.View.Exclusions[0] != pc.ID {
		t.Fatalf("policy after the edit = %+v", after.View)
	}

	// A library script's body.
	rec = f.do("POST", "/api/scripts", `{"name":"Cleanup","shell":"bash","body":"rm -rf /tmp/old"}`)
	var sc models.Script
	if err := json.Unmarshal(rec.Body.Bytes(), &sc); err != nil || rec.Code != 201 {
		t.Fatalf("create script = %d %s", rec.Code, rec.Body)
	}
	listed := propose("list_scripts", map[string]any{"query": "clean"})
	if !strings.Contains(mustJSON(listed), sc.ID) {
		t.Fatalf("list_scripts = %v", listed)
	}
	scr := propose("propose_script_edit", map[string]any{"id": sc.ID, "reason": "keep a week", "fields": map[string]any{"body": "find /tmp -mtime +7 -delete"}})["proposal_id"].(string)
	if rec := f.do("POST", "/api/edit-proposals/"+scr+"/apply", ""); rec.Code != 200 {
		t.Fatalf("script apply = %d %s", rec.Code, rec.Body)
	}
	if got, _ := f.store.GetScript(ctx, sc.ID); got.Body != "find /tmp -mtime +7 -delete" || got.Name != "Cleanup" {
		t.Fatalf("script after the edit = %+v", got)
	}

	// A patch policy's window.
	rec = f.do("POST", "/api/patch-policies", `{"name":"Weekend","enabled":true,"auto_approve":["security"],"auto_approve_age_days":0,"exclusions":[],"window_days":[0,6],"window_start_min":120,"window_end_min":360,"timezone":"UTC","reboot":"never"}`)
	var pp models.PatchPolicy
	if err := json.Unmarshal(rec.Body.Bytes(), &pp); err != nil || rec.Code >= 300 {
		t.Fatalf("create patch policy = %d %s", rec.Code, rec.Body)
	}
	ppr := propose("propose_patch_policy_edit", map[string]any{"id": pp.ID, "reason": "later at night", "fields": map[string]any{"window_start_min": 180, "window_end_min": 300}})["proposal_id"].(string)
	if rec := f.do("POST", "/api/edit-proposals/"+ppr+"/apply", ""); rec.Code != 200 {
		t.Fatalf("patch policy apply = %d %s", rec.Code, rec.Body)
	}
	if got, _ := f.store.GetPatchPolicy(ctx, pp.ID); got.WindowStartMin != 180 || got.WindowEndMin != 300 || got.Name != "Weekend" || !got.Enabled {
		t.Fatalf("patch policy after the edit = %+v", got)
	}

	// The assistant acting for a restricted user may not propose a policy edit.
	user, err := f.store.CreateUserWithScopes(ctx, "restricted-"+uuid.NewString()[:8], "hash", models.RoleTech,
		[]models.UserScope{{ScopeType: models.ScopeClient, ScopeID: client.ID}})
	if err != nil {
		t.Fatal(err)
	}
	tc = ai.ToolContext{Store: f.store, Actor: user.ID, ScopeUserID: user.ID}
	refused("propose_policy_edit", map[string]any{"id": policy.ID, "reason": "x", "fields": map[string]any{"name": "x"}}, "unrestricted administrator")
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// Runs in the PostgreSQL CI job. Regression tests for the edit proposal audit:
//   - an edit never applies to a proposal awaiting review, which would approve
//     it while the review showed only the changed fields;
//   - a restricted viewer sees no device or policy outside its scope, no raw
//     proposal content, and no policy proposals;
//   - a proposal being applied is not superseded or decided by someone else
//     (the claim's expiry is in store's TestEditProposalClaimExpiresIntegration).
func TestEditProposalsSafetyE2EIntegration(t *testing.T) {
	f := newScriptFixture(t)
	ctx := context.Background()
	tc := ai.ToolContext{Store: f.store, Actor: "e2e-admin"}
	call := func(tool string, args map[string]any) string {
		t.Helper()
		b, _ := json.Marshal(args)
		return ai.Execute(ctx, tc, tool, b).Output
	}
	mk := func(company, host string) (string, string) {
		t.Helper()
		c, err := f.store.CreateClient(ctx, company+"-"+uuid.NewString()[:8])
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.CreateSite(ctx, c.ID, "HQ")
		if err != nil {
			t.Fatal(err)
		}
		a, err := f.store.CreateAgent(ctx, host+"-"+uuid.NewString()[:8], "linux", "amd64", "0.11.4", "tok-"+uuid.NewString(), &s.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c.ID, a.ID
	}
	clientA, inScope := mk("A", "A1")
	_, outside := mk("B", "B1")

	// An AI-proposed task, unreviewed: no edit can switch it on.
	out := call("propose_task", map[string]any{"agent_id": inScope, "name": "cleanup", "shell": "bash", "script": "rm -rf /var/tmp/x", "schedule_kind": "interval", "interval_sec": 3600})
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil || created.ID == "" {
		t.Fatalf("propose_task = %s", out)
	}
	if out := call("propose_task_edit", map[string]any{"id": created.ID, "reason": "turn it on", "fields": map[string]any{"enabled": true}}); !strings.Contains(out, "awaiting review") {
		t.Fatalf("an edit to a pending task was accepted: %s", out)
	}
	target, err := f.store.EditTarget(ctx, models.EditTask, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	slipped, err := f.store.CreateEditProposal(ctx, &models.EditProposal{Kind: models.EditTask, TargetID: created.ID, BaseHash: target.View.Hash(),
		Changes: json.RawMessage(`{"fields":{"enabled":true}}`), Reason: "x", ProposedBy: "ai:e2e"})
	if err != nil {
		t.Fatal(err)
	}
	rec := f.do("GET", "/api/edit-proposals/"+slipped.ID, "")
	if !strings.Contains(rec.Body.String(), `"pending_target":true`) {
		t.Fatalf("the review does not say the task awaits review: %s", rec.Body)
	}
	if rec := f.do("POST", "/api/edit-proposals/"+slipped.ID+"/apply", ""); rec.Code != 409 {
		t.Fatalf("applying an edit to a pending task = %d %s", rec.Code, rec.Body)
	}
	if task, _ := f.store.GetTask(ctx, created.ID); task.Enabled || task.ApprovedBy != "" {
		t.Fatalf("the pending task was approved through an edit: %+v", task)
	}

	// A check on a device in scope and one outside it, with a proposal that
	// would attach it to yet another device outside.
	check, err := f.store.CreateCheck(ctx, &models.Check{Attachments: []models.Attachment{{AgentID: &inScope}, {AgentID: &outside}}, Type: models.CheckMemory,
		Name: "memory", IntervalSec: 300, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	_, outside2 := mk("C", "C1")
	out = call("propose_check_edit", map[string]any{"id": check.ID, "reason": "also C", "attach": []map[string]any{{"agent_id": outside2}}})
	var prop struct {
		ID string `json:"proposal_id"`
	}
	if err := json.Unmarshal([]byte(out), &prop); err != nil || prop.ID == "" {
		t.Fatalf("propose_check_edit = %s", out)
	}
	policy, err := f.store.CreatePolicy(ctx, "P-"+uuid.NewString()[:6], "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssignPolicy(ctx, policy.ID, models.ScopeClient, clientA); err != nil {
		t.Fatal(err)
	}
	if out := call("propose_policy_edit", map[string]any{"id": policy.ID, "reason": "rename", "fields": map[string]any{"name": "renamed"}}); !strings.Contains(out, "proposal_id") {
		t.Fatalf("propose_policy_edit = %s", out)
	}
	restore := f.asUser(t, "", []string{models.PermChecksView, models.PermPoliciesView}, []models.UserScope{{ScopeType: models.ScopeClient, ScopeID: clientA}})
	rec = f.do("GET", "/api/edit-proposals", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), prop.ID) || strings.Contains(rec.Body.String(), `"kind":"policy"`) {
		t.Fatalf("restricted list = %d %s", rec.Code, rec.Body)
	}
	for _, leak := range []string{outside, outside2, `"changes":{`} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("the list leaks %q: %s", leak, rec.Body)
		}
	}
	rec = f.do("GET", "/api/edit-proposals/"+prop.ID, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), inScope) {
		t.Fatalf("restricted detail = %d %s", rec.Code, rec.Body)
	}
	for _, leak := range []string{outside, outside2} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("the review leaks a device outside scope: %s", rec.Body)
		}
	}
	restore()

	// A claim to apply: another approver waits, the same one may retry, an
	// old claim is free, and a new proposal does not supersede one being applied.
	if _, err := f.store.ClaimEditProposal(ctx, prop.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ClaimEditProposal(ctx, prop.ID, "bob"); err == nil {
		t.Fatal("a second approver claimed a proposal being applied")
	}
	if _, err := f.store.ClaimEditProposal(ctx, prop.ID, "alice"); err != nil {
		t.Fatalf("the same approver cannot retry: %v", err)
	}
	if out := call("propose_check_edit", map[string]any{"id": check.ID, "reason": "again", "fields": map[string]any{"interval_sec": 900}}); !strings.Contains(out, "being applied") {
		t.Fatalf("a proposal being applied was superseded: %s", out)
	}
	if err := f.store.FinishEditProposal(ctx, prop.ID, models.EditRejected, "bob", ""); err == nil {
		t.Fatal("another approver rejected a proposal being applied")
	}
}
