package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/ai"
	"github.com/p1ngu/rmm/internal/models"
)

// sharedFixture is two companies, A (two devices) and B (one device), and a
// policy assigned to company A.
type sharedFixture struct {
	*scriptFixture
	ctx            context.Context
	clientA        string
	siteA          string
	a1, a2, b1     string
	policy         string
	restrictedUser string
}

func newSharedFixture(t *testing.T) *sharedFixture {
	t.Helper()
	f := &sharedFixture{scriptFixture: newScriptFixture(t), ctx: context.Background()}
	mk := func(company string, hosts ...string) (string, string, []string) {
		c, err := f.store.CreateClient(f.ctx, company+"-"+uuid.NewString()[:8])
		if err != nil {
			t.Fatal(err)
		}
		s, err := f.store.CreateSite(f.ctx, c.ID, "HQ")
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, h := range hosts {
			a, err := f.store.CreateAgent(f.ctx, h+"-"+uuid.NewString()[:8], "linux", "amd64", "0.11.4", "tok-"+uuid.NewString(), &s.ID, nil)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, a.ID)
		}
		return c.ID, s.ID, ids
	}
	var a, b []string
	f.clientA, f.siteA, a = mk("A", "A1", "A2")
	_, _, b = mk("B", "B1")
	f.a1, f.a2, f.b1 = a[0], a[1], b[0]
	p, err := f.store.CreatePolicy(f.ctx, "Baseline-"+uuid.NewString()[:8], "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AssignPolicy(f.ctx, p.ID, models.ScopeClient, f.clientA); err != nil {
		t.Fatal(err)
	}
	f.policy = p.ID
	return f
}

func (f *sharedFixture) expect(method, path, body string, code int, what string) string {
	f.t.Helper()
	rec := f.do(method, path, body)
	if rec.Code != code {
		f.t.Fatalf("%s: %s %s = %d %s, want %d", what, method, path, rec.Code, rec.Body.String(), code)
	}
	return rec.Body.String()
}

func attachmentKeys(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Attachments []models.Attachment `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, a := range out.Attachments {
		keys = append(keys, a.Key())
	}
	return strings.Join(keys, ",")
}

// Runs in the PostgreSQL CI job. A task's attachments through their own
// endpoints, as the check tests do for checks: list, attach (twice is a
// conflict), copy for one target, detach; and for a technician restricted to
// company A, what they see of a shared task and what they may change.
func TestSharedTaskAttachmentEndpointsE2EIntegration(t *testing.T) {
	f := newSharedFixture(t)
	task := `"name":"cleanup","shell":"bash","script":"true","schedule_kind":"interval","interval_sec":3600`
	var created struct {
		ID string `json:"id"`
	}
	body := f.expect("POST", "/api/tasks", `{"agent_id":"`+f.a1+`",`+task+`}`, 201, "create on A1")
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatal(err)
	}
	id := created.ID
	if got := attachmentKeys(t, f.expect("GET", "/api/tasks/"+id+"/attachments", "", 200, "list")); got != "agent:"+f.a1 {
		t.Fatalf("attachments = %s", got)
	}
	f.expect("POST", "/api/tasks/"+id+"/attachments", `{"agent_id":"`+f.b1+`"}`, 200, "attach B1")
	f.expect("POST", "/api/tasks/"+id+"/attachments", `{"agent_id":"`+f.b1+`"}`, 409, "attach B1 twice")
	f.expect("POST", "/api/tasks/"+id+"/attachments", `{"agent_id":"`+f.b1+`","policy_id":"`+f.policy+`"}`, 400, "an attachment naming both")

	// A technician on company A sees the shared task applying to A1 only, and
	// may not change a task that also runs in company B.
	restore := f.asUser(t, "", []string{models.PermTasksView, models.PermTasksManage, models.PermDevicesView},
		[]models.UserScope{{ScopeType: models.ScopeClient, ScopeID: f.clientA}})
	listed := f.expect("GET", "/api/tasks/"+id+"/attachments", "", 200, "restricted list")
	if attachmentKeys(t, listed) != "agent:"+f.a1 || strings.Contains(listed, f.b1) {
		t.Fatalf("the restricted list shows a device outside scope: %s", listed)
	}
	f.expect("POST", "/api/tasks/"+id+"/attachments", `{"agent_id":"`+f.a2+`"}`, 403, "restricted attach to a shared task")
	f.expect("DELETE", "/api/tasks/"+id+"/attachments/device/"+f.a1, "", 403, "restricted detach from a shared task")
	f.expect("POST", "/api/tasks/"+id+"/copy", `{"agent_id":"`+f.a1+`"}`, 403, "restricted copy of a shared task")
	restore()

	// The administrator makes a copy for B1: the copy applies there alone and
	// the original keeps A1.
	var copied struct {
		ID          string              `json:"id"`
		Attachments []models.Attachment `json:"attachments"`
	}
	if err := json.Unmarshal([]byte(f.expect("POST", "/api/tasks/"+id+"/copy", `{"agent_id":"`+f.b1+`"}`, 201, "copy for B1")), &copied); err != nil {
		t.Fatal(err)
	}
	if copied.ID == id || len(copied.Attachments) != 1 || *copied.Attachments[0].AgentID != f.b1 {
		t.Fatalf("copy = %+v", copied)
	}
	if got := attachmentKeys(t, f.expect("GET", "/api/tasks/"+id+"/attachments", "", 200, "after copy")); got != "agent:"+f.a1 {
		t.Fatalf("the original after the copy = %s", got)
	}

	// Within company A the technician may attach another device of A and take
	// it off again, but not attach a device of B or a policy.
	restore = f.asUser(t, "", []string{models.PermTasksView, models.PermTasksManage, models.PermDevicesView},
		[]models.UserScope{{ScopeType: models.ScopeClient, ScopeID: f.clientA}})
	f.expect("POST", "/api/tasks/"+id+"/attachments", `{"agent_id":"`+f.a2+`"}`, 200, "restricted attach A2")
	f.expect("POST", "/api/tasks/"+id+"/attachments", `{"agent_id":"`+f.b1+`"}`, 403, "restricted attach B1")
	f.expect("POST", "/api/tasks/"+id+"/attachments", `{"policy_id":"`+f.policy+`"}`, 403, "restricted attach a policy")
	f.expect("DELETE", "/api/tasks/"+id+"/attachments/device/"+f.a2, "", 200, "restricted detach A2")
	restore()

	f.expect("DELETE", "/api/tasks/"+id+"/attachments/device/"+f.a1, "", 200, "detach the last device")
	if got := attachmentKeys(t, f.expect("GET", "/api/tasks/"+id+"/attachments", "", 200, "applies nowhere")); got != "" {
		t.Fatalf("after the last detach = %q, want none", got)
	}
	f.expect("DELETE", "/api/tasks/"+id+"/attachments/device/"+f.a1, "", 404, "detach what is not attached")
	f.expect("DELETE", "/api/tasks/"+id+"/attachments/agent/"+f.a1, "", 400, "an unknown target kind")
}

// Runs in the PostgreSQL CI job. The steps an applied proposal replays that
// the other tests leave out: taking a check off a policy and onto another
// device, a policy edit naming a company, site and department in its review,
// removing an assignment that is already gone (the proposal fails and nothing
// changes), and reading proposals by a malformed or unknown id.
func TestEditProposalStepsE2EIntegration(t *testing.T) {
	f := newSharedFixture(t)
	tc := ai.ToolContext{Store: f.store, Actor: "e2e-admin"}
	propose := func(tool string, args map[string]any) string {
		t.Helper()
		b, _ := json.Marshal(args)
		var out struct {
			ID    string `json:"proposal_id"`
			Error string `json:"error"`
		}
		res := ai.Execute(f.ctx, tc, tool, b)
		if err := json.Unmarshal([]byte(res.Output), &out); err != nil || out.ID == "" {
			t.Fatalf("%s = %s", tool, res.Output)
		}
		return out.ID
	}
	check, err := f.store.CreateCheck(f.ctx, &models.Check{Attachments: []models.Attachment{{AgentID: &f.a1}, {PolicyID: &f.policy}},
		Type: models.CheckScript, Name: "probe", Config: json.RawMessage(`{"shell":"bash","script":"true"}`), IntervalSec: 300, TimeoutSec: 30, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	id := propose("propose_check_edit", map[string]any{"id": check.ID, "reason": "per device", "detach": []map[string]any{{"policy_id": f.policy}}, "attach": []map[string]any{{"agent_id": f.a2}}})
	if out := f.expect("POST", "/api/edit-proposals/"+id+"/apply", "", 200, "apply detach and attach"); !strings.Contains(out, "detach policy:"+f.policy) || !strings.Contains(out, "attach agent:"+f.a2) {
		t.Fatalf("steps = %s", out)
	}
	got, err := f.store.GetCheck(f.ctx, check.ID)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, a := range got.Attachments {
		keys = append(keys, a.Key())
	}
	if strings.Join(keys, ",") != "agent:"+f.a1+",agent:"+f.a2 && strings.Join(keys, ",") != "agent:"+f.a2+",agent:"+f.a1 {
		t.Fatalf("attachments after apply = %v", keys)
	}

	group, err := f.store.CreateGroup(f.ctx, "Finance-"+uuid.NewString()[:6], &f.siteA)
	if err != nil {
		t.Fatal(err)
	}
	id = propose("propose_policy_edit", map[string]any{"id": f.policy, "reason": "narrow it", "add_assignments": []map[string]any{
		{"scope_type": "site", "scope_id": f.siteA, "os": "windows"}, {"scope_type": "group", "scope_id": group.ID}}})
	review := f.expect("GET", "/api/edit-proposals/"+id, "", 200, "review")
	for _, want := range []string{`"site:` + f.siteA + `":"HQ"`, `"group:` + group.ID + `":"` + group.Name + `"`} {
		if !strings.Contains(review, want) {
			t.Fatalf("the review does not name %s: %s", want, review)
		}
	}
	f.expect("POST", "/api/edit-proposals/"+id+"/apply", "", 200, "apply the assignments")
	asg, err := f.store.ListPolicyAssignments(f.ctx, f.policy)
	if err != nil || len(asg) != 3 {
		t.Fatalf("assignments after apply = %+v %v", asg, err)
	}

	// An assignment that does not exist: the proposal fails, every step rolls
	// back and the failure names the step.
	before := len(asg)
	id = propose("propose_policy_edit", map[string]any{"id": f.policy, "reason": "tidy", "fields": map[string]any{"name": "renamed"},
		"remove_assignments": []map[string]any{{"id": uuid.NewString()}}})
	f.expect("POST", "/api/edit-proposals/"+id+"/apply", "", 409, "remove a missing assignment")
	p, err := f.store.GetEditProposal(f.ctx, id)
	if err != nil || p.Status != models.EditFailed || !strings.Contains(p.Outcome, "remove assignment") {
		t.Fatalf("proposal after a missing assignment = %+v %v", p, err)
	}
	pol, err := f.store.GetPolicy(f.ctx, f.policy)
	if err != nil || pol.Name == "renamed" {
		t.Fatalf("the rename was kept although a later step failed: %+v %v", pol, err)
	}
	if asg, _ := f.store.ListPolicyAssignments(f.ctx, f.policy); len(asg) != before {
		t.Fatalf("assignments changed: %d, want %d", len(asg), before)
	}

	f.expect("GET", "/api/edit-proposals/not-a-uuid", "", 400, "malformed id")
	f.expect("GET", "/api/edit-proposals/"+uuid.NewString(), "", 404, "unknown id")
	f.expect("POST", "/api/edit-proposals/"+uuid.NewString()+"/apply", "", 404, "apply an unknown id")
	f.expect("POST", "/api/edit-proposals/"+uuid.NewString()+"/reject", "", 404, "reject an unknown id")
}

// Runs in the PostgreSQL CI job. What the assistant sees and may propose for a
// technician restricted to company A, on the built-in chat and on MCP alike:
// list_checks and list_tasks show a shared item without its device in company
// B; get_editable_object shows the same; an edit of an item that also runs in
// company B, an attachment to a device of B or to a policy, and an edit of a
// policy without policies.manage are all refused, and nothing is proposed.
func TestAIToolsKeepTheUsersScopeOnSharedItemsE2EIntegration(t *testing.T) {
	f := newSharedFixture(t)
	user, err := f.store.CreateUserWithScopes(f.ctx, "tech-"+uuid.NewString()[:8], "hash", models.RoleTech,
		[]models.UserScope{{ScopeType: models.ScopeClient, ScopeID: f.clientA}})
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]bool{models.PermChecksView: true, models.PermChecksManage: true, models.PermTasksView: true,
		models.PermTasksManage: true, models.PermDevicesView: true, models.PermPoliciesView: true}
	shared, err := f.store.CreateCheck(f.ctx, &models.Check{Attachments: []models.Attachment{{AgentID: &f.a1}, {AgentID: &f.b1}},
		Type: models.CheckScript, Name: "shared-probe", Config: json.RawMessage(`{"shell":"bash","script":"true"}`), IntervalSec: 300, TimeoutSec: 30, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	own, err := f.store.CreateCheck(f.ctx, &models.Check{Attachments: models.OnAgent(&f.a1),
		Type: models.CheckScript, Name: "own-probe", Config: json.RawMessage(`{"shell":"bash","script":"true"}`), IntervalSec: 300, TimeoutSec: 30, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	sharedTask, err := f.store.CreateTask(f.ctx, &models.Task{Attachments: []models.Attachment{{AgentID: &f.a1}, {AgentID: &f.b1}},
		Name: "shared-task", Shell: "bash", Script: "true", ScheduleKind: models.ScheduleInterval, IntervalSec: 3600})
	if err != nil {
		t.Fatal(err)
	}
	for _, channel := range []string{ai.ChannelChat, ai.ChannelMCP} {
		tc := ai.ToolContext{Store: f.store, Actor: "tech", ScopeUserID: user.ID, Permissions: perms, Channel: channel}
		run := func(tool string, args map[string]any) string {
			b, _ := json.Marshal(args)
			return ai.Execute(f.ctx, tc, tool, b).Output
		}
		for _, tool := range []string{"list_checks", "list_tasks"} {
			out := run(tool, map[string]any{"agent_id": f.a1})
			if strings.Contains(out, f.b1) {
				t.Fatalf("%s on %s shows a device outside scope: %s", channel, tool, out)
			}
			name := map[string]string{"list_checks": "shared-probe", "list_tasks": "shared-task"}[tool]
			if !strings.Contains(out, name) || !strings.Contains(out, f.a1) {
				t.Fatalf("%s on %s hides the shared item or its device in scope: %s", channel, tool, out)
			}
		}
		out := run("get_editable_object", map[string]any{"kind": "check", "id": shared.ID})
		if strings.Contains(out, f.b1) || !strings.Contains(out, f.a1) {
			t.Fatalf("%s get_editable_object shows a device outside scope: %s", channel, out)
		}
		before, err := f.store.ListEditProposals(f.ctx, "", "", 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			tool string
			args map[string]any
			want string
		}{
			{"propose_check_edit", map[string]any{"id": shared.ID, "reason": "r", "fields": map[string]any{"interval_sec": 600}}, ""},
			{"propose_task_edit", map[string]any{"id": sharedTask.ID, "reason": "r", "fields": map[string]any{"interval_sec": 7200}}, ""},
			{"propose_check_edit", map[string]any{"id": own.ID, "reason": "r", "attach": []map[string]any{{"agent_id": f.b1}}}, "outside the user's scope"},
			{"propose_check_edit", map[string]any{"id": own.ID, "reason": "r", "attach": []map[string]any{{"policy_id": f.policy}}}, "unrestricted administrator"},
			{"propose_policy_edit", map[string]any{"id": f.policy, "reason": "r", "fields": map[string]any{"name": "x"}}, "missing permission"},
			{"get_editable_object", map[string]any{"kind": "script", "id": uuid.NewString()}, ""},
		} {
			out := run(tc.tool, tc.args)
			if !strings.Contains(out, `"error"`) || (tc.want != "" && !strings.Contains(out, tc.want)) {
				t.Fatalf("%s %s %v = %s, want a refusal %q", channel, tc.tool, tc.args, out, tc.want)
			}
		}
		// The one edit in scope is proposed.
		if out := run("propose_check_edit", map[string]any{"id": own.ID, "reason": "slower", "fields": map[string]any{"interval_sec": 600}}); !strings.Contains(out, "proposal_id") {
			t.Fatalf("%s: an edit in scope was refused: %s", channel, out)
		}
		after, err := f.store.ListEditProposals(f.ctx, "", "", 500)
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before)+1 {
			t.Fatalf("%s: %d proposals were created, want 1", channel, len(after)-len(before))
		}
	}
}
