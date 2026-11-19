package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// Edit proposals: the assistant reads an existing library script, check,
// task, policy or patch policy (get_editable_object) and proposes an edit to
// it. A proposal changes nothing. A person who could make the same edit by
// hand reviews it in the console and applies it, through the same checks as an
// edit by hand (internal/api). Proposals are never covered by autonomy.

// editKinds maps each propose tool to the kind of object it edits.
var editKinds = map[string]string{
	"propose_script_edit":       models.EditScript,
	"propose_check_edit":        models.EditCheck,
	"propose_task_edit":         models.EditTask,
	"propose_policy_edit":       models.EditPolicy,
	"propose_patch_policy_edit": models.EditPatchPolicy,
}

// editManagePermission is what proposing an edit of each kind takes: the
// permission an edit by hand takes.
var editManagePermission = map[string]string{
	models.EditScript:      models.PermScriptsManage,
	models.EditCheck:       models.PermChecksManage,
	models.EditTask:        models.PermTasksManage,
	models.EditPolicy:      models.PermPoliciesManage,
	models.EditPatchPolicy: models.PermPatchPoliciesManage,
}

// editViewPermission is what reading an object of each kind takes.
var editViewPermission = map[string]string{
	models.EditScript:      models.PermScriptsView,
	models.EditCheck:       models.PermChecksView,
	models.EditTask:        models.PermTasksView,
	models.EditPolicy:      models.PermPoliciesView,
	models.EditPatchPolicy: models.PermPatchPoliciesManage,
}

const editProposalNotice = "EDIT PROPOSED, NOTHING CHANGED. A person must review it in the console and apply it; until then the object stays as it is. " +
	"If the object changes before then, the proposal goes stale and has to be proposed again. Tell the user it is waiting for their review."

var attachmentItems = `{"type":"object","properties":{"policy_id":{"type":"string"},"agent_id":{"type":"string"}},"additionalProperties":false}`
var assignmentItems = `{"type":"object","properties":{
	"id":{"type":"string","description":"to remove one: its id (get_editable_object lists them)"},
	"scope_type":{"type":"string","enum":["global","client","site","group","agent"]},
	"scope_id":{"type":"string"},
	"os":{"type":"string","enum":["","windows","macos","linux"]},
	"role":{"type":"string","enum":["","workstation","server"]}
},"additionalProperties":false}`

func editToolDef(name, what, fields, extra string) Tool {
	props := `"id":{"type":"string","description":"the ` + what + ` to change"},
		"reason":{"type":"string","description":"why, in one or two sentences, for the person who reviews it"},
		"fields":{"type":"object","description":"the fields to set, with the names and formats get_editable_object shows: ` + fields + `. Leave out what stays the same."}`
	if extra != "" {
		props += "," + extra
	}
	return Tool{Type: "function", Function: FunctionDef{
		Name: name,
		Description: "Propose an edit to an existing " + what + ". NOTHING CHANGES until a person reviews the proposal in the console and applies it. " +
			"Read the current state with get_editable_object first and propose only the changes. One open proposal per object: a new one replaces the previous. " +
			"Applying it makes the same edit, with the same checks, as the person making it by hand, so an edit they could not make is refused then.",
		Parameters: json.RawMessage(`{"type":"object","properties":{` + props + `},"required":["id","reason"],"additionalProperties":false}`),
	}}
}

var editToolDefs = []Tool{
	{Type: "function", Function: FunctionDef{
		Name:        "list_scripts",
		Description: "List the library scripts: id, name, category, shell, description, declared parameters and script variable names, and whether each is an AI proposal awaiting review. Use get_editable_object with kind script to read one script's body.",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"optional: only scripts whose name or category contains this text"}},"additionalProperties":false}`),
	}},
	{Type: "function", Function: FunctionDef{
		Name:        "get_editable_object",
		Description: "Read what an edit proposal can change of a library script, check, task, policy or patch policy: its editable fields, where a check or task applies (attachments as policy:<id> or agent:<id>), and a policy's assignments and excluded devices, with names. Base propose_*_edit on this.",
		Parameters: json.RawMessage(`{"type":"object","properties":{
			"kind":{"type":"string","enum":["script","check","task","policy","patch_policy"]},
			"id":{"type":"string"}
		},"required":["kind","id"],"additionalProperties":false}`),
	}},
	editToolDef("propose_script_edit", "library script", "name, description, category, shell, body, params, variables", ""),
	editToolDef("propose_check_edit", "check", "name, config, warn_threshold, err_threshold, interval_sec, failure_count, recovery_count, hysteresis, cooldown_sec, timeout_sec, enabled",
		`"attach":{"type":"array","maxItems":50,"description":"policies or devices to apply it to as well","items":`+attachmentItems+`},
		"detach":{"type":"array","maxItems":50,"description":"policies or devices to take it off","items":`+attachmentItems+`}`),
	editToolDef("propose_task_edit", "scheduled task", "name, script_id, shell, script, schedule_kind, interval_sec, run_at_minute, days_of_week, run_at_minutes, timezone, enabled",
		`"attach":{"type":"array","maxItems":50,"items":`+attachmentItems+`},
		"detach":{"type":"array","maxItems":50,"items":`+attachmentItems+`}`),
	editToolDef("propose_policy_edit", "policy", "name, description, and enabled only to switch it off (switching it on goes through its activation review)",
		`"add_assignments":{"type":"array","maxItems":50,"items":`+assignmentItems+`},
		"remove_assignments":{"type":"array","maxItems":50,"items":`+assignmentItems+`},
		"exclude_devices":{"type":"array","maxItems":50,"items":{"type":"string"},"description":"device ids to leave out"},
		"include_devices":{"type":"array","maxItems":50,"items":{"type":"string"},"description":"excluded device ids to take back"}`),
	editToolDef("propose_patch_policy_edit", "patch policy", "name, enabled, auto_approve, auto_approve_age_days, exclusions, window_days, window_start_min, window_end_min, timezone, reboot",
		`"add_assignments":{"type":"array","maxItems":50,"items":`+assignmentItems+`},
		"remove_assignments":{"type":"array","maxItems":50,"items":`+assignmentItems+`},
		"exclude_devices":{"type":"array","maxItems":50,"items":{"type":"string"}},
		"include_devices":{"type":"array","maxItems":50,"items":{"type":"string"}}`),
}

// editToolPermission is the static permission of the edit tools; the object
// read takes its kind's view permission, checked when it runs.
func editToolPermission(name string) (string, bool) {
	switch name {
	case "list_scripts":
		return models.PermScriptsView, true
	case "get_editable_object":
		return "", true
	}
	if kind, ok := editKinds[name]; ok {
		return editManagePermission[kind], true
	}
	return "", false
}

func executeEditTool(ctx context.Context, tc ToolContext, name string, args json.RawMessage) (ToolResult, bool) {
	switch name {
	case "list_scripts":
		return jsonResult(listScriptsTool(ctx, tc, args)), true
	case "get_editable_object":
		return jsonResult(getEditableObject(ctx, tc, args)), true
	}
	if kind, ok := editKinds[name]; ok {
		return jsonResult(proposeEdit(ctx, tc, kind, args)), true
	}
	return ToolResult{}, false
}

func listScriptsTool(ctx context.Context, tc ToolContext, args json.RawMessage) (any, error) {
	var in struct {
		Query string `json:"query"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &in); err != nil {
			return nil, err
		}
	}
	scripts, err := tc.Store.ListScripts(ctx)
	if err != nil {
		return nil, err
	}
	q := strings.ToLower(strings.TrimSpace(in.Query))
	out := []map[string]any{}
	for _, s := range scripts {
		if q != "" && !strings.Contains(strings.ToLower(s.Name+" "+s.Category), q) {
			continue
		}
		out = append(out, map[string]any{"id": s.ID, "name": s.Name, "category": s.Category, "shell": s.Shell,
			"description": s.Description, "params": s.Params, "variables": s.Variables, "pending": s.Pending})
	}
	return map[string]any{"scripts": out}, nil
}

// editTarget loads an object for the assistant, refusing one the user it acts
// for may not see (manage false) or may not edit by hand (manage true).
func (tc ToolContext) editTarget(ctx context.Context, kind, id string, manage bool) (*store.EditTarget, error) {
	perm := editViewPermission[kind]
	if manage {
		perm = editManagePermission[kind]
	}
	if perm == "" {
		return nil, fmt.Errorf("unknown kind %q", kind)
	}
	if !tc.hasPermission(perm) {
		return nil, fmt.Errorf("missing permission: %s", perm)
	}
	t, err := tc.Store.EditTarget(ctx, kind, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%s %s not found", kind, id)
	}
	if err != nil {
		return nil, err
	}
	if tc.ScopeUserID == "" {
		return t, nil
	}
	switch kind {
	case models.EditScript:
		if manage {
			return nil, errors.New("only an unrestricted administrator may change the global script library")
		}
	case models.EditPolicy, models.EditPatchPolicy:
		if manage {
			return nil, errors.New("only an unrestricted administrator may change policies")
		}
		ok, err := tc.policyVisible(ctx, kind, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%s %s not found", kind, id)
		}
	case models.EditCheck, models.EditTask:
		visible, all := false, true
		for _, k := range t.View.Attachments {
			agentID, isAgent := strings.CutPrefix(k, "agent:")
			if isAgent && tc.allows(ctx, agentID) {
				visible = true
			} else {
				all = false
				if !isAgent && !visible {
					policyID := strings.TrimPrefix(k, "policy:")
					if ok, err := tc.Store.PolicyAllowedForUser(ctx, tc.ScopeUserID, policyID); err == nil && ok {
						visible = true
					}
				}
			}
		}
		if !visible {
			return nil, fmt.Errorf("%s %s not found", kind, id)
		}
		if manage && (!all || len(t.View.Attachments) == 0) {
			return nil, errors.New("it applies outside the user's scope or through a policy; only an unrestricted administrator may change it")
		}
		// Shown only as far as the user may see.
		kept := t.View.Attachments[:0]
		for _, k := range t.View.Attachments {
			if agentID, isAgent := strings.CutPrefix(k, "agent:"); isAgent && tc.allows(ctx, agentID) {
				kept = append(kept, k)
			} else if !isAgent {
				if ok, _ := tc.Store.PolicyAllowedForUser(ctx, tc.ScopeUserID, strings.TrimPrefix(k, "policy:")); ok {
					kept = append(kept, k)
				}
			}
		}
		t.View.Attachments = kept
	}
	return t, nil
}

func (tc ToolContext) policyVisible(ctx context.Context, kind, id string) (bool, error) {
	if kind == models.EditPatchPolicy {
		return tc.Store.PatchPolicyAllowedForUser(ctx, tc.ScopeUserID, id)
	}
	return tc.Store.PolicyAllowedForUser(ctx, tc.ScopeUserID, id)
}

func getEditableObject(ctx context.Context, tc ToolContext, args json.RawMessage) (any, error) {
	var in struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return nil, err
	}
	t, err := tc.editTarget(ctx, in.Kind, strings.TrimSpace(in.ID), false)
	if err != nil {
		return nil, err
	}
	view := t.View
	if tc.ScopeUserID != "" && (in.Kind == models.EditPolicy || in.Kind == models.EditPatchPolicy) {
		// Keep EditTarget canonical for review hashes. Only project the read
		// result, using the same scope intersection as the REST reviews.
		view.Assignments = nil
		for _, a := range t.View.Assignments {
			ok, err := tc.Store.ScopeIntersectsUser(ctx, tc.ScopeUserID, a.ScopeType, a.ScopeID)
			if err != nil {
				return nil, err
			}
			if ok {
				view.Assignments = append(view.Assignments, a)
			}
		}
		view.Exclusions = nil
		for _, id := range t.View.Exclusions {
			if tc.allows(ctx, id) {
				view.Exclusions = append(view.Exclusions, id)
			}
		}
	}
	return map[string]any{"kind": in.Kind, "id": in.ID, "name": t.Name, "current": view}, nil
}

func proposeEdit(ctx context.Context, tc ToolContext, kind string, args json.RawMessage) (any, error) {
	var in struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
		models.EditChanges
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, err
	}
	in.ID, in.Reason = strings.TrimSpace(in.ID), strings.TrimSpace(in.Reason)
	if in.ID == "" {
		return nil, errors.New("id is required")
	}
	if in.Reason == "" || len(in.Reason) > models.MaxEditReasonBytes {
		return nil, fmt.Errorf("reason is required, up to %d bytes", models.MaxEditReasonBytes)
	}
	if err := models.ValidateEditChanges(kind, &in.EditChanges); err != nil {
		return nil, err
	}
	changes, err := json.Marshal(in.EditChanges)
	if err != nil {
		return nil, err
	}
	if len(changes) > models.MaxEditChangeBytes {
		return nil, fmt.Errorf("the proposal is larger than %d bytes", models.MaxEditChangeBytes)
	}
	t, err := tc.editTarget(ctx, kind, in.ID, true)
	if err != nil {
		return nil, err
	}
	if t.Pending {
		return nil, errors.New("it is a proposal awaiting review: a person reviews it as it is on its own screen, and an edit cannot change or approve it")
	}
	for _, a := range in.Attach {
		if a.AgentID != nil && !tc.allows(ctx, *a.AgentID) {
			return nil, errors.New("a device to attach is outside the user's scope")
		}
		if a.PolicyID != nil && tc.ScopeUserID != "" {
			return nil, errors.New("only an unrestricted administrator may attach to a policy")
		}
	}
	p, err := tc.Store.CreateEditProposal(ctx, &models.EditProposal{
		Kind: kind, TargetID: in.ID, BaseHash: t.View.Hash(), Changes: changes, Reason: in.Reason, ProposedBy: tc.proposalActor(),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"proposal_id": p.ID, "kind": kind, "target_id": in.ID, "name": t.Name, "status": models.EditPending, "message": editProposalNotice}, nil
}
