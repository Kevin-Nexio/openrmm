package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// An edit with an invalid value is refused when the model proposes it, by the
// validation its handler would run on apply, and a valid one passes. Found in
// the lab: a patch policy edit proposed reboot "if_needed" and failed only
// when a person applied it.
func TestEditedObjectIsValidatedWhenProposed(t *testing.T) {
	objects := map[string]map[string]any{
		"check": {"type": "ping", "name": "ping", "config": map[string]any{"host": "10.0.0.1"}, "interval_sec": 60,
			"failure_count": 1, "recovery_count": 1, "hysteresis": 2, "cooldown_sec": 300, "timeout_sec": 180, "enabled": true},
		"task": {"name": "cleanup", "shell": "powershell", "script": "Write-Output 1", "schedule_kind": "interval",
			"interval_sec": 3600, "enabled": false},
		"patch_policy": {"name": "patches", "enabled": true, "auto_approve": []any{}, "window_days": []any{}, "window_start_min": 120,
			"window_end_min": 240, "timezone": "America/Sao_Paulo", "reboot": "never"},
		"script": {"name": "disk", "shell": "powershell", "body": "Get-PSDrive", "params": []any{}},
		"policy": {"name": "Workstations", "description": "", "enabled": true},
	}
	raw := func(s string) map[string]json.RawMessage {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, tc := range []struct {
		kind, fields, wantErr string
	}{
		{"check", `{"interval_sec":120}`, ""},
		{"check", `{"interval_sec":5}`, "interval_sec"},
		{"check", `{"config":{"host":""}}`, "host"},
		{"task", `{"interval_sec":7200,"script":"Write-Output 2"}`, ""},
		{"task", `{"schedule_kind":"weekly","days_of_week":0}`, "day of week"},
		{"task", `{"schedule_kind":"weekly","days_of_week":64,"run_at_minutes":[60]}`, ""},
		{"patch_policy", `{"reboot":"if_required","window_days":[6]}`, ""},
		{"patch_policy", `{"reboot":"if_needed"}`, "reboot"},
		{"script", `{"params":[{"name":"site","kind":"enum","values":["hq","branch"]}]}`, ""},
		{"script", `{"name":"  "}`, "name"},
		{"policy", `{"name":"Servers"}`, ""},
		{"policy", `{"name":""}`, "name"},
		{"check", `{"interval_sec":"often"}`, "wrong type"},
	} {
		err := validateEditedObject(tc.kind, objects[tc.kind], raw(tc.fields))
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s %s: refused a valid edit: %v", tc.kind, tc.fields, err)
		case tc.wantErr != "" && err == nil:
			t.Errorf("%s %s: accepted an invalid edit", tc.kind, tc.fields)
		case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
			t.Errorf("%s %s: error %q does not name %q", tc.kind, tc.fields, err, tc.wantErr)
		}
	}
}

// The built-in chat and MCP offer the edit tools from the same catalogue,
// filtered by the user's permissions, and refuse a call the user's
// permissions do not cover on either channel, even if the model names a tool
// it was not offered.
func TestEditToolsFollowTheUsersPermissionsOnBothChannels(t *testing.T) {
	need := map[string]string{
		"list_scripts":              "scripts.view",
		"propose_script_edit":       "scripts.manage",
		"propose_check_edit":        "checks.manage",
		"propose_task_edit":         "tasks.manage",
		"propose_policy_edit":       "policies.manage",
		"propose_patch_policy_edit": "patches.policies.manage",
	}
	offered := func(perms map[string]bool) map[string]bool {
		out := map[string]bool{}
		for _, tool := range ToolsForPermissions(perms) {
			out[tool.Function.Name] = true
		}
		return out
	}
	for name, perm := range need {
		if got := toolPermission(name); got != perm {
			t.Errorf("%s needs %q, want %q", name, got, perm)
			continue
		}
		if !offered(map[string]bool{perm: true})[name] {
			t.Errorf("%s is not offered with %s", name, perm)
		}
		if offered(map[string]bool{"devices.view": true})[name] {
			t.Errorf("%s is offered without %s", name, perm)
		}
		for _, channel := range []string{ChannelChat, ChannelMCP} {
			tc := ToolContext{Channel: channel, Actor: "tech", ScopeUserID: "u1", Permissions: map[string]bool{"devices.view": true}}
			res := Execute(context.Background(), tc, name, json.RawMessage(`{"id":"x","reason":"r","fields":{"name":"n"}}`))
			if !strings.Contains(res.Output, "missing permission: "+perm) {
				t.Errorf("%s on %s without %s: %s", name, channel, perm, res.Output)
			}
		}
	}
	// Reading an object to edit is offered to everyone; the tool checks the
	// kind's view permission and the user's scope itself.
	if !offered(map[string]bool{"devices.view": true})["get_editable_object"] {
		t.Error("get_editable_object is not offered")
	}
}
