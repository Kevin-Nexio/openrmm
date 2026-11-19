package models

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestValidateEditChangesKeepsProposalsToEditableFields(t *testing.T) {
	ok := func(kind string, c EditChanges) {
		t.Helper()
		if err := ValidateEditChanges(kind, &c); err != nil {
			t.Errorf("%s %+v refused: %v", kind, c, err)
		}
	}
	bad := func(kind string, c EditChanges, want string) {
		t.Helper()
		err := ValidateEditChanges(kind, &c)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s %+v = %v, want an error about %q", kind, c, err, want)
		}
	}
	p := "pol-1"
	ok(EditScript, EditChanges{Fields: map[string]json.RawMessage{"body": raw("echo hi")}})
	ok(EditCheck, EditChanges{Fields: map[string]json.RawMessage{"interval_sec": raw(600)}, Attach: []Attachment{{PolicyID: &p}}})
	ok(EditPolicy, EditChanges{Fields: map[string]json.RawMessage{"enabled": raw(false)}, AddAssignments: []EditAssignment{{ScopeType: "global"}}})
	ok(EditPatchPolicy, EditChanges{RemoveAssignments: []EditAssignment{{ID: "a1"}}, ExcludeDevices: []string{"d1"}})
	bad(EditScript, EditChanges{Fields: map[string]json.RawMessage{"ai_release": raw(true)}}, "cannot be changed")
	bad(EditCheck, EditChanges{Fields: map[string]json.RawMessage{"approved_by": raw("me")}}, "cannot be changed")
	bad(EditTask, EditChanges{Fields: map[string]json.RawMessage{"proposed_by": raw("")}}, "cannot be changed")
	bad(EditPolicy, EditChanges{Fields: map[string]json.RawMessage{"enabled": raw(true)}}, "activation review")
	bad(EditScript, EditChanges{Attach: []Attachment{{PolicyID: &p}}}, "no attachments")
	bad(EditCheck, EditChanges{ExcludeDevices: []string{"d1"}}, "no assignments")
	bad(EditCheck, EditChanges{Attach: []Attachment{{}}}, "exactly one")
	bad(EditPolicy, EditChanges{AddAssignments: []EditAssignment{{}}}, "scope_type")
	bad("device", EditChanges{}, "unknown kind")
	if err := ValidateEditChanges(EditCheck, &EditChanges{}); !errors.Is(err, ErrEmptyEdit) {
		t.Errorf("empty proposal = %v", err)
	}
	many := make([]string, MaxEditListItems+1)
	bad(EditPolicy, EditChanges{ExcludeDevices: many}, "at most")
}

func TestProposedViewAndHash(t *testing.T) {
	cur := EditView{
		Fields:      map[string]any{"name": "disk", "interval_sec": float64(300)},
		Attachments: []string{"policy:b", "agent:x"},
		Assignments: []EditAssignment{{ID: "a2", ScopeType: "site", ScopeID: "s"}, {ID: "a1", ScopeType: "client", ScopeID: "c"}},
		Exclusions:  []string{"d2", "d1"},
	}
	cur.Normalize()
	again := EditView{Fields: map[string]any{"interval_sec": float64(300), "name": "disk"}, Attachments: []string{"agent:x", "policy:b"},
		Assignments: []EditAssignment{{ID: "a1", ScopeType: "client", ScopeID: "c"}, {ID: "a2", ScopeType: "site", ScopeID: "s"}}, Exclusions: []string{"d1", "d2"}}
	again.Normalize()
	if cur.Hash() != again.Hash() {
		t.Fatal("the same view in another order hashes differently")
	}
	a := "a"
	p := ProposedView(cur, &EditChanges{
		Fields: map[string]json.RawMessage{"interval_sec": raw(600)},
		Attach: []Attachment{{PolicyID: &a}}, Detach: []Attachment{{AgentID: strptr("x")}},
		AddAssignments:    []EditAssignment{{ScopeType: "global"}},
		RemoveAssignments: []EditAssignment{{ScopeType: "site", ScopeID: "s"}},
		ExcludeDevices:    []string{"d3"}, IncludeDevices: []string{"d1"},
	})
	if p.Fields["interval_sec"] != float64(600) || p.Fields["name"] != "disk" {
		t.Errorf("fields = %v", p.Fields)
	}
	if strings.Join(p.Attachments, ",") != "policy:a,policy:b" {
		t.Errorf("attachments = %v", p.Attachments)
	}
	if len(p.Assignments) != 2 || p.Assignments[1].ID != "a1" || p.Assignments[0].ScopeType != "global" {
		t.Errorf("assignments = %+v", p.Assignments)
	}
	if strings.Join(p.Exclusions, ",") != "d2,d3" {
		t.Errorf("exclusions = %v", p.Exclusions)
	}
	if cur.Hash() == p.Hash() {
		t.Error("a change did not change the hash")
	}
	if cur.Fields["interval_sec"] != float64(300) {
		t.Error("ProposedView changed the current view")
	}
}

func strptr(s string) *string { return &s }
