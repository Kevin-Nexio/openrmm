package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// Edit proposals: an edit the AI assistant proposes to an existing object. It
// changes nothing until a person applies it, and applying it makes the same
// edit, through the same checks, as an edit by hand (internal/api).

// Kinds of object an edit proposal can change.
const (
	EditScript      = "script"
	EditCheck       = "check"
	EditTask        = "task"
	EditPolicy      = "policy"
	EditPatchPolicy = "patch_policy"
)

// Edit proposal statuses.
const (
	EditPending    = "pending"
	EditApplied    = "applied"
	EditRejected   = "rejected"
	EditStale      = "stale"      // the object changed after the proposal was made
	EditSuperseded = "superseded" // a newer proposal for the same object replaced it
	EditFailed     = "failed"     // applying it stopped at a step the server refused
)

// EditProposal is one proposed edit.
type EditProposal struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	TargetID   string          `json:"target_id"`
	TargetName string          `json:"target_name,omitempty"`
	BaseHash   string          `json:"base_hash"`
	Changes    json.RawMessage `json:"changes"`
	Reason     string          `json:"reason"`
	ProposedBy string          `json:"proposed_by"`
	Status     string          `json:"status"`
	DecidedBy  string          `json:"decided_by,omitempty"`
	Outcome    string          `json:"outcome,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	DecidedAt  *time.Time      `json:"decided_at,omitempty"`
}

// EditAssignment is a policy or patch policy assignment as an edit sees it.
// One to remove is named by its id, or by its scope and filters.
type EditAssignment struct {
	ID        string `json:"id,omitempty"`
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id,omitempty"`
	OS        string `json:"os,omitempty"`
	Role      string `json:"role,omitempty"`
}

// EditView is what an edit can see and change of an object: its editable
// fields, where a check or task applies, and a policy's assignments and
// exclusions. Its hash is what a proposal is bound to.
type EditView struct {
	Fields      map[string]any   `json:"fields"`
	Attachments []string         `json:"attachments,omitempty"`
	Assignments []EditAssignment `json:"assignments,omitempty"`
	Exclusions  []string         `json:"exclusions,omitempty"`
}

// Hash is the view's fingerprint: encoding/json writes map keys in order and
// the lists are kept sorted, so equal views hash the same.
func (v EditView) Hash() string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Normalize sorts the view's lists so its hash does not depend on row order.
func (v *EditView) Normalize() {
	sort.Strings(v.Attachments)
	sort.Strings(v.Exclusions)
	sort.Slice(v.Assignments, func(i, j int) bool {
		a, b := v.Assignments[i], v.Assignments[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.ScopeType+a.ScopeID+a.OS+a.Role < b.ScopeType+b.ScopeID+b.OS+b.Role
	})
}

// Matches reports whether other names this assignment: by id when other has
// one, else by scope and filters.
func (a EditAssignment) Matches(other EditAssignment) bool {
	if other.ID != "" {
		return other.ID == a.ID
	}
	return other.ScopeType == a.ScopeType && other.ScopeID == a.ScopeID && other.OS == a.OS && other.Role == a.Role
}

// EditChanges is a proposal's content: the fields to set and the attachments,
// assignments or exclusions to add or remove.
type EditChanges struct {
	Fields            map[string]json.RawMessage `json:"fields,omitempty"`
	Attach            []Attachment               `json:"attach,omitempty"`
	Detach            []Attachment               `json:"detach,omitempty"`
	AddAssignments    []EditAssignment           `json:"add_assignments,omitempty"`
	RemoveAssignments []EditAssignment           `json:"remove_assignments,omitempty"`
	ExcludeDevices    []string                   `json:"exclude_devices,omitempty"`
	IncludeDevices    []string                   `json:"include_devices,omitempty"`
}

// EditableFields are the fields each kind's edit may set. Anything else (an
// id, provenance, approval, an AI release) is the server's, never a proposal's.
var EditableFields = map[string][]string{
	EditScript: {"name", "description", "category", "shell", "body", "params", "variables"},
	EditCheck:  {"name", "config", "warn_threshold", "err_threshold", "interval_sec", "failure_count", "recovery_count", "hysteresis", "cooldown_sec", "timeout_sec", "enabled"},
	EditTask:   {"name", "script_id", "shell", "script", "schedule_kind", "interval_sec", "run_at_minute", "days_of_week", "run_at_minutes", "timezone", "enabled"},
	EditPolicy: {"name", "description", "enabled"},
	EditPatchPolicy: {"name", "enabled", "auto_approve", "auto_approve_age_days", "exclusions", "window_days",
		"window_start_min", "window_end_min", "timezone", "reboot"},
}

// Limits on one proposal, so a review stays readable.
const (
	MaxEditListItems   = 50
	MaxEditReasonBytes = 2000
	MaxEditChangeBytes = 256 << 10
)

// ValidEditKind reports whether kind is one an edit proposal may change.
func ValidEditKind(kind string) bool {
	_, ok := EditableFields[kind]
	return ok
}

// ErrEmptyEdit refuses a proposal that changes nothing.
var ErrEmptyEdit = errors.New("the proposal changes nothing")

// ValidateEditChanges checks a proposal's shape for its kind: only editable
// fields, only the list changes the kind has, bounded lists, and something to
// change. A policy is switched on only through its activation review, so an
// edit may switch one off but never on. The values themselves are validated
// when the edit is applied, by the same code as an edit by hand.
func ValidateEditChanges(kind string, c *EditChanges) error {
	allowed, ok := EditableFields[kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", kind)
	}
	for k := range c.Fields {
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("%s: %q cannot be changed by a proposal", kind, k)
		}
	}
	if kind == EditPolicy {
		if raw, ok := c.Fields["enabled"]; ok {
			var on bool
			if err := json.Unmarshal(raw, &on); err != nil || on {
				return errors.New("a proposal may switch a policy off; switching it on goes through its activation review")
			}
		}
	}
	attachments := kind == EditCheck || kind == EditTask
	policies := kind == EditPolicy || kind == EditPatchPolicy
	if !attachments && (len(c.Attach) > 0 || len(c.Detach) > 0) {
		return fmt.Errorf("%s has no attachments", kind)
	}
	if !policies && (len(c.AddAssignments) > 0 || len(c.RemoveAssignments) > 0 || len(c.ExcludeDevices) > 0 || len(c.IncludeDevices) > 0) {
		return fmt.Errorf("%s has no assignments or exclusions", kind)
	}
	for _, list := range []int{len(c.Attach), len(c.Detach), len(c.AddAssignments), len(c.RemoveAssignments), len(c.ExcludeDevices), len(c.IncludeDevices)} {
		if list > MaxEditListItems {
			return fmt.Errorf("at most %d items per list", MaxEditListItems)
		}
	}
	for _, a := range append(append([]Attachment{}, c.Attach...), c.Detach...) {
		if err := a.Validate(); err != nil {
			return err
		}
	}
	for _, a := range append(append([]EditAssignment{}, c.AddAssignments...), c.RemoveAssignments...) {
		if a.ScopeType == "" && a.ID == "" {
			return errors.New("an assignment needs a scope_type (or, to remove one, its id)")
		}
	}
	if len(c.Fields) == 0 && len(c.Attach) == 0 && len(c.Detach) == 0 && len(c.AddAssignments) == 0 &&
		len(c.RemoveAssignments) == 0 && len(c.ExcludeDevices) == 0 && len(c.IncludeDevices) == 0 {
		return ErrEmptyEdit
	}
	return nil
}

// ProposedView is the view as the proposal would leave it: fields replaced,
// attachments, assignments and exclusions added and removed. It is what the
// review shows next to the current view.
func ProposedView(cur EditView, c *EditChanges) EditView {
	out := EditView{Fields: map[string]any{}}
	for k, v := range cur.Fields {
		out.Fields[k] = v
	}
	for k, raw := range c.Fields {
		var v any
		if json.Unmarshal(raw, &v) == nil {
			out.Fields[k] = v
		}
	}
	keys := map[string]bool{}
	for _, k := range cur.Attachments {
		keys[k] = true
	}
	for _, a := range c.Detach {
		delete(keys, a.Key())
	}
	for _, a := range c.Attach {
		keys[a.Key()] = true
	}
	for k := range keys {
		out.Attachments = append(out.Attachments, k)
	}
	for _, a := range cur.Assignments {
		if !slices.ContainsFunc(c.RemoveAssignments, a.Matches) {
			out.Assignments = append(out.Assignments, a)
		}
	}
	out.Assignments = append(out.Assignments, c.AddAssignments...)
	excluded := map[string]bool{}
	for _, id := range cur.Exclusions {
		excluded[id] = true
	}
	for _, id := range c.IncludeDevices {
		delete(excluded, id)
	}
	for _, id := range c.ExcludeDevices {
		excluded[id] = true
	}
	for id := range excluded {
		out.Exclusions = append(out.Exclusions, id)
	}
	out.Normalize()
	return out
}
