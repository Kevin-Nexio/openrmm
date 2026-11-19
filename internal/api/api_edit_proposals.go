package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// Edit proposals: edits the AI assistant proposes to existing library scripts,
// checks, tasks, policies and patch policies. A proposal changes nothing. A
// person who could make the same edit by hand reviews it and applies it, and
// applying it runs the console's own handlers as that person, step by step:
// the same validation, scope rules, side effects and audit as an edit by hand,
// with no second write path to keep in step. The AI never applies its own
// proposals, and autonomy does not cover them.

// editPermissions are what seeing and deciding a proposal of each kind take.
var editPermissions = map[string]struct{ view, manage string }{
	models.EditScript:      {models.PermScriptsView, models.PermScriptsManage},
	models.EditCheck:       {models.PermChecksView, models.PermChecksManage},
	models.EditTask:        {models.PermTasksView, models.PermTasksManage},
	models.EditPolicy:      {models.PermPoliciesView, models.PermPoliciesManage},
	models.EditPatchPolicy: {models.PermPatchPoliciesManage, models.PermPatchPoliciesManage},
}

// editTargetVisible reports whether the caller may see the object a proposal
// is about, as its own screen would show it.
func (s *Server) editTargetVisible(r *http.Request, kind string, t *store.EditTarget, targetID string) (bool, error) {
	uid := s.scopeUserID(r)
	if uid == "" {
		return true, nil
	}
	switch kind {
	case models.EditScript:
		return true, nil // the library is global and read by anyone with scripts.view
	case models.EditCheck, models.EditTask:
		visible, _, err := s.attachmentAccess(r, attachmentsOf(t))
		return visible, err
	}
	// Policies and patch policies are global: a restricted principal can
	// neither decide an edit to one nor see the other clients its assignments
	// reach, so their proposals are not shown to it.
	return false, nil
}

// redactEditView keeps, for a restricted caller, only the attachments and
// excluded devices it may see; an unrestricted one sees the view as it is.
func (s *Server) redactEditView(r *http.Request, v *models.EditView) {
	uid := s.scopeUserID(r)
	if uid == "" || v == nil {
		return
	}
	atts := v.Attachments[:0:0]
	for _, k := range v.Attachments {
		id := k[strings.IndexByte(k, ':')+1:]
		if strings.HasPrefix(k, "policy:") {
			if ok, err := s.store.PolicyAllowedForUser(r.Context(), uid, id); err == nil && ok {
				atts = append(atts, k)
			}
		} else if s.agentAllowed(r, id) {
			atts = append(atts, k)
		}
	}
	v.Attachments = atts
	excl := v.Exclusions[:0:0]
	for _, id := range v.Exclusions {
		if s.agentAllowed(r, id) {
			excl = append(excl, id)
		}
	}
	v.Exclusions = excl
}

// attachmentsOf rebuilds a check's or task's attachments from its view.
func attachmentsOf(t *store.EditTarget) []models.Attachment {
	out := make([]models.Attachment, 0, len(t.View.Attachments))
	for _, k := range t.View.Attachments {
		id := k[strings.IndexByte(k, ':')+1:]
		if strings.HasPrefix(k, "policy:") {
			out = append(out, models.Attachment{PolicyID: &id})
		} else {
			out = append(out, models.Attachment{AgentID: &id})
		}
	}
	return out
}

func (s *Server) listEditProposals(w http.ResponseWriter, r *http.Request) {
	kind, status := r.URL.Query().Get("kind"), r.URL.Query().Get("status")
	if kind != "" && !models.ValidEditKind(kind) {
		writeErr(w, http.StatusBadRequest, "unknown kind")
		return
	}
	list, err := s.store.ListEditProposals(r.Context(), kind, status, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]models.EditProposal, 0, len(list))
	for _, p := range list {
		perm, ok := editPermissions[p.Kind]
		if !ok || !hasPermission(r, perm.view) {
			continue
		}
		target, err := s.store.EditTarget(r.Context(), p.Kind, p.TargetID)
		if errors.Is(err, store.ErrNotFound) {
			if s.scopeUserID(r) == "" {
				out = append(out, p) // its object is gone: an administrator still sees it
			}
			continue
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		visible, err := s.editTargetVisible(r, p.Kind, target, p.TargetID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if visible {
			p.TargetName = target.Name
			if s.scopeUserID(r) != "" {
				p.Changes = nil // its raw content may name targets outside the caller's scope
			}
			out = append(out, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposals": out})
}

// loadEditProposal reads a proposal the caller may see, with its object.
func (s *Server) loadEditProposal(w http.ResponseWriter, r *http.Request, manage bool) (*models.EditProposal, *store.EditTarget, bool) {
	p, err := s.store.GetEditProposal(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
		return nil, nil, false
	}
	perm := editPermissions[p.Kind]
	need := perm.view
	if manage {
		need = perm.manage
	}
	if !hasPermission(r, need) {
		writeErr(w, http.StatusForbidden, "missing permission: "+need)
		return nil, nil, false
	}
	target, err := s.store.EditTarget(r.Context(), p.Kind, p.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		if s.scopeUserID(r) != "" {
			writeErr(w, http.StatusNotFound, "not found")
			return nil, nil, false
		}
		return p, nil, true
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil, nil, false
	}
	visible, err := s.editTargetVisible(r, p.Kind, target, p.TargetID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil, nil, false
	}
	if !visible {
		writeErr(w, http.StatusNotFound, "not found")
		return nil, nil, false
	}
	p.TargetName = target.Name
	return p, target, true
}

func decodeEditChanges(p *models.EditProposal) (*models.EditChanges, error) {
	var c models.EditChanges
	dec := json.NewDecoder(bytes.NewReader(p.Changes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("invalid changes: %w", err)
	}
	if err := models.ValidateEditChanges(p.Kind, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// getEditProposal returns a proposal with its object now and as the proposal
// would leave it, whether it went stale, and the names of the policies,
// devices and scopes it mentions that the caller may see.
func (s *Server) getEditProposal(w http.ResponseWriter, r *http.Request) {
	p, target, ok := s.loadEditProposal(w, r, false)
	if !ok {
		return
	}
	out := map[string]any{"proposal": p}
	if target == nil {
		out["gone"] = true
		writeJSON(w, http.StatusOK, out)
		return
	}
	c, err := decodeEditChanges(p)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	proposed := models.ProposedView(target.View, c)
	stale := p.Status == models.EditPending && target.View.Hash() != p.BaseHash
	current := target.View
	s.redactEditView(r, &current)
	s.redactEditView(r, &proposed)
	if s.scopeUserID(r) != "" {
		p.Changes = nil
	}
	out["current"] = current
	out["proposed"] = proposed
	out["stale"] = stale
	out["pending_target"] = target.Pending
	out["names"] = s.editNames(r, current, proposed)
	writeJSON(w, http.StatusOK, out)
}

// editNames maps the ids a review mentions ("policy:<id>", "agent:<id>",
// "client:<id>", "site:<id>", "group:<id>") to names the caller may see.
func (s *Server) editNames(r *http.Request, views ...models.EditView) map[string]string {
	ctx, uid := r.Context(), s.scopeUserID(r)
	names := map[string]string{}
	add := func(key, id string, lookup func() (string, error)) {
		if _, done := names[key]; done || id == "" {
			return
		}
		if name, err := lookup(); err == nil && name != "" {
			names[key] = name
		}
	}
	agent := func(id string) {
		add("agent:"+id, id, func() (string, error) {
			if !s.agentAllowed(r, id) {
				return "", nil
			}
			a, err := s.store.GetAgent(ctx, id)
			if err != nil {
				return "", err
			}
			return a.Hostname, nil
		})
	}
	for _, v := range views {
		for _, k := range v.Attachments {
			id := k[strings.IndexByte(k, ':')+1:]
			if strings.HasPrefix(k, "policy:") {
				add(k, id, func() (string, error) {
					if uid != "" {
						if ok, err := s.store.PolicyAllowedForUser(ctx, uid, id); err != nil || !ok {
							return "", err
						}
					}
					p, err := s.store.GetPolicy(ctx, id)
					if err != nil {
						return "", err
					}
					return p.Name, nil
				})
			} else {
				agent(id)
			}
		}
		for _, id := range v.Exclusions {
			agent(id)
		}
		for _, a := range v.Assignments {
			if a.ScopeType == models.ScopeAgent {
				agent(a.ScopeID)
				continue
			}
			if uid != "" || a.ScopeID == "" {
				continue // scope names are an administrator's view; policies are global
			}
			add(a.ScopeType+":"+a.ScopeID, a.ScopeID, func() (string, error) { return s.store.ScopeName(ctx, a.ScopeType, a.ScopeID) })
		}
	}
	return names
}

// applyEditProposal applies a pending proposal as the caller.
func (s *Server) applyEditProposal(w http.ResponseWriter, r *http.Request) {
	p, target, ok := s.loadEditProposal(w, r, true)
	if !ok {
		return
	}
	actor := actorOf(r)
	if p.Status != models.EditPending {
		writeErr(w, http.StatusConflict, "the proposal is "+p.Status)
		return
	}
	if target == nil {
		_ = s.store.FinishEditProposal(r.Context(), p.ID, models.EditFailed, actor, "the object no longer exists")
		writeErr(w, http.StatusGone, "the object no longer exists")
		return
	}
	if _, err := s.store.ClaimEditProposal(r.Context(), p.ID, actor); err != nil {
		writeErr(w, httpStatusFor(err), "the proposal is being decided by someone else")
		return
	}
	finish := func(status, outcome string) {
		if err := s.store.FinishEditProposal(context.WithoutCancel(r.Context()), p.ID, status, actor, outcome); err != nil {
			_ = s.store.ReleaseEditProposal(context.WithoutCancel(r.Context()), p.ID)
		}
	}
	if target.Pending {
		finish(models.EditFailed, "the object is a proposal awaiting review; review it on its own screen")
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the object is a proposal awaiting review; review it on its own screen", "status": models.EditFailed})
		return
	}
	if target.View.Hash() != p.BaseHash {
		finish(models.EditStale, "the object changed after the proposal was made")
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the object changed after the proposal was made; ask for a new one", "status": models.EditStale})
		return
	}
	c, err := decodeEditChanges(p)
	if err != nil {
		finish(models.EditFailed, err.Error())
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	steps := s.editSteps(p, target, c)
	var done []string
	for _, st := range steps {
		code, body := s.replay(r, st.handler, st.params, st.body)
		if code >= 300 {
			msg := replayError(body)
			outcome := st.name + ": " + msg
			if len(done) > 0 {
				outcome += " (applied before it: " + strings.Join(done, ", ") + ")"
			}
			finish(models.EditFailed, outcome)
			_ = s.store.AddAudit(r.Context(), actor, p.Kind+".edit.fail", p.TargetID, alertAuditDetail(map[string]any{
				"proposal_id": p.ID, "proposed_by": p.ProposedBy, "step": st.name, "error": msg, "applied": done}))
			writeJSON(w, http.StatusConflict, map[string]any{"error": outcome, "status": models.EditFailed})
			return
		}
		done = append(done, st.name)
	}
	finish(models.EditApplied, strings.Join(done, ", "))
	_ = s.store.AddAudit(r.Context(), actor, p.Kind+".edit.apply", p.TargetID, alertAuditDetail(map[string]any{
		"proposal_id": p.ID, "proposed_by": p.ProposedBy, "steps": done}))
	writeJSON(w, http.StatusOK, map[string]any{"status": models.EditApplied, "steps": done})
}

func (s *Server) rejectEditProposal(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.loadEditProposal(w, r, true)
	if !ok {
		return
	}
	if err := s.store.FinishEditProposal(r.Context(), p.ID, models.EditRejected, actorOf(r), ""); err != nil {
		writeErr(w, httpStatusFor(err), "the proposal is no longer pending")
		return
	}
	_ = s.store.AddAudit(r.Context(), actorOf(r), p.Kind+".edit.reject", p.TargetID, alertAuditDetail(map[string]any{
		"proposal_id": p.ID, "proposed_by": p.ProposedBy}))
	writeJSON(w, http.StatusOK, map[string]any{"status": models.EditRejected})
}

// editStep is one handler call applying part of a proposal.
type editStep struct {
	name    string
	handler http.HandlerFunc
	params  map[string]string
	body    any
}

// withFields is the object as the API returns it, with the proposal's fields
// set and the parts its edit endpoint does not take left out.
func withFields(obj map[string]any, fields map[string]json.RawMessage, drop ...string) map[string]any {
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		out[k] = v
	}
	for _, k := range drop {
		delete(out, k)
	}
	for k, raw := range fields {
		var v any
		if json.Unmarshal(raw, &v) == nil {
			out[k] = v
		}
	}
	return out
}

func attachmentRoute(a models.Attachment) (kind, target string) {
	if a.PolicyID != nil {
		return "policy", *a.PolicyID
	}
	return "device", *a.AgentID
}

// editSteps turns a proposal into handler calls, the same ones the console
// makes for the same edit: the fields first, then what is removed, then what
// is added.
func (s *Server) editSteps(p *models.EditProposal, t *store.EditTarget, c *models.EditChanges) []editStep {
	id := p.TargetID
	var steps []editStep
	switch p.Kind {
	case models.EditScript:
		if len(c.Fields) > 0 {
			steps = append(steps, editStep{"update", s.updateScript, map[string]string{"id": id}, withFields(t.Object, c.Fields)})
		}
	case models.EditCheck, models.EditTask:
		update, detach, attach := s.updateCheck, s.detachCheck, s.attachCheck
		if p.Kind == models.EditTask {
			update, detach, attach = s.updateTask, s.detachTask, s.attachTask
		}
		if len(c.Fields) > 0 {
			steps = append(steps, editStep{"update", update, map[string]string{"id": id},
				withFields(t.Object, c.Fields, "attachments", "agent_id", "policy_id", "instances", "summary")})
		}
		for _, a := range c.Detach {
			kind, target := attachmentRoute(a)
			steps = append(steps, editStep{"detach " + a.Key(), detach, map[string]string{"id": id, "kind": kind, "target": target}, nil})
		}
		for _, a := range c.Attach {
			steps = append(steps, editStep{"attach " + a.Key(), attach, map[string]string{"id": id}, models.Attachment{PolicyID: a.PolicyID, AgentID: a.AgentID}})
		}
	case models.EditPolicy, models.EditPatchPolicy:
		patch := p.Kind == models.EditPatchPolicy
		if patch {
			if len(c.Fields) > 0 {
				steps = append(steps, editStep{"update", s.updatePatchPolicy, map[string]string{"id": id}, withFields(t.Object, c.Fields, "pending", "proposed_by", "approved_by", "created_at")})
			}
		} else {
			fields := map[string]json.RawMessage{}
			for k, v := range c.Fields {
				if k != "enabled" {
					fields[k] = v
				}
			}
			if len(fields) > 0 {
				body := withFields(map[string]any{"name": t.Object["name"], "description": t.Object["description"]}, fields)
				steps = append(steps, editStep{"update", s.updatePolicy, map[string]string{"id": id}, body})
			}
			if _, off := c.Fields["enabled"]; off {
				steps = append(steps, editStep{"switch off", s.deactivatePolicy, map[string]string{"id": id}, nil})
			}
		}
		addAsg, delAsg, addExcl, delExcl := s.createPolicyAssignment, s.deletePolicyAssignment, s.addPolicyExclusion, s.removePolicyExclusion
		if patch {
			addAsg, delAsg, addExcl, delExcl = s.addPatchPolicyAssignment, s.deletePatchPolicyAssignment, s.addPatchPolicyExclusion, s.removePatchPolicyExclusion
		}
		for _, rm := range c.RemoveAssignments {
			name := "remove assignment " + rm.ScopeType + ":" + rm.ScopeID
			aid := ""
			for _, a := range t.View.Assignments {
				if a.Matches(rm) {
					aid = a.ID
					break
				}
			}
			if aid == "" {
				steps = append(steps, editStep{name, missingAssignment, nil, nil})
				continue
			}
			steps = append(steps, editStep{name, delAsg, map[string]string{"aid": aid}, nil})
		}
		for _, agentID := range c.IncludeDevices {
			steps = append(steps, editStep{"include " + agentID, delExcl, map[string]string{"id": id, "agentID": agentID}, nil})
		}
		for _, a := range c.AddAssignments {
			steps = append(steps, editStep{"assign " + a.ScopeType + ":" + a.ScopeID, addAsg, map[string]string{"id": id},
				assignmentTarget{ScopeType: a.ScopeType, ScopeID: a.ScopeID, OS: a.OS, Role: a.Role}})
		}
		for _, agentID := range c.ExcludeDevices {
			steps = append(steps, editStep{"exclude " + agentID, addExcl, map[string]string{"id": id}, map[string]string{"agent_id": agentID}})
		}
	}
	return steps
}

// replay runs a console handler as the current caller, with route parameters
// and a JSON body, and returns its status and body. The route's permission
// middleware does not run here: applyEditProposal checked the kind's
// permission, and every handler still makes its own scope checks.
func (s *Server) replay(r *http.Request, h http.HandlerFunc, params map[string]string, body any) (int, []byte) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return http.StatusInternalServerError, []byte(`{"error":"cannot encode the step"}`)
		}
	}
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	req := r.Clone(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	req.Body = io.NopCloser(bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := &stepRecorder{header: http.Header{}, code: http.StatusOK}
	h(rec, req)
	return rec.code, rec.body.Bytes()
}

// stepRecorder captures a replayed handler's answer.
type stepRecorder struct {
	header http.Header
	code   int
	body   bytes.Buffer
	wrote  bool
}

func (r *stepRecorder) Header() http.Header { return r.header }
func (r *stepRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}
func (r *stepRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.code, r.wrote = code, true
	}
}

// missingAssignment fails the step removing an assignment the policy does not
// have.
func missingAssignment(w http.ResponseWriter, _ *http.Request) {
	writeErr(w, http.StatusNotFound, "the policy has no such assignment")
}

func replayError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	return strings.TrimSpace(string(body))
}
