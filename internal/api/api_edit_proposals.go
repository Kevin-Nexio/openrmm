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
	"github.com/google/uuid"

	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// Edit proposals: edits the AI assistant proposes to existing library scripts,
// checks, tasks, policies and patch policies. A proposal changes nothing. A
// person who could make the same edit by hand reviews it and applies it, and
// applying it runs the console's own handlers as that person, step by step:
// the same validation, scope rules and side effects as an edit by hand.
// Every step and the decision are recorded in one database transaction.
// The AI never applies its own
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
func (s *Server) editTargetVisible(r *http.Request, kind string, t *store.EditTarget) (bool, error) {
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

// Scope filtering for proposal reads must also cover outcome text. A finished
// step can contain the ID of a target outside the reader's scope.
func (s *Server) redactEditProposal(r *http.Request, p *models.EditProposal) {
	if s.scopeUserID(r) != "" {
		p.Changes = nil
		p.Outcome = ""
	}
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
		visible, err := s.editTargetVisible(r, p.Kind, target)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if visible {
			p.TargetName = target.Name
			s.redactEditProposal(r, &p)
			out = append(out, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"proposals": out})
}

// loadEditProposal reads a proposal the caller may see, with its object.
func (s *Server) loadEditProposal(w http.ResponseWriter, r *http.Request) (*models.EditProposal, *store.EditTarget, bool) {
	p, err := s.store.GetEditProposal(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
		return nil, nil, false
	}
	if need := editPermissions[p.Kind].view; !hasPermission(r, need) {
		writeErr(w, http.StatusForbidden, "missing permission: "+need)
		return nil, nil, false
	}
	target, err := s.store.EditTarget(r.Context(), p.Kind, p.TargetID)
	if errors.Is(err, store.ErrNotFound) {
		if s.scopeUserID(r) == "" {
			return p, nil, true
		}
		writeErr(w, http.StatusNotFound, "not found")
		return nil, nil, false
	}
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
		return nil, nil, false
	}
	visible, err := s.editTargetVisible(r, p.Kind, target)
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
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
	p, target, ok := s.loadEditProposal(w, r)
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
	s.redactEditProposal(r, p)
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

// lockEditDecision authorizes the whole target under its write lock before
// acquiring the proposal lock. An unauthorized request cannot close or claim it.
func (s *Server) lockEditDecision(w http.ResponseWriter, r *http.Request) (*models.EditProposal, *store.EditTarget, error) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid proposal id")
		return nil, nil, errConfigResponse
	}
	p, err := s.store.GetEditProposal(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	perm, valid := editPermissions[p.Kind]
	if !valid || !hasPermission(r, perm.manage) {
		writeErr(w, http.StatusForbidden, "missing permission: "+perm.manage)
		return nil, nil, errConfigResponse
	}
	scoped := s.scopeUserID(r) != ""
	if scoped && p.Kind != models.EditCheck && p.Kind != models.EditTask {
		// Match the hidden policy proposals and the global script write rule.
		if p.Kind == models.EditScript {
			writeErr(w, http.StatusForbidden, "restricted principals cannot mutate the global script library")
		} else {
			writeErr(w, http.StatusNotFound, "not found")
		}
		return nil, nil, errConfigResponse
	}
	var target *store.EditTarget
	err = s.store.LockConfigTarget(ctx, p.Kind, p.TargetID, scoped)
	if errors.Is(err, store.ErrNotFound) && !scoped {
		// An unrestricted reviewer can still close the proposal of a deleted
		// object. Target ids are assigned by the server and are never reused.
	} else if err != nil {
		return nil, nil, err
	} else {
		target, err = s.store.EditTarget(ctx, p.Kind, p.TargetID)
		if err != nil {
			return nil, nil, err
		}
		if scoped && !s.requireAttachments(w, r, attachmentsOf(target), true) {
			return nil, nil, errConfigResponse
		}
	}
	if target != nil && !s.requireEditDestinations(w, r, p, target) {
		return nil, nil, errConfigResponse
	}
	p, err = s.store.LockEditProposal(ctx, p.ID)
	return p, target, err
}

// requireEditDestinations covers privileges required by the proposed edit,
// before even a failed apply or rejection can consume the proposal.
func (s *Server) requireEditDestinations(w http.ResponseWriter, r *http.Request, p *models.EditProposal, target *store.EditTarget) bool {
	if p.Kind == models.EditScript && !hasPermission(r, models.PermScriptsVariables) {
		current, _ := target.View.Fields["variables"].([]any)
		var proposed []string
		if c, err := decodeEditChanges(p); err == nil {
			_ = json.Unmarshal(c.Fields["variables"], &proposed)
		}
		if len(current) > 0 || len(proposed) > 0 {
			writeErr(w, http.StatusForbidden, "scripts.variables required")
			return false
		}
	}
	if s.scopeUserID(r) == "" {
		return true
	}
	c, err := decodeEditChanges(p)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid proposal changes")
		return false
	}
	for _, targets := range [][]models.Attachment{c.Attach, c.Detach} {
		for _, a := range targets {
			if a.PolicyID != nil {
				return s.requireUnrestricted(w, r, "global policies")
			}
			if !s.lockAttachmentAgent(w, r, a) || !s.requireAttachmentTarget(w, r, a) {
				return false
			}
		}
	}
	return true
}

func (s *Server) applyEditProposal(w http.ResponseWriter, r *http.Request) {
	s.configWrite(w, r, (*Server).applyLockedEditProposal)
}

// applyLockedEditProposal uses a savepoint for the edit. If a step fails, the
// edit and every side effect are rolled back before marking the proposal failed.
func (s *Server) applyLockedEditProposal(w *stepRecorder, r *http.Request) error {
	p, target, err := s.lockEditDecision(w, r)
	if err != nil {
		return err
	}
	ctx, actor := r.Context(), actorOf(r)
	finish := func(status, outcome string, code int) error {
		if err := s.store.FinishEditProposal(ctx, p.ID, status, actor, outcome); err != nil {
			return err
		}
		writeJSON(w, code, map[string]any{"error": outcome, "status": status})
		return nil
	}
	if target == nil {
		return finish(models.EditFailed, "the object no longer exists", http.StatusGone)
	}
	if target.Pending {
		return finish(models.EditFailed, "the object is a proposal awaiting review; review it on its own screen", http.StatusConflict)
	}
	if target.View.Hash() != p.BaseHash {
		return finish(models.EditStale, "the object changed after the proposal was made; ask for a new one", http.StatusConflict)
	}
	c, err := decodeEditChanges(p)
	if err != nil {
		return finish(models.EditFailed, err.Error(), http.StatusUnprocessableEntity)
	}
	var done []string
	var failedStep, failure string
	err = s.store.InConfigTransaction(ctx, func(tx *store.Store) error {
		writer := &Server{cfg: s.cfg, store: tx}
		// The base hash and these unchanged fields were read under the target
		// and link locks. The normal handlers still validate the proposed fields.
		for _, st := range writer.editSteps(p, target, c) {
			code, body := writer.replay(r, st.handler, st.params, st.body)
			if code == http.StatusConflict {
				var result struct {
					Code string `json:"code"`
				}
				if json.Unmarshal(body, &result) == nil && result.Code == configBusyCode {
					// Roll back the entire attempt, including earlier successful
					// steps, but retain the proposal for a later retry.
					return store.ErrConfigBusy
				}
			}
			if code >= 500 {
				return errors.New("an edit step could not be saved")
			}
			if code >= 300 {
				failedStep, failure = st.name, replayError(body)
				return errConfigResponse
			}
			done = append(done, st.name)
		}
		return nil
	})
	if errors.Is(err, errConfigResponse) {
		if err := s.store.AddAudit(ctx, actor, p.Kind+".edit.fail", p.TargetID, alertAuditDetail(map[string]any{
			"proposal_id": p.ID, "proposed_by": p.ProposedBy, "step": failedStep, "error": failure,
		})); err != nil {
			return err
		}
		return finish(models.EditFailed, failedStep+": "+failure, http.StatusConflict)
	}
	if err != nil {
		return err
	}
	if err := s.store.FinishEditProposal(ctx, p.ID, models.EditApplied, actor, strings.Join(done, ", ")); err != nil {
		return err
	}
	if err := s.store.AddAudit(ctx, actor, p.Kind+".edit.apply", p.TargetID, alertAuditDetail(map[string]any{
		"proposal_id": p.ID, "proposed_by": p.ProposedBy, "steps": done,
	})); err != nil {
		return err
	}
	if p.Kind == models.EditScript && len(c.Fields) > 0 {
		script, err := s.store.GetScript(ctx, p.TargetID)
		if err != nil {
			return err
		}
		w.afterCommit = func(root *Server) { root.store.RegisterScriptCategory(ctx, script.Category) }
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": models.EditApplied, "steps": done})
	return nil
}

func (s *Server) rejectEditProposal(w http.ResponseWriter, r *http.Request) {
	s.configWrite(w, r, (*Server).rejectLockedEditProposal)
}

func (s *Server) rejectLockedEditProposal(w *stepRecorder, r *http.Request) error {
	p, _, err := s.lockEditDecision(w, r)
	if err != nil {
		return err
	}
	ctx, actor := r.Context(), actorOf(r)
	if err := s.store.FinishEditProposal(ctx, p.ID, models.EditRejected, actor, ""); err != nil {
		return err
	}
	if err := s.store.AddAudit(ctx, actor, p.Kind+".edit.reject", p.TargetID, alertAuditDetail(map[string]any{
		"proposal_id": p.ID, "proposed_by": p.ProposedBy,
	})); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": models.EditRejected})
	return nil
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
			steps = append(steps, editStep{"update", s.updateScriptFromProposal, map[string]string{"id": id}, withFields(t.Object, c.Fields)})
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
			if rm.ScopeType == "" {
				name = "remove assignment " + rm.ID // named by its id alone
			}
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
	header      http.Header
	code        int
	body        bytes.Buffer
	wrote       bool
	afterCommit func(*Server)
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
