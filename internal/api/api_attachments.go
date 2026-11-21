package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// A check or scheduled task is attached to any number of policies and
// devices. Who may do what with it follows from all of them:
//
//   - seeing it takes one attachment the caller may see: a device in their
//     scope, or a policy visible to them;
//   - changing, attaching, detaching, copying, deleting or silencing it takes
//     every attachment: each device in their scope, and no policy at all for a
//     restricted principal, since policies are global (requirePolicy);
//   - one with no attachment (Not in use) is an unrestricted principal's only.
//
// A restricted caller is shown only the attachments they may see.

// attachmentAccess reports whether the caller may see and may manage an item
// with these attachments.
func (s *Server) attachmentAccess(r *http.Request, atts []models.Attachment) (visible, manageable bool, err error) {
	uid := s.scopeUserID(r)
	if uid == "" {
		return true, true, nil
	}
	if len(atts) == 0 {
		return false, false, nil
	}
	manageable = true
	for _, a := range atts {
		switch {
		case a.AgentID != nil:
			if s.agentAllowed(r, *a.AgentID) {
				visible = true
			} else {
				manageable = false
			}
		case a.PolicyID != nil:
			manageable = false
			if !visible {
				ok, err := s.store.PolicyAllowedForUser(r.Context(), uid, *a.PolicyID)
				if err != nil {
					return false, false, err
				}
				visible = ok
			}
		}
	}
	return visible, manageable && visible, nil
}

// requireAttachments writes the refusal and returns false when the caller may
// not see (manage false) or may not manage (manage true) the item.
func (s *Server) requireAttachments(w http.ResponseWriter, r *http.Request, atts []models.Attachment, manage bool) bool {
	visible, manageable, err := s.attachmentAccess(r, atts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if !visible {
		writeErr(w, http.StatusNotFound, "not found")
		return false
	}
	if manage && !manageable {
		writeErr(w, http.StatusForbidden, "it applies outside your access scope or through a policy; only an unrestricted administrator may change it")
		return false
	}
	return true
}

// requireAttachmentTarget checks the caller may attach something to the
// target: a device in their scope, or a policy they may manage.
func (s *Server) requireAttachmentTarget(w http.ResponseWriter, r *http.Request, a models.Attachment) bool {
	if err := a.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return false
	}
	if a.AgentID != nil {
		return s.requireAgent(w, r, *a.AgentID)
	}
	return s.requirePolicy(w, r, *a.PolicyID, true)
}

// lockAttachmentAgent is used by the transactional attach handlers before
// authorizing a new direct target.
func (s *Server) lockAttachmentAgent(w http.ResponseWriter, r *http.Request, a models.Attachment) bool {
	if s.scopeUserID(r) == "" || a.AgentID == nil {
		return true
	}
	if err := s.store.LockConfigAgent(r.Context(), *a.AgentID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusForbidden, "device is outside your access scope")
		} else {
			writeErr(w, httpStatusFor(err), err.Error())
		}
		return false
	}
	return true
}

// visibleAttachments is what a restricted caller is shown of an item's
// attachments: the devices in their scope and the policies visible to them.
func (s *Server) visibleAttachments(r *http.Request, atts []models.Attachment) ([]models.Attachment, error) {
	uid := s.scopeUserID(r)
	if uid == "" {
		return atts, nil
	}
	out := make([]models.Attachment, 0, len(atts))
	for _, a := range atts {
		switch {
		case a.AgentID != nil:
			if s.agentAllowed(r, *a.AgentID) {
				out = append(out, a)
			}
		case a.PolicyID != nil:
			ok, err := s.store.PolicyAllowedForUser(r.Context(), uid, *a.PolicyID)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// redactCheck limits a check's attachments to what the caller may see.
func (s *Server) redactCheck(r *http.Request, c *models.Check) error {
	atts, err := s.visibleAttachments(r, c.Attachments)
	if err != nil {
		return err
	}
	c.Attachments = atts
	c.SingleAgentID, c.SinglePolicyID = models.SingleTarget(atts)
	return nil
}

// redactTask limits a task's attachments to what the caller may see.
func (s *Server) redactTask(r *http.Request, t *models.Task) error {
	atts, err := s.visibleAttachments(r, t.Attachments)
	if err != nil {
		return err
	}
	t.Attachments = atts
	t.SingleAgentID, t.SinglePolicyID = models.SingleTarget(atts)
	return nil
}

// requestedAttachments reads where a new check or task applies, and checks
// the caller may attach it to each target.
func (s *Server) requestedAttachments(w http.ResponseWriter, r *http.Request, list []models.Attachment, agentID, policyID *string) ([]models.Attachment, bool) {
	atts, err := models.RequestedAttachments(list, agentID, policyID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	if len(atts) == 0 && !s.requireUnrestricted(w, r, "checks and tasks that apply nowhere") {
		return nil, false
	}
	actor := actorOf(r)
	for i := range atts {
		if !s.requireAttachmentTarget(w, r, atts[i]) {
			return nil, false
		}
		atts[i].AddedBy = actor
	}
	return atts, true
}

// unchangedTargets reports whether the targets an update names, if it names
// any, are the item's current ones. An edit that would move the item is
// refused: that goes through the attachments endpoints. A client that sends
// back what GET returned names an item on one target twice, in attachments
// and in the agent_id or policy_id kept for older clients, so the two may
// come together as long as they agree.
func unchangedTargets(list []models.Attachment, agentID, policyID *string, current []models.Attachment) bool {
	if len(list) == 0 {
		requested, err := models.RequestedAttachments(nil, agentID, policyID)
		return err == nil && (len(requested) == 0 || sameTargets(requested, current))
	}
	requested, err := models.RequestedAttachments(list, nil, nil)
	if err != nil || !sameTargets(requested, current) {
		return false
	}
	currentAgent, currentPolicy := models.SingleTarget(current)
	return sameOptionalID(agentID, currentAgent) && sameOptionalID(policyID, currentPolicy)
}

// sameOptionalID reports whether a sent id, when sent, is the current one.
func sameOptionalID(sent, current *string) bool {
	if sent == nil || *sent == "" {
		return true
	}
	return current != nil && *current == *sent
}

// sameTargets reports whether two attachment lists name the same targets.
func sameTargets(a, b []models.Attachment) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, x := range a {
		seen[x.Key()] = true
	}
	for _, y := range b {
		if !seen[y.Key()] {
			return false
		}
	}
	return true
}

// attachmentFromPath reads an attachment target from the route: kind is
// "policy" or "device".
func attachmentFromPath(r *http.Request) (models.Attachment, bool) {
	id := chi.URLParam(r, "target")
	switch chi.URLParam(r, "kind") {
	case "policy":
		return models.Attachment{PolicyID: &id}, id != ""
	case "device":
		return models.Attachment{AgentID: &id}, id != ""
	}
	return models.Attachment{}, false
}

// decodeAttachment reads {policy_id} or {agent_id} from the body.
func decodeAttachment(w http.ResponseWriter, r *http.Request) (models.Attachment, bool) {
	var a models.Attachment
	if err := decode(r, &a); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return a, false
	}
	if err := a.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return a, false
	}
	return models.Attachment{PolicyID: a.PolicyID, AgentID: a.AgentID}, true
}

// attachmentError maps the store's attachment errors to a status.
func attachmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrPendingSingleAttachment), errors.Is(err, store.ErrAttachmentExists):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, models.ErrInvalidAttachment):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		writeErr(w, httpStatusFor(err), err.Error())
	}
}

func attachmentAudit(a models.Attachment) map[string]any {
	if a.PolicyID != nil {
		return map[string]any{"policy_id": *a.PolicyID}
	}
	return map[string]any{"agent_id": *a.AgentID}
}

// ---- checks ----

func (s *Server) listCheckAttachments(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCheck(w, r, chi.URLParam(r, "id"), false)
	if !ok {
		return
	}
	reach, err := s.store.AgentIDsForCheck(r.Context(), c.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attachments": c.Attachments, "devices": s.countVisibleAgents(r, reach)})
}

func (s *Server) attachCheck(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCheck(w, r, chi.URLParam(r, "id"), true)
	if !ok {
		return
	}
	a, ok := decodeAttachment(w, r)
	if !ok || !s.lockAttachmentAgent(w, r, a) || !s.requireAttachmentTarget(w, r, a) {
		return
	}
	a.AddedBy = actorOf(r)
	if err := s.store.AttachCheck(r.Context(), c.ID, a); err != nil {
		attachmentError(w, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), actorOf(r), "check.attach", c.ID, alertAuditDetail(attachmentAudit(a)))
	s.writeCheck(w, r, c.ID, http.StatusOK)
}

func (s *Server) detachCheck(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCheck(w, r, chi.URLParam(r, "id"), true)
	if !ok {
		return
	}
	a, ok := attachmentFromPath(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid attachment")
		return
	}
	if err := s.store.DetachCheck(r.Context(), c.ID, a); err != nil {
		attachmentError(w, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), actorOf(r), "check.detach", c.ID, alertAuditDetail(attachmentAudit(a)))
	s.writeCheck(w, r, c.ID, http.StatusOK)
}

func (s *Server) copyCheck(w http.ResponseWriter, r *http.Request) {
	c, ok := s.requireCheck(w, r, chi.URLParam(r, "id"), true)
	if !ok {
		return
	}
	a, ok := decodeAttachment(w, r)
	if !ok {
		return
	}
	out, err := s.store.CopyCheckFor(r.Context(), c.ID, a, actorOf(r))
	if err != nil {
		attachmentError(w, err)
		return
	}
	detail := attachmentAudit(a)
	detail["copy_id"] = out.ID
	_ = s.store.AddAudit(r.Context(), actorOf(r), "check.copy", c.ID, alertAuditDetail(detail))
	if err := s.redactCheck(r, out); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// writeCheck answers with the check as it is now, as the caller may see it.
func (s *Server) writeCheck(w http.ResponseWriter, r *http.Request, id string, status int) {
	out, err := s.store.GetCheck(r.Context(), id)
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
		return
	}
	if err := s.redactCheck(r, out); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, status, out)
}

// ---- tasks ----

func (s *Server) listTaskAttachments(w http.ResponseWriter, r *http.Request) {
	t, ok := s.requireTask(w, r, chi.URLParam(r, "id"), false)
	if !ok {
		return
	}
	reach, err := s.store.AgentIDsForTask(r.Context(), t.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attachments": t.Attachments, "devices": s.countVisibleAgents(r, reach)})
}

func (s *Server) attachTask(w http.ResponseWriter, r *http.Request) {
	t, ok := s.requireTask(w, r, chi.URLParam(r, "id"), true)
	if !ok {
		return
	}
	a, ok := decodeAttachment(w, r)
	if !ok || !s.lockAttachmentAgent(w, r, a) || !s.requireAttachmentTarget(w, r, a) {
		return
	}
	a.AddedBy = actorOf(r)
	if err := s.store.AttachTask(r.Context(), t.ID, a); err != nil {
		attachmentError(w, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), actorOf(r), "task.attach", t.ID, alertAuditDetail(attachmentAudit(a)))
	s.writeTask(w, r, t.ID, http.StatusOK)
}

func (s *Server) detachTask(w http.ResponseWriter, r *http.Request) {
	t, ok := s.requireTask(w, r, chi.URLParam(r, "id"), true)
	if !ok {
		return
	}
	a, ok := attachmentFromPath(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid attachment")
		return
	}
	if err := s.store.DetachTask(r.Context(), t.ID, a); err != nil {
		attachmentError(w, err)
		return
	}
	_ = s.store.AddAudit(r.Context(), actorOf(r), "task.detach", t.ID, alertAuditDetail(attachmentAudit(a)))
	s.writeTask(w, r, t.ID, http.StatusOK)
}

func (s *Server) copyTask(w http.ResponseWriter, r *http.Request) {
	t, ok := s.requireTask(w, r, chi.URLParam(r, "id"), true)
	if !ok {
		return
	}
	a, ok := decodeAttachment(w, r)
	if !ok {
		return
	}
	out, err := s.store.CopyTaskFor(r.Context(), t.ID, a, actorOf(r))
	if err != nil {
		attachmentError(w, err)
		return
	}
	detail := attachmentAudit(a)
	detail["copy_id"] = out.ID
	_ = s.store.AddAudit(r.Context(), actorOf(r), "task.copy", t.ID, alertAuditDetail(detail))
	if err := s.redactTask(r, out); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

// writeTask answers with the task as it is now, as the caller may see it.
func (s *Server) writeTask(w http.ResponseWriter, r *http.Request, id string, status int) {
	out, err := s.store.GetTask(r.Context(), id)
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
		return
	}
	if err := s.redactTask(r, out); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, status, out)
}

// countVisibleAgents counts the devices among ids the caller may see.
func (s *Server) countVisibleAgents(r *http.Request, ids []string) int {
	if s.scopeUserID(r) == "" {
		return len(ids)
	}
	n := 0
	for _, id := range ids {
		if s.agentAllowed(r, id) {
			n++
		}
	}
	return n
}
