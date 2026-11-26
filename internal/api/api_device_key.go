package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/p1ngu/rmm/internal/e2e"
	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// A device whose E2E identity key changed, went missing or is shared by more
// than one machine stays online; its native remote sessions pause until an
// administrator reviews it here. Nothing in this file pins a key the device
// asked for: an administrator approves exactly the key the device presented,
// after comparing its fingerprint on the device (rmm-agent -fingerprint).

// DeviceKeyNotifier delivers the alert for a new device key issue.
type DeviceKeyNotifier interface {
	QueueDeviceKeyIssue(ctx context.Context, agentID, hostname, issue, pinnedFingerprint, presentedFingerprint, ip string)
}

// SetDeviceKeyNotifier wires the alert for device key issues (cmd/server).
func (s *Server) SetDeviceKeyNotifier(n DeviceKeyNotifier) { s.keyNotifier = n }

// reportDeviceKeyOutcome audits what one registration did to the device key.
// Only a new or worse issue alerts; a repeat of the same one does not.
func (s *Server) reportDeviceKeyOutcome(ctx context.Context, agentID, reportedHostname, ip, version string, out store.DeviceKeyOutcome) {
	switch out.Event {
	case store.DeviceKeyEventPinned:
		detail, _ := json.Marshal(map[string]string{"fingerprint": e2e.DisplayFingerprint(out.Pinned)})
		_ = s.store.AddAudit(ctx, "agent", "device.e2e_key_pinned", agentID, detail)
	case store.DeviceKeyEventResolved:
		detail, _ := json.Marshal(map[string]string{"fingerprint": e2e.DisplayFingerprint(out.Pinned), "previous_issue": out.PrevIssue})
		_ = s.store.AddAudit(ctx, "agent", "device.e2e_key_restored", agentID, detail)
	case store.DeviceKeyEventIssue:
		s.raiseDeviceKeyIssue(ctx, agentID, reportedHostname, out.Issue, out.Pinned, out.Presented, ip, version)
	}
}

func (s *Server) raiseDeviceKeyIssue(ctx context.Context, agentID, reportedHostname, issue, pinned, presented, ip, version string) {
	pinnedFP, presentedFP := e2e.DisplayFingerprint(pinned), e2e.DisplayFingerprint(presented)
	// The stored hostname names the device in the alert: the reported one comes
	// from whoever presented this key, and is kept only as context.
	hostname := agentID
	if a, err := s.store.GetAgent(ctx, agentID); err == nil {
		hostname = a.Hostname
	}
	log.Printf("agent: device key issue=%s agent=%s pinned=%s presented=%s ip=%s version=%.32q",
		issue, agentID, pinnedFP, presentedFP, ip, version)
	detail, _ := json.Marshal(map[string]string{
		"issue": issue, "pinned_fingerprint": pinnedFP, "presented_fingerprint": presentedFP,
		"ip": ip, "version": cleanHeaderValue(version, 32), "reported_hostname": cleanHeaderValue(reportedHostname, 255),
	})
	_ = s.store.AddAudit(ctx, "agent", "device.e2e_key_issue", agentID, detail)
	if s.keyNotifier != nil {
		n := s.keyNotifier
		go func() {
			nctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			n.QueueDeviceKeyIssue(nctx, agentID, hostname, issue, pinnedFP, presentedFP, ip)
		}()
	}
}

// Machines that share one identity (a disk image cloned after enrollment) keep
// taking the connection from each other: each one the server closes reconnects
// at once. One machine on a flaky network replaces a half-open connection now
// and then, from one address and the next, never back and forth this often.
const (
	duplicateWindow    = 10 * time.Minute
	duplicateTakeovers = 6 // in the window
	duplicatePerIP     = 3 // takeovers to each of at least two addresses
	duplicateHistory   = 32
)

type takeover struct {
	at time.Time
	ip string
}

type connHistory struct {
	lastIP    string
	takeovers []takeover
}

type connectionWatch struct {
	mu     sync.Mutex
	agents map[string]*connHistory
}

// observe records one attachment and reports whether the agent's connections
// now look like several machines using the same identity. replaced is whether
// the attachment displaced a live connection of the same agent.
func (w *connectionWatch) observe(agentID, ip string, replaced bool, now time.Time) bool {
	if ip == "" {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.agents == nil {
		w.agents = make(map[string]*connHistory)
	}
	h := w.agents[agentID]
	if h == nil {
		h = &connHistory{}
		w.agents[agentID] = h
	}
	defer func() { h.lastIP = ip }()
	if !replaced || h.lastIP == "" || h.lastIP == ip {
		return false
	}
	kept := h.takeovers[:0]
	for _, t := range h.takeovers {
		if now.Sub(t.at) < duplicateWindow {
			kept = append(kept, t)
		}
	}
	h.takeovers = append(kept, takeover{at: now, ip: ip})
	if len(h.takeovers) > duplicateHistory {
		h.takeovers = h.takeovers[len(h.takeovers)-duplicateHistory:]
	}
	if len(h.takeovers) < duplicateTakeovers {
		return false
	}
	perIP := map[string]int{}
	for _, t := range h.takeovers {
		perIP[t.ip]++
	}
	busy := 0
	for _, n := range perIP {
		if n >= duplicatePerIP {
			busy++
		}
	}
	return busy >= 2
}

// reset forgets past connection takeovers for one agent, for example after an
// administrator clears a duplicate-identity warning or retires the device, so
// pre-review takeovers cannot re-trigger the warning on a single reconnect.
func (w *connectionWatch) reset(agentID string) {
	w.mu.Lock()
	delete(w.agents, agentID)
	w.mu.Unlock()
}

func (s *Server) watchAgentConnection(ctx context.Context, agentID, ip, version string, replaced bool) {
	if !s.conns.observe(agentID, ip, replaced, time.Now()) {
		return
	}
	raised, err := s.store.MarkAgentDeviceDuplicate(ctx, agentID, ip, version)
	if err != nil {
		log.Printf("agent: record duplicate identity agent=%s: %v", agentID, err)
		return
	}
	if raised {
		pinned := ""
		if a, err := s.store.GetAgent(ctx, agentID); err == nil {
			pinned = a.DevicePublicKey
		}
		s.raiseDeviceKeyIssue(ctx, agentID, "", models.DeviceKeyDuplicate, pinned, "", ip, version)
	}
}

// decodeDeviceKeyReview reads a small review body (the key and the reason the
// reviewer wrote down, which goes to the audit log).
func decodeDeviceKeyReview(w http.ResponseWriter, r *http.Request, in any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := decode(r, in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return false
	}
	return true
}

// approveDeviceKey pins the key the device presented, which an administrator
// compared on the device first. Unrestricted administrators only: the key
// decides which machine every technician's encrypted session reaches.
func (s *Server) approveDeviceKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnrestricted(w, r, "device encryption keys") {
		return
	}
	id := chi.URLParam(r, "id")
	if !s.requireAgent(w, r, id) {
		return
	}
	var in struct {
		PendingKey string `json:"pending_device_public_key"`
		Reason     string `json:"reason"`
	}
	if !decodeDeviceKeyReview(w, r, &in) {
		return
	}
	if e2e.ValidatePublicKey(in.PendingKey) != nil {
		writeErr(w, http.StatusBadRequest, "invalid device key")
		return
	}
	reason := e2e.CleanOneLine(in.Reason, 200)
	if reason == "" {
		writeCodedErr(w, http.StatusBadRequest, "reason_required", "say why the new key is the device's")
		return
	}
	previous, err := s.store.ApproveAgentDeviceKey(r.Context(), id, in.PendingKey, actorOf(r))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "device not found")
		return
	case errors.Is(err, store.ErrDeviceKeyNotPending):
		writeCodedErr(w, http.StatusConflict, "device_key_not_pending", err.Error())
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.conns.reset(id)
	detail, _ := json.Marshal(map[string]string{
		"previous_fingerprint": e2e.DisplayFingerprint(previous), "fingerprint": e2e.DisplayFingerprint(in.PendingKey), "reason": reason,
	})
	_ = s.store.AddAudit(r.Context(), actorOf(r), "device.e2e_key_approved", id, detail)
	agent, err := s.store.GetAgent(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

// dismissDeviceKeyIssue keeps the pinned key and clears the issue, for instance
// after the extra machine was re-enrolled or the old agent replaced. If the
// cause persists, the next registration raises it again.
func (s *Server) dismissDeviceKeyIssue(w http.ResponseWriter, r *http.Request) {
	if !s.requireUnrestricted(w, r, "device encryption keys") {
		return
	}
	id := chi.URLParam(r, "id")
	if !s.requireAgent(w, r, id) {
		return
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if !decodeDeviceKeyReview(w, r, &in) {
		return
	}
	reason := e2e.CleanOneLine(in.Reason, 200)
	if reason == "" {
		writeCodedErr(w, http.StatusBadRequest, "reason_required", "say why the issue can be cleared")
		return
	}
	issue, pinned, pending, err := s.store.DismissAgentDeviceKeyIssue(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "device not found")
		return
	case errors.Is(err, store.ErrDeviceKeyNoIssue):
		writeCodedErr(w, http.StatusConflict, "device_key_no_issue", err.Error())
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.conns.reset(id)
	detail, _ := json.Marshal(map[string]string{
		"issue": issue, "fingerprint": e2e.DisplayFingerprint(pinned), "presented_fingerprint": e2e.DisplayFingerprint(pending), "reason": reason,
	})
	_ = s.store.AddAudit(r.Context(), actorOf(r), "device.e2e_key_issue_dismissed", id, detail)
	agent, err := s.store.GetAgent(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

// writeDeviceKeyIssue refuses a native remote session on a device under review.
func writeDeviceKeyIssue(w http.ResponseWriter, issue string) {
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": "this device's encryption identity needs an administrator's review before a remote session",
		"code":  "remote_device_key_issue",
		"issue": issue,
	})
}
