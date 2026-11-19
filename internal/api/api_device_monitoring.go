package api

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/p1ngu/rmm/internal/models"
	"github.com/p1ngu/rmm/internal/store"
)

// The checks and tasks that apply to one device, for its detail drawer.
//
// GET /api/checks?agent_id= answers a different question: the checks assigned
// to the device itself. Most monitoring arrives through a policy on the
// device's department, site or client, so that list was empty on machines that
// were in fact being watched. These resolve the set the scheduler runs —
// ChecksForAgent and TasksForAgent, the same queries — and add what happened
// on this device: each check's state here, each task's last run here.
//
// The scheduler runs only enabled rows, so these list only enabled rows: a
// disabled check, or an AI proposal nobody has reviewed, is not applied to the
// machine, and the Checks and Scheduled tasks screens are where to find those.

// monitoringSource is one way a check or task reaches a device: attached to
// the device itself (Direct), or through a policy that reaches it.
type monitoringSource struct {
	Direct   bool    `json:"direct,omitempty"`
	PolicyID *string `json:"policy_id,omitempty"`
	Name     string  `json:"name,omitempty"`
}

// deviceCheck is a check as it stands on one device.
type deviceCheck struct {
	models.Check
	// Sources are how the check reaches this device, direct first. A check
	// shared by several policies that reach the device lists each; it still
	// runs once.
	Sources []monitoringSource `json:"sources"`
	// PolicyName names the first policy it came through, for clients of the
	// one-owner API; empty when it reaches the device only directly.
	PolicyName string `json:"policy_name,omitempty"`
	// State is this device's: never-run checks read unknown.
	Status       string     `json:"status"`
	Value        *float64   `json:"value,omitempty"`
	Output       string     `json:"output"`
	LastResultAt *time.Time `json:"last_result_at,omitempty"`
}

// deviceTask is a task as it stands on one device.
type deviceTask struct {
	models.Task
	Sources    []monitoringSource `json:"sources"`
	PolicyName string             `json:"policy_name,omitempty"`
	// LastRunAt is when the task last queued a job on this device.
	LastRunAt *time.Time `json:"last_run_at,omitempty"`
}

func (s *Server) listDeviceChecks(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !s.requireAgent(w, r, id) {
		return
	}
	ctx := r.Context()
	siteID, clientID, err := s.store.AgentScope(ctx, id)
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
		return
	}
	checks, err := s.store.ChecksForAgent(ctx, id, siteID, clientID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	states := make(map[string]*models.CheckState, len(checks))
	for _, c := range checks {
		st, err := s.store.GetCheckState(ctx, c.ID, id)
		if errors.Is(err, store.ErrNotFound) {
			continue // dispatched to nothing yet: unknown
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		states[c.ID] = st
	}
	reaching, err := s.store.PoliciesReachingAgent(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := deviceChecks(checks, states, id, reaching)
	for i := range rows {
		if err := s.redactCheck(r, &rows[i].Check); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": rows})
}

func (s *Server) listDeviceTasks(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !s.requireAgent(w, r, id) {
		return
	}
	ctx := r.Context()
	siteID, clientID, err := s.store.AgentScope(ctx, id)
	if err != nil {
		writeErr(w, httpStatusFor(err), err.Error())
		return
	}
	tasks, err := s.store.TasksForAgent(ctx, id, siteID, clientID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	lastRuns := make(map[string]time.Time, len(tasks))
	for _, t := range tasks {
		at, err := s.store.LastTaskRunTime(ctx, t.ID, id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		lastRuns[t.ID] = at
	}
	reaching, err := s.store.PoliciesReachingAgent(ctx, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := deviceTasks(tasks, lastRuns, id, reaching)
	for i := range rows {
		if err := s.redactTask(r, &rows[i].Task); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": rows})
}

// sourcesOn lists how attachments reach the device agentID: directly, then
// through each policy among reaching, by name. The policies are those already
// applied to a device the caller may see, so no scope filter narrows them.
func sourcesOn(atts []models.Attachment, agentID string, reaching map[string]bool) []monitoringSource {
	var direct []monitoringSource
	var policies []monitoringSource
	for _, a := range atts {
		switch {
		case a.AgentID != nil && *a.AgentID == agentID:
			direct = append(direct, monitoringSource{Direct: true})
		case a.PolicyID != nil && reaching[*a.PolicyID]:
			id := *a.PolicyID
			policies = append(policies, monitoringSource{PolicyID: &id, Name: a.Name})
		}
	}
	sort.SliceStable(policies, func(i, j int) bool { return policies[i].Name < policies[j].Name })
	return append(direct, policies...)
}

// firstPolicy is the first policy among sources, for the one-owner fields.
func firstPolicy(sources []monitoringSource) (*string, string) {
	for _, s := range sources {
		if s.PolicyID != nil {
			return s.PolicyID, s.Name
		}
	}
	return nil, ""
}

// deviceChecks pairs each check with this device's state and how it reaches
// the device. Direct ones first, then by policy, then by name, so the drawer
// reads the same on every refresh.
func deviceChecks(checks []models.Check, states map[string]*models.CheckState, agentID string, reaching map[string]bool) []deviceCheck {
	out := make([]deviceCheck, 0, len(checks))
	for _, c := range checks {
		row := deviceCheck{Check: c, Status: models.CheckUnknown, Sources: sourcesOn(c.Attachments, agentID, reaching)}
		_, row.PolicyName = firstPolicy(row.Sources)
		if st := states[c.ID]; st != nil {
			if st.Status != "" {
				row.Status = st.Status
			}
			row.Value, row.Output, row.LastResultAt = st.LastValue, st.LastOutput, st.LastResultAt
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return lessBySource(out[i].Sources, out[i].Name, out[j].Sources, out[j].Name)
	})
	return out
}

// deviceTasks pairs each task with its last run on this device; a zero time
// means it has not run here.
func deviceTasks(tasks []models.Task, lastRuns map[string]time.Time, agentID string, reaching map[string]bool) []deviceTask {
	out := make([]deviceTask, 0, len(tasks))
	for _, t := range tasks {
		row := deviceTask{Task: t, Sources: sourcesOn(t.Attachments, agentID, reaching)}
		_, row.PolicyName = firstPolicy(row.Sources)
		if at := lastRuns[t.ID]; !at.IsZero() {
			at := at
			row.LastRunAt = &at
		}
		out = append(out, row)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return lessBySource(out[i].Sources, out[i].Name, out[j].Sources, out[j].Name)
	})
	return out
}

// lessBySource orders direct items first, then by their first policy's name,
// then by name.
func lessBySource(a []monitoringSource, aName string, b []monitoringSource, bName string) bool {
	aDirect := len(a) > 0 && a[0].Direct
	bDirect := len(b) > 0 && b[0].Direct
	if aDirect != bDirect {
		return aDirect
	}
	_, aPolicy := firstPolicy(a)
	_, bPolicy := firstPolicy(b)
	if aPolicy != bPolicy {
		return aPolicy < bPolicy
	}
	return aName < bName
}
