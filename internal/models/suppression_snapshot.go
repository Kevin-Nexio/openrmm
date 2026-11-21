package models

import "time"

// SuppressionSnapshot is what a silence or maintenance window covers, recorded
// when it is made so later changes never widen it.
//
// For a device scope, Agents holds that device. For a check scope, Agents
// holds every device the check is attached to directly, and CoversPolicyReach
// says whether it had a policy attachment, which only an unrestricted
// principal may silence: such a silence follows the check everywhere it
// reaches. Each device's monitoring scope is recorded with it; the silence
// stops applying to a device that moves.
type SuppressionSnapshot struct {
	Agents            map[string]time.Time
	Hostnames         map[string]string
	CoversPolicyReach bool
}

// Same reports whether two snapshots cover the same devices, with the same
// monitoring scopes, and the same policy reach. Nil is only the same as nil.
func (s *SuppressionSnapshot) Same(o *SuppressionSnapshot) bool {
	if s == nil || o == nil {
		return s == o
	}
	if s.CoversPolicyReach != o.CoversPolicyReach || len(s.Agents) != len(o.Agents) {
		return false
	}
	for id, since := range s.Agents {
		if other, ok := o.Agents[id]; !ok || !other.Equal(since) {
			return false
		}
	}
	return true
}
