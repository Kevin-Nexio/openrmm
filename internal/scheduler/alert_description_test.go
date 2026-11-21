package scheduler

import (
	"testing"
	"time"

	"github.com/p1ngu/rmm/internal/models"
)

func TestAlertDeviceDescriptionRespectsScopeHistory(t *testing.T) {
	now := time.Now()
	id := "agent-id"
	captured := now.Add(-2 * time.Hour)
	for _, tc := range []struct {
		name          string
		id            string
		scopeSince    time.Time
		incidentScope *time.Time
		want          string
	}{
		{"same scope", id, captured, &captured, "Friendly device"},
		{"scope change before observed time", id, now.Add(-time.Hour), &captured, ""},
		{"scope change after observed time", id, now.Add(time.Second), &captured, ""},
		{"unknown device scope", id, time.Time{}, &captured, ""},
		{"legacy incident", id, captured, nil, ""},
		{"wrong device", "another-agent", captured, &captured, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alert := &models.Alert{AgentSnapshotID: &id, AgentMonitoringScopeSince: tc.incidentScope, FirstSeenAt: now}
			agent := &models.Agent{ID: tc.id, Description: "Friendly device", MonitoringScopeSince: tc.scopeSince}
			if got := alertDeviceDescription(alert, agent); got != tc.want {
				t.Fatalf("description = %q, want %q", got, tc.want)
			}
		})
	}
	if alertDeviceDescription(nil, nil) != "" || alertDeviceDescription(&models.Alert{}, &models.Agent{}) != "" {
		t.Fatal("missing device should fall back to the snapshot hostname")
	}
}
