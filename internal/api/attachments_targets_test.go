package api

import (
	"testing"

	"github.com/p1ngu/rmm/internal/models"
)

// An update may name an item's targets only to repeat them. Every way of
// naming another target, or naming the same one inconsistently, is refused;
// what GET returns (attachments plus the one-owner field for an item on one
// target) is accepted.
func TestUnchangedTargets(t *testing.T) {
	dev1, dev2, pol := "dev-1", "dev-2", "pol-1"
	empty := ""
	onDev := []models.Attachment{{AgentID: &dev1}}
	onPol := []models.Attachment{{PolicyID: &pol}}
	shared := []models.Attachment{{AgentID: &dev1}, {PolicyID: &pol}}
	for _, tc := range []struct {
		what            string
		list            []models.Attachment
		agentID, policy *string
		current         []models.Attachment
		want            bool
	}{
		{"nothing named", nil, nil, nil, onDev, true},
		{"empty one-owner fields", nil, &empty, &empty, onDev, true},
		{"what GET returns, one device", onDev, &dev1, nil, onDev, true},
		{"what GET returns, one policy", onPol, nil, &pol, onPol, true},
		{"what GET returns, shared", shared, nil, nil, shared, true},
		{"shared in another order", []models.Attachment{{PolicyID: &pol}, {AgentID: &dev1}}, nil, nil, shared, true},
		{"legacy one-owner field only", nil, &dev1, nil, onDev, true},
		{"legacy field naming another device", nil, &dev2, nil, onDev, false},
		{"both legacy fields", nil, &dev1, &pol, onDev, false},
		{"attachments naming another device", []models.Attachment{{AgentID: &dev2}}, nil, nil, onDev, false},
		{"same attachments, other agent_id", onDev, &dev2, nil, onDev, false},
		{"same attachments, a policy_id too", onDev, &dev1, &pol, onDev, false},
		{"a one-owner field beside a shared list", shared, &dev1, nil, shared, false},
		{"a subset of a shared item", onDev, nil, nil, shared, false},
		{"a superset", shared, nil, nil, onDev, false},
		{"a target listed twice", []models.Attachment{{AgentID: &dev1}, {AgentID: &dev1}}, nil, nil, onDev, false},
		{"an attachment naming both kinds", []models.Attachment{{AgentID: &dev1, PolicyID: &pol}}, nil, nil, onDev, false},
		{"an item that applies nowhere, nothing named", nil, nil, nil, nil, true},
		{"an item that applies nowhere, one named", onDev, nil, nil, nil, false},
	} {
		if got := unchangedTargets(tc.list, tc.agentID, tc.policy, tc.current); got != tc.want {
			t.Errorf("%s: unchangedTargets = %v, want %v", tc.what, got, tc.want)
		}
	}
}
