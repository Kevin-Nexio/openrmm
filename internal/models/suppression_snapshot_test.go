package models

import (
	"testing"
	"time"
)

func TestSuppressionSnapshotSame(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	a := &SuppressionSnapshot{Agents: map[string]time.Time{"d1": at}}
	for name, tc := range map[string]struct {
		other *SuppressionSnapshot
		want  bool
	}{
		"identical":           {&SuppressionSnapshot{Agents: map[string]time.Time{"d1": at}}, true},
		"a device moved":      {&SuppressionSnapshot{Agents: map[string]time.Time{"d1": at.Add(time.Second)}}, false},
		"a device added":      {&SuppressionSnapshot{Agents: map[string]time.Time{"d1": at, "d2": at}}, false},
		"another device":      {&SuppressionSnapshot{Agents: map[string]time.Time{"d2": at}}, false},
		"policy reach gained": {&SuppressionSnapshot{Agents: map[string]time.Time{"d1": at}, CoversPolicyReach: true}, false},
		"nil":                 {nil, false},
	} {
		if got := a.Same(tc.other); got != tc.want {
			t.Errorf("%s: Same = %v, want %v", name, got, tc.want)
		}
	}
	var none *SuppressionSnapshot
	if !none.Same(nil) {
		t.Error("nil is the same as nil")
	}
}
