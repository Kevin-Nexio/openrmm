package store

import (
	"testing"

	"github.com/p1ngu/rmm/internal/models"
)

// Every case of what one registration does to a device's key state. The
// invariant across all of them: once a key is pinned, nothing the device
// presents replaces it.
func TestNextDeviceKeyState(t *testing.T) {
	const pinned, other, third = "K1", "K2", "K3"
	none := DeviceKeyPresentation{}
	unavailable := DeviceKeyPresentation{Unavailable: true}
	key := func(k string) DeviceKeyPresentation { return DeviceKeyPresentation{Key: k} }
	st := func(issue, pending string) deviceKeyState {
		return deviceKeyState{Pinned: pinned, Issue: issue, Pending: pending}
	}
	cases := []struct {
		name  string
		cur   deviceKeyState
		p     DeviceKeyPresentation
		want  deviceKeyState
		event string
	}{
		{"legacy agent stays legacy", deviceKeyState{}, none, deviceKeyState{}, DeviceKeyEventNone},
		{"first key is pinned", deviceKeyState{}, key(pinned), st("", ""), DeviceKeyEventPinned},
		{"same key, nothing to do", st("", ""), key(pinned), st("", ""), DeviceKeyEventNone},
		{"different key is a change, not a refusal", st("", ""), key(other), st(models.DeviceKeyChanged, other), DeviceKeyEventIssue},
		{"same different key again is only seen", st(models.DeviceKeyChanged, other), key(other), st(models.DeviceKeyChanged, other), DeviceKeyEventIssueSeen},
		{"a third key means several machines", st(models.DeviceKeyChanged, other), key(third), st(models.DeviceKeyDuplicate, third), DeviceKeyEventIssue},
		{"pinned key back during a change means two machines", st(models.DeviceKeyChanged, other), key(pinned), st(models.DeviceKeyDuplicate, other), DeviceKeyEventIssue},
		{"duplicate stays duplicate on the pinned key", st(models.DeviceKeyDuplicate, other), key(pinned), st(models.DeviceKeyDuplicate, other), DeviceKeyEventIssueSeen},
		{"duplicate keeps the latest other key", st(models.DeviceKeyDuplicate, other), key(third), st(models.DeviceKeyDuplicate, third), DeviceKeyEventIssueSeen},
		{"older agent without a key is outdated", st("", ""), none, st(models.DeviceKeyOutdated, ""), DeviceKeyEventIssue},
		{"new agent that lost its key is missing", st("", ""), unavailable, st(models.DeviceKeyMissing, ""), DeviceKeyEventIssue},
		{"outdated again is only seen", st(models.DeviceKeyOutdated, ""), none, st(models.DeviceKeyOutdated, ""), DeviceKeyEventIssueSeen},
		{"outdated then missing changes the issue", st(models.DeviceKeyOutdated, ""), unavailable, st(models.DeviceKeyMissing, ""), DeviceKeyEventIssue},
		{"pinned key back after missing resolves", st(models.DeviceKeyMissing, ""), key(pinned), st("", ""), DeviceKeyEventResolved},
		{"pinned key back after outdated resolves", st(models.DeviceKeyOutdated, ""), key(pinned), st("", ""), DeviceKeyEventResolved},
		{"a different key after missing is a change", st(models.DeviceKeyMissing, ""), key(other), st(models.DeviceKeyChanged, other), DeviceKeyEventIssue},
		{"no key during a change means two machines", st(models.DeviceKeyChanged, other), none, st(models.DeviceKeyDuplicate, other), DeviceKeyEventIssue},
		{"no key during duplicate is only seen", st(models.DeviceKeyDuplicate, other), unavailable, st(models.DeviceKeyDuplicate, other), DeviceKeyEventIssueSeen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, event := nextDeviceKeyState(c.cur, c.p)
			if got != c.want || event != c.event {
				t.Fatalf("next(%+v, %+v) = %+v, %q; want %+v, %q", c.cur, c.p, got, event, c.want, c.event)
			}
			if c.cur.Pinned != "" && got.Pinned != c.cur.Pinned {
				t.Fatalf("the pinned key changed from %q to %q", c.cur.Pinned, got.Pinned)
			}
		})
	}
}

func TestClipText(t *testing.T) {
	if got := clipText("ação", 2); got != "a" {
		t.Fatalf("clipText split a character: %q", got)
	}
	if got := clipText("abc", 10); got != "abc" {
		t.Fatalf("clipText changed a short value: %q", got)
	}
}
