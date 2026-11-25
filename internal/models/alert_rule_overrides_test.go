package models

import (
	"encoding/json"
	"testing"
)

func TestRuleOverrideValidationAndReviewFingerprint(t *testing.T) {
	policyID := "policy"
	deviceID := "device"
	for _, kind := range ServerRuleTypes {
		c := Check{Attachments: []Attachment{{PolicyID: &policyID}}, Type: kind, Name: kind, Config: json.RawMessage(`{"override_parent":true}`)}
		if err := ValidateCheck(&c); err != nil || !c.OverridesParent() {
			t.Fatalf("%s: %v", kind, err)
		}
		review := PolicyReview{Checks: []Check{c}}
		review.Seal()
		before := review.Fingerprint
		review.Checks[0].Config = json.RawMessage(`{"override_parent":false}`)
		review.Seal()
		if review.Fingerprint == before {
			t.Fatal("override missing from fingerprint")
		}
		c.Attachments = []Attachment{{AgentID: &deviceID}}
		if err := ValidateCheck(&c); err == nil {
			t.Fatal("device override accepted")
		}
	}
	if cfg, err := ParseServerRuleConfig(CheckConnectivity, nil); err != nil || cfg.OverrideParent {
		t.Fatalf("default=%+v %v", cfg, err)
	}
	if _, err := ParseServerRuleConfig(CheckConnectivity, json.RawMessage(`{"override_parent":"true"}`)); err == nil {
		t.Fatal("string flag accepted")
	}
}

func TestClearingRuleOverrideRestoresLegacyConfig(t *testing.T) {
	for _, kind := range ServerRuleTypes {
		legacy, err := ParseServerRuleConfig(kind, json.RawMessage(`{"mode":"alert"}`))
		if err != nil {
			t.Fatal(err)
		}
		override := legacy
		override.OverrideParent = true
		withOverride, err := ParseServerRuleConfig(kind, override.Raw())
		if err != nil || !withOverride.OverrideParent {
			t.Fatalf("%s: override configuration was not persisted: %v", kind, err)
		}
		withOverride.OverrideParent = false
		if got, want := string(withOverride.Raw()), string(legacy.Raw()); got != want {
			t.Fatalf("%s: cleared config = %s, want legacy shape %s", kind, got, want)
		}
	}
}
