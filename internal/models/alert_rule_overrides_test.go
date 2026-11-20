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
