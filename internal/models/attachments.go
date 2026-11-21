package models

import (
	"errors"
	"time"
)

// Attachment is one place a check or scheduled task applies: exactly one
// policy or one device. A device gets the check or task when any attachment
// reaches it, and it runs there once however many do.
type Attachment struct {
	PolicyID *string `json:"policy_id,omitempty"`
	AgentID  *string `json:"agent_id,omitempty"`
	// Name is the policy's name or the device's hostname, for display.
	Name    string    `json:"name,omitempty"`
	AddedBy string    `json:"added_by,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// ErrInvalidAttachment refuses an attachment naming both a policy and a
// device, or neither.
var ErrInvalidAttachment = errors.New("an attachment names exactly one of policy_id or agent_id")

// Validate checks that the attachment names exactly one target.
func (a Attachment) Validate() error {
	if (a.PolicyID == nil || *a.PolicyID == "") == (a.AgentID == nil || *a.AgentID == "") {
		return ErrInvalidAttachment
	}
	return nil
}

// Key identifies the attachment's target: "policy:<id>" or "agent:<id>".
func (a Attachment) Key() string {
	if a.PolicyID != nil {
		return "policy:" + *a.PolicyID
	}
	if a.AgentID != nil {
		return "agent:" + *a.AgentID
	}
	return ""
}

// AttachmentTargets splits attachments into policy and device ids.
func AttachmentTargets(atts []Attachment) (policyIDs, agentIDs []string) {
	for _, a := range atts {
		switch {
		case a.PolicyID != nil:
			policyIDs = append(policyIDs, *a.PolicyID)
		case a.AgentID != nil:
			agentIDs = append(agentIDs, *a.AgentID)
		}
	}
	return policyIDs, agentIDs
}

// SingleTarget returns the attachment's ids when there is exactly one, for
// the one-owner fields kept in the API.
func SingleTarget(atts []Attachment) (agentID, policyID *string) {
	if len(atts) != 1 {
		return nil, nil
	}
	return atts[0].AgentID, atts[0].PolicyID
}

// RequestedAttachments reads where a new check or task should apply: the
// attachments list, or the one-owner shorthand agent_id / policy_id. Both at
// once, an invalid entry or a repeated target is an error.
func RequestedAttachments(list []Attachment, agentID, policyID *string) ([]Attachment, error) {
	if agentID != nil && *agentID == "" {
		agentID = nil
	}
	if policyID != nil && *policyID == "" {
		policyID = nil
	}
	if agentID != nil || policyID != nil {
		if len(list) > 0 || (agentID != nil && policyID != nil) {
			return nil, errors.New("send attachments, or one of agent_id or policy_id")
		}
		return []Attachment{{AgentID: agentID, PolicyID: policyID}}, nil
	}
	seen := map[string]bool{}
	out := make([]Attachment, 0, len(list))
	for _, a := range list {
		if err := a.Validate(); err != nil {
			return nil, err
		}
		if seen[a.Key()] {
			return nil, errors.New("an attachment is listed twice")
		}
		seen[a.Key()] = true
		out = append(out, Attachment{AgentID: a.AgentID, PolicyID: a.PolicyID})
	}
	return out, nil
}

// OnAgent is the attachment list of an item applied to one device; nil id
// gives none.
func OnAgent(id *string) []Attachment {
	if id == nil {
		return nil
	}
	return []Attachment{{AgentID: id}}
}

// OnPolicy is the attachment list of an item applied to one policy; nil id
// gives none.
func OnPolicy(id *string) []Attachment {
	if id == nil {
		return nil
	}
	return []Attachment{{PolicyID: id}}
}
