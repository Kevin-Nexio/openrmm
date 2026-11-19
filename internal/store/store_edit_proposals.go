package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/p1ngu/rmm/internal/models"
)

// EditTarget is an object as an edit proposal sees it: its view (what the
// proposal can change, and is bound to by hash), the object as the API
// returns it (what applying the edit starts from), and a name to show.
type EditTarget struct {
	View   models.EditView
	Object map[string]any
	Name   string
	// Pending marks an AI proposal nobody has reviewed yet. An edit proposal
	// never applies to one: switching a proposed check or task on through an
	// edit would approve it while the review showed only the changed fields,
	// not the script it runs. It is reviewed on its own screen instead.
	Pending bool
}

// pickFields copies the editable fields of kind out of an object's JSON form.
// A field the object leaves out is recorded as null, so the view is complete.
func pickFields(kind string, obj map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range models.EditableFields[kind] {
		out[k] = obj[k]
	}
	return out
}

func asMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

// EditTarget loads the object an edit proposal of kind is about.
func (s *Store) EditTarget(ctx context.Context, kind, id string) (*EditTarget, error) {
	var obj any
	t := &EditTarget{}
	switch kind {
	case models.EditScript:
		sc, err := s.GetScript(ctx, id)
		if err != nil {
			return nil, err
		}
		obj, t.Name, t.Pending = sc, sc.Name, sc.Pending
	case models.EditCheck:
		c, err := s.GetCheck(ctx, id)
		if err != nil {
			return nil, err
		}
		obj, t.Name, t.Pending = c, c.Name, c.ProposedBy != "" && c.ApprovedBy == ""
		for _, a := range c.Attachments {
			t.View.Attachments = append(t.View.Attachments, a.Key())
		}
	case models.EditTask:
		tk, err := s.GetTask(ctx, id)
		if err != nil {
			return nil, err
		}
		obj, t.Name, t.Pending = tk, tk.Name, tk.ProposedBy != "" && tk.ApprovedBy == ""
		for _, a := range tk.Attachments {
			t.View.Attachments = append(t.View.Attachments, a.Key())
		}
	case models.EditPolicy:
		p, err := s.GetPolicy(ctx, id)
		if err != nil {
			return nil, err
		}
		obj, t.Name, t.Pending = p, p.Name, p.Pending
		asg, err := s.ListPolicyAssignments(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, a := range asg {
			t.View.Assignments = append(t.View.Assignments, models.EditAssignment{ID: a.ID, ScopeType: a.ScopeType, ScopeID: a.ScopeID, OS: a.OS, Role: a.Role})
		}
		if t.View.Exclusions, err = s.excludedAgentIDs(ctx, false, id); err != nil {
			return nil, err
		}
	case models.EditPatchPolicy:
		p, err := s.GetPatchPolicy(ctx, id)
		if err != nil {
			return nil, err
		}
		obj, t.Name, t.Pending = p, p.Name, p.Pending
		asg, err := s.ListPatchPolicyAssignments(ctx, id)
		if err != nil {
			return nil, err
		}
		for _, a := range asg {
			t.View.Assignments = append(t.View.Assignments, models.EditAssignment{ID: a.ID, ScopeType: a.ScopeType, ScopeID: a.ScopeID, OS: a.OS, Role: a.Role})
		}
		if t.View.Exclusions, err = s.excludedAgentIDs(ctx, true, id); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown kind %q", kind)
	}
	m, err := asMap(obj)
	if err != nil {
		return nil, err
	}
	t.Object = m
	t.View.Fields = pickFields(kind, m)
	t.View.Normalize()
	return t, nil
}

func (s *Store) excludedAgentIDs(ctx context.Context, patch bool, policyID string) ([]string, error) {
	list, err := s.ListExclusions(ctx, patch, policyID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, e.AgentID)
	}
	return out, nil
}

const editProposalCols = `id, kind, target_id, base_hash, changes, reason, proposed_by, status, decided_by, outcome, created_at, decided_at`

func scanEditProposal(row pgx.Row) (*models.EditProposal, error) {
	var p models.EditProposal
	var changes []byte
	if err := row.Scan(&p.ID, &p.Kind, &p.TargetID, &p.BaseHash, &changes, &p.Reason, &p.ProposedBy,
		&p.Status, &p.DecidedBy, &p.Outcome, &p.CreatedAt, &p.DecidedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	p.Changes = changes
	return &p, nil
}

// CreateEditProposal records a pending proposal, superseding the one already
// open for the same object, so a review never shows two competing edits.
func (s *Store) CreateEditProposal(ctx context.Context, p *models.EditProposal) (*models.EditProposal, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// One being applied right now is left alone: the unique index on the open
	// proposal then refuses the new one, and the caller proposes again later.
	if _, err := tx.Exec(ctx, `UPDATE edit_proposals SET status='superseded', decided_at=now(), decided_by=$3
		WHERE kind=$1 AND target_id=$2 AND status='pending' AND `+claimFreeSQL, p.Kind, p.TargetID, p.ProposedBy); err != nil {
		return nil, err
	}
	out, err := scanEditProposal(tx.QueryRow(ctx, `INSERT INTO edit_proposals (id, kind, target_id, base_hash, changes, reason, proposed_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+editProposalCols,
		newID(), p.Kind, p.TargetID, p.BaseHash, []byte(p.Changes), p.Reason, p.ProposedBy))
	if isUniqueViolation(err) {
		return nil, fmt.Errorf("%w: an edit to this object is being applied; propose again once it is done", ErrConflict)
	}
	if err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

// GetEditProposal fetches one proposal.
func (s *Store) GetEditProposal(ctx context.Context, id string) (*models.EditProposal, error) {
	return scanEditProposal(s.pool.QueryRow(ctx, `SELECT `+editProposalCols+` FROM edit_proposals WHERE id=$1`, id))
}

// ListEditProposals lists proposals, newest first, narrowed by kind and status
// when given.
func (s *Store) ListEditProposals(ctx context.Context, kind, status string, limit int) ([]models.EditProposal, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `SELECT `+editProposalCols+` FROM edit_proposals
		WHERE ($1 = '' OR kind=$1) AND ($2 = '' OR status=$2) ORDER BY created_at DESC, id LIMIT $3`, kind, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.EditProposal{}
	for rows.Next() {
		p, err := scanEditProposal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// FinishEditProposal closes a pending proposal with status (applied,
// rejected, stale or failed). ErrConflict when it is no longer pending, or
// someone else has claimed it to apply it: only the first decision counts.
func (s *Store) FinishEditProposal(ctx context.Context, id, status, actor, outcome string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE edit_proposals SET status=$2, decided_by=$3, outcome=$4, decided_at=$5, claimed_at=NULL
		WHERE id=$1 AND status='pending' AND (`+claimFreeSQL+` OR decided_by=$3)`, id, status, actor, outcome, time.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

// claimFreeSQL is true for a proposal nobody is applying: unclaimed, or
// claimed so long ago that the apply cannot still be running.
const claimFreeSQL = `(decided_by='' OR claimed_at IS NULL OR claimed_at < now() - interval '15 minutes')`

// ClaimEditProposal marks a pending proposal as being applied by actor, so a
// second approver cannot apply or reject it at the same time. The same actor
// may claim it again (a retry), and a stale claim is free. It returns the
// proposal as claimed; ErrConflict when it is no longer pending or someone
// else is applying it.
func (s *Store) ClaimEditProposal(ctx context.Context, id, actor string) (*models.EditProposal, error) {
	p, err := scanEditProposal(s.pool.QueryRow(ctx, `UPDATE edit_proposals SET decided_by=$2, claimed_at=now()
		WHERE id=$1 AND status='pending' AND (`+claimFreeSQL+` OR decided_by=$2) RETURNING `+editProposalCols, id, actor))
	if errors.Is(err, ErrNotFound) {
		if _, getErr := s.GetEditProposal(ctx, id); getErr != nil {
			return nil, getErr
		}
		return nil, ErrConflict
	}
	return p, err
}

// ReleaseEditProposal hands back a claim when applying did not start.
func (s *Store) ReleaseEditProposal(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE edit_proposals SET decided_by='', claimed_at=NULL WHERE id=$1 AND status='pending'`, id)
	return err
}

// ScopeName names a client, site or department (group) for a review.
func (s *Store) ScopeName(ctx context.Context, scopeType, id string) (string, error) {
	var table string
	switch scopeType {
	case models.ScopeClient:
		table = "clients"
	case models.ScopeSite:
		table = "sites"
	case models.ScopeGroup:
		table = "device_groups"
	default:
		return "", nil
	}
	var name string
	err := s.pool.QueryRow(ctx, `SELECT name FROM `+table+` WHERE id=$1`, id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}
