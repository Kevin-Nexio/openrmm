package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
	// A concurrent decision holds this row for its entire transaction. A
	// proposal should report the conflict instead of waiting to replace it.
	var previous string
	err = tx.QueryRow(ctx, `SELECT id FROM edit_proposals
		WHERE kind=$1 AND target_id=$2 AND status='pending' FOR UPDATE NOWAIT`, p.Kind, p.TargetID).Scan(&previous)
	switch {
	case err == nil:
		tag, err := tx.Exec(ctx, `UPDATE edit_proposals SET status='superseded', decided_at=now(), decided_by=$2, claimed_at=NULL
			WHERE id=$1 AND `+legacyClaimFreeSQL, previous, p.ProposedBy)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return nil, fmt.Errorf("%w: an edit to this object is being applied; propose again once it is done", ErrConflict)
		}
	case !errors.Is(err, pgx.ErrNoRows):
		if errors.Is(configLockError(err), ErrConflict) {
			return nil, fmt.Errorf("%w: an edit to this object is being applied; propose again once it is done", ErrConflict)
		}
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

// legacyClaimFreeSQL honors claims left by the preceding implementation.
// Current decisions are guarded by a transaction lock rather than a lease.
const legacyClaimFreeSQL = `(decided_by='' OR claimed_at IS NULL OR claimed_at < now() - interval '15 minutes')`

// LockEditProposal locks an undecided proposal for this database transaction.
// The audit actor is attribution only. It does not grant ownership of a lock.
func (s *Store) LockEditProposal(ctx context.Context, id string) (*models.EditProposal, error) {
	if err := s.requireConfigTransaction(); err != nil {
		return nil, err
	}
	p, err := scanEditProposal(s.pool.QueryRow(ctx, `SELECT `+editProposalCols+` FROM edit_proposals
		WHERE id=$1 AND status='pending' AND `+legacyClaimFreeSQL+` FOR UPDATE NOWAIT`, id))
	if errors.Is(err, ErrNotFound) {
		if _, err := s.GetEditProposal(ctx, id); err != nil {
			return nil, err
		}
		return nil, ErrConflict
	}
	return p, configLockError(err)
}

// FinishEditProposal records the decision on a locked row in the same
// transaction as its changes and audit entry.
func (s *Store) FinishEditProposal(ctx context.Context, id, status, actor, outcome string) error {
	if err := s.requireConfigTransaction(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE edit_proposals SET status=$2, decided_by=$3, outcome=$4, decided_at=now(), claimed_at=NULL
		WHERE id=$1 AND status='pending'`, id, status, actor, outcome)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
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
