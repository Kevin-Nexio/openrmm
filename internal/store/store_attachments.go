package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/p1ngu/rmm/internal/models"
)

// A check or scheduled task applies wherever one of its attachments reaches:
// a device attached directly, or a switched-on policy whose assignment reaches
// the device and does not exclude it (policiesReachingSQL). It runs there once
// however many attachments reach the device: every query selects the check or
// task row, never one row per attachment.

// dbBeginner opens a transaction (the pool).
type dbBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// attachmentKind names a kind's link table and its key column. Never built
// from input.
type attachmentKind struct{ table, key string }

var (
	checkAttachmentKind = attachmentKind{table: "check_attachments", key: "check_id"}
	taskAttachmentKind  = attachmentKind{table: "task_attachments", key: "task_id"}
)

// reachesSQL is true when the item with alias item reaches the device with
// alias a. Fixed SQL built from aliases this package supplies.
func (k attachmentKind) reachesSQL(item, a string) string {
	return `EXISTS (SELECT 1 FROM ` + k.table + ` att WHERE att.` + k.key + ` = ` + item + `.id AND (att.agent_id = ` + a + `.id OR att.policy_id IN ` + policiesReachingSQL(a) + `))`
}

// checkReachesSQL is true when check c reaches device a.
func checkReachesSQL(c, a string) string { return checkAttachmentKind.reachesSQL(c, a) }

// taskReachesSQL is true when task t reaches device a.
func taskReachesSQL(t, a string) string { return taskAttachmentKind.reachesSQL(t, a) }

// ErrPendingSingleAttachment refuses a second attachment for an AI proposal
// nobody approved yet. A policy's activation approves the proposals attached
// to it; with one attachment only, approving a proposal in one policy can never
// make it live through another policy nobody reviewed.
var ErrPendingSingleAttachment = errors.New("an AI proposal awaiting review applies to one policy or device only; approve it before attaching it elsewhere")

// ErrAttachmentExists refuses attaching an item where it already applies.
var ErrAttachmentExists = errors.New("it is already attached there")

// loadAttachments fills the attachments of each item, with the policy's name
// or the device's hostname, oldest first. lock holds the attachment rows FOR
// UPDATE, so none can be removed until the transaction ends.
func (k attachmentKind) load(ctx context.Context, q dbQuerier, ids []string, lock bool) (map[string][]models.Attachment, error) {
	out := make(map[string][]models.Attachment, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	forUpdate := ""
	if lock {
		forUpdate = " FOR UPDATE OF att"
	}
	rows, err := q.Query(ctx, `SELECT att.`+k.key+`, att.policy_id, att.agent_id, att.added_by, att.added_at,
		COALESCE(p.name, ag.hostname, '')
		FROM `+k.table+` att
		LEFT JOIN policies p ON p.id = att.policy_id
		LEFT JOIN agents ag ON ag.id = att.agent_id
		WHERE att.`+k.key+` = ANY($1::uuid[])
		ORDER BY att.added_at, att.policy_id NULLS LAST, att.agent_id`+forUpdate, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var a models.Attachment
		if err := rows.Scan(&id, &a.PolicyID, &a.AgentID, &a.AddedBy, &a.AddedAt, &a.Name); err != nil {
			return nil, err
		}
		out[id] = append(out[id], a)
	}
	return out, rows.Err()
}

// withCheckAttachments fills the attachments of every check in list.
func withCheckAttachments(ctx context.Context, q dbQuerier, list []models.Check, lock bool) ([]models.Check, error) {
	ids := make([]string, len(list))
	for i := range list {
		ids[i] = list[i].ID
	}
	byID, err := checkAttachmentKind.load(ctx, q, ids, lock)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Attachments = byID[list[i].ID]
		if list[i].Attachments == nil {
			list[i].Attachments = []models.Attachment{}
		}
		list[i].SingleAgentID, list[i].SinglePolicyID = models.SingleTarget(list[i].Attachments)
	}
	return list, nil
}

// withTaskAttachments fills the attachments of every task in list.
func withTaskAttachments(ctx context.Context, q dbQuerier, list []models.Task, lock bool) ([]models.Task, error) {
	ids := make([]string, len(list))
	for i := range list {
		ids[i] = list[i].ID
	}
	byID, err := taskAttachmentKind.load(ctx, q, ids, lock)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Attachments = byID[list[i].ID]
		if list[i].Attachments == nil {
			list[i].Attachments = []models.Attachment{}
		}
		list[i].SingleAgentID, list[i].SinglePolicyID = models.SingleTarget(list[i].Attachments)
	}
	return list, nil
}

// insertAttachments writes the attachments of a new item.
func (k attachmentKind) insert(ctx context.Context, q dbQuerier, id string, atts []models.Attachment) error {
	for _, a := range atts {
		if err := a.Validate(); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `INSERT INTO `+k.table+` (`+k.key+`, policy_id, agent_id, added_by) VALUES ($1,$2,$3,$4)`,
			id, a.PolicyID, a.AgentID, a.AddedBy); err != nil {
			if isUniqueViolation(err) {
				return ErrAttachmentExists
			}
			return err
		}
	}
	return nil
}

// pendingSQL is true for an AI proposal nobody approved yet.
const pendingSQL = `proposed_by <> '' AND approved_by = ''`

// attach adds one attachment to an existing item, refusing a second one for an
// unapproved AI proposal. The item row is locked so the check and the insert
// see the same state.
func (k attachmentKind) attach(ctx context.Context, pool dbBeginner, itemTable, id string, a models.Attachment) error {
	if err := a.Validate(); err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT `+pendingSQL+` FROM `+itemTable+` WHERE id=$1 FOR NO KEY UPDATE`, id).Scan(&pending); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if pending {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+k.table+` WHERE `+k.key+`=$1`, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrPendingSingleAttachment
		}
	}
	if err := k.insert(ctx, tx, id, []models.Attachment{a}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// detach removes one attachment. The item itself stays, as Not in use when it
// was the last one.
func (k attachmentKind) detach(ctx context.Context, q dbQuerier, id string, target models.Attachment) error {
	if err := target.Validate(); err != nil {
		return err
	}
	var tag pgconn.CommandTag
	var err error
	if target.PolicyID != nil {
		tag, err = q.Exec(ctx, `DELETE FROM `+k.table+` WHERE `+k.key+`=$1 AND policy_id=$2`, id, *target.PolicyID)
	} else {
		tag, err = q.Exec(ctx, `DELETE FROM `+k.table+` WHERE `+k.key+`=$1 AND agent_id=$2`, id, *target.AgentID)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AttachCheck attaches a check to one more policy or device.
func (s *Store) AttachCheck(ctx context.Context, checkID string, a models.Attachment) error {
	return checkAttachmentKind.attach(ctx, s.pool, "checks", checkID, a)
}

// DetachCheck removes one of a check's attachments.
func (s *Store) DetachCheck(ctx context.Context, checkID string, a models.Attachment) error {
	return checkAttachmentKind.detach(ctx, s.pool, checkID, a)
}

// AttachTask attaches a task to one more policy or device.
func (s *Store) AttachTask(ctx context.Context, taskID string, a models.Attachment) error {
	return taskAttachmentKind.attach(ctx, s.pool, "tasks", taskID, a)
}

// DetachTask removes one of a task's attachments.
func (s *Store) DetachTask(ctx context.Context, taskID string, a models.Attachment) error {
	return taskAttachmentKind.detach(ctx, s.pool, taskID, a)
}

// CopyCheckFor makes a copy of a check for one of its attachments: the copy
// takes that attachment, and the original keeps the others. It is how a policy
// gets its own thresholds for a check it shares. The copy keeps the original's
// provenance, and an AI proposal's copy is still a proposal.
func (s *Store) CopyCheckFor(ctx context.Context, checkID string, target models.Attachment, actor string) (*models.Check, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	orig, err := scanCheck(tx.QueryRow(ctx, `SELECT `+checkCols+` FROM checks c WHERE c.id=$1 FOR NO KEY UPDATE`, checkID))
	if err != nil {
		return nil, err
	}
	if err := checkAttachmentKind.detach(ctx, tx, checkID, target); err != nil {
		return nil, err
	}
	cp := *orig
	cp.Attachments = []models.Attachment{{PolicyID: target.PolicyID, AgentID: target.AgentID, AddedBy: actor}}
	if err := insertCheck(ctx, tx, &cp); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetCheck(ctx, cp.ID)
}

// CopyTaskFor is CopyCheckFor for a scheduled task.
func (s *Store) CopyTaskFor(ctx context.Context, taskID string, target models.Attachment, actor string) (*models.Task, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	orig, err := scanTask(tx.QueryRow(ctx, `SELECT `+taskCols+` FROM tasks t WHERE t.id=$1 FOR NO KEY UPDATE`, taskID))
	if err != nil {
		return nil, err
	}
	if err := taskAttachmentKind.detach(ctx, tx, taskID, target); err != nil {
		return nil, err
	}
	cp := *orig
	cp.Attachments = []models.Attachment{{PolicyID: target.PolicyID, AgentID: target.AgentID, AddedBy: actor}}
	if err := insertTask(ctx, tx, &cp); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetTask(ctx, cp.ID)
}

// AgentIDsForTask resolves every device a task reaches through any of its
// attachments, for "Run now".
func (s *Store) AgentIDsForTask(ctx context.Context, taskID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.id FROM agents a JOIN tasks t ON t.id=$1
		WHERE a.revoked_at IS NULL AND `+taskReachesSQL("t", "a")+` ORDER BY a.hostname, a.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// AgentIDsForCheck resolves every device a check reaches, for the editor's
// "used by" count.
func (s *Store) AgentIDsForCheck(ctx context.Context, checkID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.id FROM agents a JOIN checks c ON c.id=$1
		WHERE a.revoked_at IS NULL AND `+checkReachesSQL("c", "a")+` ORDER BY a.hostname, a.id`, checkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// attachmentLabel describes an attachment for errors and audit detail.
func attachmentLabel(a models.Attachment) string {
	switch {
	case a.PolicyID != nil:
		return fmt.Sprintf("policy %s", *a.PolicyID)
	case a.AgentID != nil:
		return fmt.Sprintf("device %s", *a.AgentID)
	}
	return strings.TrimSpace(a.Name)
}

// PoliciesReachingAgent lists the switched-on policies whose assignment
// reaches the device and that do not exclude it: the policies a check or task
// can reach it through.
func (s *Store) PoliciesReachingAgent(ctx context.Context, agentID string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT reach.policy_id FROM agents a CROSS JOIN LATERAL `+policiesReachingSQL("a")+` reach WHERE a.id=$1`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
