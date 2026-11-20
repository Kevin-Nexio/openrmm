package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/p1ngu/rmm/internal/models"
)

type dbSession interface {
	dbQuerier
	dbBeginner
}

// InConfigTransaction runs configuration reads, validation and writes on one
// connection. Nesting it creates a savepoint, so a refused proposal can roll
// back every step and still record its final decision in the outer transaction.
func (s *Store) InConfigTransaction(ctx context.Context, fn func(*Store) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		// pgx does not roll back automatically when the request is cancelled.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	}()
	writer := &Store{pool: tx, connections: s.connections, configAudits: []configAudit{}}
	if err := fn(writer); err != nil {
		return configLockError(err)
	}
	if s.configAudits != nil {
		// The surrounding write owns the audit lock. Publish the intents to
		// it only after this savepoint succeeds.
		if err := tx.Commit(ctx); err != nil {
			return configLockError(err)
		}
		s.configAudits = append(s.configAudits, writer.configAudits...)
		return nil
	}
	// Flush last: audit writes acquire the global chain lock. At this point
	// there are no further configuration rows to lock.
	for _, a := range writer.configAudits {
		if err := writer.writeAudit(ctx, a.actor, a.action, a.target, a.detail); err != nil {
			return configLockError(err)
		}
	}
	return configLockError(tx.Commit(ctx))
}

func (s *Store) requireConfigTransaction() error {
	if _, ok := s.pool.(pgx.Tx); !ok {
		return errors.New("configuration lock requires a transaction")
	}
	return nil
}

func configLockError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "55P03" || pgErr.Code == "40P01" || pgErr.Code == "40001") {
		return fmt.Errorf("%w: configuration is being changed", ErrConflict)
	}
	return err
}

// LockConfigTarget serializes edits and freezes the links consulted by the
// review hash and scope checks. New check/task links take the same item lock
// in attach; new policy assignments and exclusions are fenced by their parent
// foreign keys. Existing links are locked against edits and cascading deletes.
// Read the target only after these locks are held.
func (s *Store) LockConfigTarget(ctx context.Context, kind, id string, scoped bool) error {
	if err := s.requireConfigTransaction(); err != nil {
		return err
	}
	var table string
	var children []string
	var agentLinks, itemKey string
	switch kind {
	case models.EditScript:
		table = "scripts"
	case models.EditCheck:
		table, agentLinks, itemKey = "checks", "check_attachments", "check_id"
		children = []string{"SELECT 1 FROM check_attachments WHERE check_id=$1 FOR UPDATE"}
	case models.EditTask:
		table, agentLinks, itemKey = "tasks", "task_attachments", "task_id"
		children = []string{"SELECT 1 FROM task_attachments WHERE task_id=$1 FOR UPDATE"}
	case models.EditPolicy:
		table = "policies"
		children = []string{
			"SELECT 1 FROM policy_assignments WHERE policy_id=$1 FOR UPDATE",
			"SELECT 1 FROM policy_exclusions WHERE policy_id=$1 FOR UPDATE",
		}
	case models.EditPatchPolicy:
		table = "patch_policies"
		children = []string{
			"SELECT 1 FROM patch_policy_assignments WHERE policy_id=$1 FOR UPDATE",
			"SELECT 1 FROM patch_policy_exclusions WHERE policy_id=$1 FOR UPDATE",
		}
	default:
		return fmt.Errorf("unknown configuration kind %q", kind)
	}
	rowLock := " FOR NO KEY UPDATE"
	if kind == models.EditPolicy || kind == models.EditPatchPolicy {
		rowLock = " FOR UPDATE"
	}
	var locked string
	// Check results and jobs can take foreign-key key-share locks alongside a
	// non-key edit. Otherwise a result holding an execution row could deadlock
	// with an edit that must cancel that execution.
	if err := s.pool.QueryRow(ctx, "SELECT id FROM "+table+" WHERE id=$1"+rowLock, id).Scan(&locked); err != nil {
		return configLockError(err)
	}
	if scoped && agentLinks != "" {
		// A shared lock blocks moves without conflicting with a concurrent
		// edit or attachment on another item that uses the same device.
		if _, err := s.pool.Exec(ctx, "SELECT 1 FROM agents WHERE id IN (SELECT agent_id FROM "+agentLinks+
			" WHERE "+itemKey+"=$1) ORDER BY id FOR SHARE", id); err != nil {
			return err
		}
	}
	for _, query := range children {
		if _, err := s.pool.Exec(ctx, query, id); err != nil {
			return err
		}
	}
	return nil
}

// LockConfigAgent protects authorization of a new direct attachment against a
// simultaneous move. The caller checks scope after acquiring the lock.
func (s *Store) LockConfigAgent(ctx context.Context, id string) error {
	if err := s.requireConfigTransaction(); err != nil {
		return err
	}
	var locked string
	return configLockError(s.pool.QueryRow(ctx, "SELECT id FROM agents WHERE id=$1 FOR SHARE", id).Scan(&locked))
}
