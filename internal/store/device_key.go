package store

import (
	"context"
	"errors"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/p1ngu/rmm/internal/models"
)

// A device's E2E identity key is pinned on first contact. A later registration
// that presents another key, or none, is not refused: the agent token already
// authenticates the control channel, and refusing it would take the device
// offline for jobs, monitoring and updates. The issue is recorded instead, and
// native remote sessions pause until an administrator reviews it. Nothing here
// ever replaces the pinned key on the agent's word.

var (
	// ErrDeviceKeyNotPending: the key to approve is not the one the device
	// presented last (it changed since the reviewer looked), or there is no
	// changed key to approve.
	ErrDeviceKeyNotPending = errors.New("the presented device key changed or is no longer pending; review it again")
	// ErrDeviceKeyNoIssue: there is no device key issue to dismiss.
	ErrDeviceKeyNoIssue = errors.New("this device has no encryption key issue")
)

// DeviceKeyPresentation is what one authenticated registration presented.
type DeviceKeyPresentation struct {
	Key string
	// Unavailable: an agent that supports encryption could not read its key.
	Unavailable bool
}

// deviceKeyState is the stored key and issue of one agent.
type deviceKeyState struct {
	Pinned  string
	Issue   string
	Pending string
}

// Device key events a registration can cause.
const (
	DeviceKeyEventNone      = ""
	DeviceKeyEventPinned    = "pinned"     // first key recorded
	DeviceKeyEventIssue     = "issue"      // a new issue, or a worse one: audit and alert
	DeviceKeyEventIssueSeen = "issue_seen" // the same issue again: only last seen and count move
	DeviceKeyEventResolved  = "resolved"   // the pinned key came back after a missing or outdated report
)

// DeviceKeyOutcome reports what a registration did to a device's key state.
type DeviceKeyOutcome struct {
	Event     string
	Issue     string // the issue after this registration
	PrevIssue string
	Pinned    string // the pinned key after this registration
	Presented string
}

// nextDeviceKeyState is the whole decision, kept free of I/O so every case is
// tested on its own. It never changes the pinned key once there is one.
func nextDeviceKeyState(cur deviceKeyState, p DeviceKeyPresentation) (deviceKeyState, string) {
	next := cur
	if cur.Pinned == "" {
		if p.Key == "" {
			return cur, DeviceKeyEventNone // an agent without encryption: legacy relay, as before
		}
		return deviceKeyState{Pinned: p.Key}, DeviceKeyEventPinned
	}
	conflict := cur.Issue == models.DeviceKeyChanged || cur.Issue == models.DeviceKeyDuplicate
	switch {
	case p.Key == cur.Pinned:
		switch cur.Issue {
		case "":
			return cur, DeviceKeyEventNone
		case models.DeviceKeyMissing, models.DeviceKeyOutdated:
			return deviceKeyState{Pinned: cur.Pinned}, DeviceKeyEventResolved
		case models.DeviceKeyChanged:
			// The pinned key is back while another one was seen: two machines
			// are using this identity.
			next.Issue = models.DeviceKeyDuplicate
			return next, DeviceKeyEventIssue
		default:
			return cur, DeviceKeyEventIssueSeen
		}
	case p.Key == "":
		if conflict {
			if cur.Issue == models.DeviceKeyDuplicate {
				return cur, DeviceKeyEventIssueSeen
			}
			next.Issue = models.DeviceKeyDuplicate
			return next, DeviceKeyEventIssue
		}
		kind := models.DeviceKeyOutdated
		if p.Unavailable {
			kind = models.DeviceKeyMissing
		}
		if cur.Issue == kind {
			return cur, DeviceKeyEventIssueSeen
		}
		return deviceKeyState{Pinned: cur.Pinned, Issue: kind}, DeviceKeyEventIssue
	default: // a different, non-empty key
		switch cur.Issue {
		case models.DeviceKeyChanged:
			if cur.Pending == p.Key {
				return cur, DeviceKeyEventIssueSeen
			}
			// A third key: more than one machine, each with its own key.
			next.Issue, next.Pending = models.DeviceKeyDuplicate, p.Key
			return next, DeviceKeyEventIssue
		case models.DeviceKeyDuplicate:
			next.Pending = p.Key
			return next, DeviceKeyEventIssueSeen
		default:
			return deviceKeyState{Pinned: cur.Pinned, Issue: models.DeviceKeyChanged, Pending: p.Key}, DeviceKeyEventIssue
		}
	}
}

const clearDeviceKeyIssue = `device_key_issue='', pending_device_public_key='', device_key_issue_since=NULL,
	device_key_issue_seen_at=NULL, device_key_issue_ip='', device_key_issue_version='', device_key_issue_count=0`

// CheckAgentDeviceKey applies one authenticated registration's key to the
// agent's state, in a transaction so concurrent registrations serialize.
func (s *Store) CheckAgentDeviceKey(ctx context.Context, id string, p DeviceKeyPresentation, ip, version string) (DeviceKeyOutcome, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DeviceKeyOutcome{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cur deviceKeyState
	err = tx.QueryRow(ctx, `SELECT device_public_key, device_key_issue, pending_device_public_key
		FROM agents WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`, id).Scan(&cur.Pinned, &cur.Issue, &cur.Pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceKeyOutcome{}, ErrNotFound
	}
	if err != nil {
		return DeviceKeyOutcome{}, err
	}
	next, event := nextDeviceKeyState(cur, p)
	out := DeviceKeyOutcome{Event: event, Issue: next.Issue, PrevIssue: cur.Issue, Pinned: next.Pinned, Presented: p.Key}
	switch event {
	case DeviceKeyEventNone:
		return out, nil
	case DeviceKeyEventPinned:
		_, err = tx.Exec(ctx, `UPDATE agents SET device_public_key=$2, `+clearDeviceKeyIssue+` WHERE id=$1`, id, next.Pinned)
	case DeviceKeyEventResolved:
		_, err = tx.Exec(ctx, `UPDATE agents SET `+clearDeviceKeyIssue+` WHERE id=$1`, id)
	case DeviceKeyEventIssue, DeviceKeyEventIssueSeen:
		_, err = tx.Exec(ctx, `UPDATE agents SET device_key_issue=$2, pending_device_public_key=$3,
			device_key_issue_since=CASE WHEN device_key_issue='' OR device_key_issue_since IS NULL THEN now() ELSE device_key_issue_since END,
			device_key_issue_seen_at=now(), device_key_issue_ip=$4, device_key_issue_version=$5,
			device_key_issue_count=CASE WHEN device_key_issue='' THEN 1 ELSE device_key_issue_count+1 END
			WHERE id=$1`, id, next.Issue, next.Pending, clipText(ip, 64), clipText(version, 32))
	}
	if err != nil {
		return DeviceKeyOutcome{}, err
	}
	return out, tx.Commit(ctx)
}

// MarkAgentDeviceDuplicate records that more than one machine is using this
// device identity, seen from its connections rather than its key. raised is
// true when this is new, so the caller audits and alerts once.
func (s *Store) MarkAgentDeviceDuplicate(ctx context.Context, id, ip, version string) (raised bool, err error) {
	tag, err := s.pool.Exec(ctx, `UPDATE agents SET device_key_issue=$2,
		device_key_issue_since=CASE WHEN device_key_issue='' OR device_key_issue_since IS NULL THEN now() ELSE device_key_issue_since END,
		device_key_issue_seen_at=now(), device_key_issue_ip=$3, device_key_issue_version=$4,
		device_key_issue_count=CASE WHEN device_key_issue='' THEN 1 ELSE device_key_issue_count+1 END
		WHERE id=$1 AND revoked_at IS NULL AND device_key_issue<>$2`, id, models.DeviceKeyDuplicate, clipText(ip, 64), clipText(version, 32))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ApproveAgentDeviceKey pins exactly the key the device presented last, after
// an administrator compared its fingerprint on the device. It returns the key
// that was pinned before.
func (s *Store) ApproveAgentDeviceKey(ctx context.Context, id, pendingKey, actor string) (previous string, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cur deviceKeyState
	err = tx.QueryRow(ctx, `SELECT device_public_key, device_key_issue, pending_device_public_key
		FROM agents WHERE id=$1 AND revoked_at IS NULL FOR UPDATE`, id).Scan(&cur.Pinned, &cur.Issue, &cur.Pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if cur.Issue != models.DeviceKeyChanged || pendingKey == "" || cur.Pending != pendingKey {
		return "", ErrDeviceKeyNotPending
	}
	if _, err := tx.Exec(ctx, `UPDATE agents SET device_public_key=$2, `+clearDeviceKeyIssue+`,
		device_key_changed_at=now(), device_key_changed_by=$3 WHERE id=$1`, id, pendingKey, clipText(actor, 200)); err != nil {
		return "", err
	}
	return cur.Pinned, tx.Commit(ctx)
}

// DismissAgentDeviceKeyIssue keeps the pinned key and clears the issue. If the
// cause persists, the device's next registration raises it again.
func (s *Store) DismissAgentDeviceKeyIssue(ctx context.Context, id string) (issue, pinned, pending string, err error) {
	err = s.pool.QueryRow(ctx, `UPDATE agents a SET `+clearDeviceKeyIssue+`
		FROM (SELECT id, device_key_issue, pending_device_public_key FROM agents WHERE id=$1 AND revoked_at IS NULL FOR UPDATE) prev
		WHERE a.id=prev.id AND prev.device_key_issue<>''
		RETURNING prev.device_key_issue, a.device_public_key, prev.pending_device_public_key`, id).Scan(&issue, &pinned, &pending)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, getErr := s.GetAgent(ctx, id); errors.Is(getErr, ErrNotFound) {
			return "", "", "", ErrNotFound
		}
		return "", "", "", ErrDeviceKeyNoIssue
	}
	return issue, pinned, pending, err
}

// clipText bounds a reported value at n bytes without splitting a character.
func clipText(v string, n int) string {
	if len(v) <= n {
		return v
	}
	for n > 0 && !utf8.RuneStart(v[n]) {
		n--
	}
	return v[:n]
}
