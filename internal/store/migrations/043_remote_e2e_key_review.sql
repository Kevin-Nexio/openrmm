-- A device presenting a different E2E identity key than the pinned one, or none,
-- stays online; only its native remote sessions pause until an administrator
-- reviews the change (approve the presented key, or keep the pinned one).
--
-- device_key_issue: '' | changed | missing | outdated | duplicate.
-- pending_device_public_key: the last key presented that differs from the pinned one.
-- device_key_changed_at/_by: the last administrator-approved key change, which
-- browsers that remembered the previous key show before they accept the new one.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS device_key_issue TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS pending_device_public_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS device_key_issue_since TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS device_key_issue_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS device_key_issue_ip TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS device_key_issue_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS device_key_issue_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS device_key_changed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS device_key_changed_by TEXT NOT NULL DEFAULT '';
