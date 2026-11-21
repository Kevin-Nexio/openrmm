-- Edits the AI assistant proposes to existing library scripts, checks, tasks,
-- policies and patch policies. A proposal changes nothing: a person reviews it
-- and applies it, which makes the same edit through the same checks as an edit
-- by hand. base_hash is the object as the proposal saw it; if the object has
-- changed since, the proposal is stale and cannot be applied. One proposal per
-- object is open at a time: a newer one supersedes it.
CREATE TABLE IF NOT EXISTS edit_proposals (
    id          UUID PRIMARY KEY,
    kind        TEXT NOT NULL CONSTRAINT edit_proposals_kind_valid
                    CHECK (kind IN ('script', 'check', 'task', 'policy', 'patch_policy')),
    target_id   UUID NOT NULL,
    base_hash   TEXT NOT NULL,
    changes     JSONB NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    proposed_by TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending' CONSTRAINT edit_proposals_status_valid
                    CHECK (status IN ('pending', 'applied', 'rejected', 'stale', 'superseded', 'failed')),
    decided_by  TEXT NOT NULL DEFAULT '',
    -- Set while someone applies it; a claim older than 15 minutes (a crash
    -- mid-apply) no longer blocks anyone.
    claimed_at  TIMESTAMPTZ,
    outcome     TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_edit_proposals_open ON edit_proposals (kind, target_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_edit_proposals_status ON edit_proposals (status, created_at DESC);
