-- Older incidents have no proven monitoring scope revision.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS agent_monitoring_scope_since TIMESTAMPTZ;

-- One current bucket per instance, independent of the notification outbox.
CREATE TABLE IF NOT EXISTS shared_alert_test_budget (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    hour_start TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts > 0)
);
