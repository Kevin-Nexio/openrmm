-- Checks and scheduled tasks are attached to any number of policies and
-- devices, instead of belonging to exactly one of them. A device gets a check or
-- task when one of its attachments reaches it: the device itself, or a
-- switched-on policy whose assignment reaches the device and does not exclude
-- it. Every existing check and task keeps its reach: its policy or device
-- becomes its attachment, dated when it was made.
CREATE TABLE IF NOT EXISTS check_attachments (
    check_id  UUID NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    agent_id  UUID REFERENCES agents(id) ON DELETE CASCADE,
    added_by  TEXT NOT NULL DEFAULT '',
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT check_attachments_one_target CHECK ((policy_id IS NULL) <> (agent_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_check_attachments_policy ON check_attachments (check_id, policy_id) WHERE policy_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_check_attachments_agent ON check_attachments (check_id, agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_check_attachments_policy ON check_attachments (policy_id) WHERE policy_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_check_attachments_agent ON check_attachments (agent_id) WHERE agent_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS task_attachments (
    task_id   UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    agent_id  UUID REFERENCES agents(id) ON DELETE CASCADE,
    added_by  TEXT NOT NULL DEFAULT '',
    added_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT task_attachments_one_target CHECK ((policy_id IS NULL) <> (agent_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_task_attachments_policy ON task_attachments (task_id, policy_id) WHERE policy_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_task_attachments_agent ON task_attachments (task_id, agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_task_attachments_policy ON task_attachments (policy_id) WHERE policy_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_task_attachments_agent ON task_attachments (agent_id) WHERE agent_id IS NOT NULL;

INSERT INTO check_attachments (check_id, policy_id, added_at)
     SELECT id, policy_id, created_at FROM checks WHERE policy_id IS NOT NULL
ON CONFLICT DO NOTHING;
INSERT INTO check_attachments (check_id, agent_id, added_at)
     SELECT id, agent_id, created_at FROM checks WHERE agent_id IS NOT NULL
ON CONFLICT DO NOTHING;
INSERT INTO task_attachments (task_id, policy_id, added_at)
     SELECT id, policy_id, created_at FROM tasks WHERE policy_id IS NOT NULL
ON CONFLICT DO NOTHING;
INSERT INTO task_attachments (task_id, agent_id, added_at)
     SELECT id, agent_id, created_at FROM tasks WHERE agent_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- A check-scoped silence or maintenance window records what it covered when it
-- was made, so attaching the check somewhere later never widens it:
--   covers_policy_reach: the check had a policy attachment, which only an
--     unrestricted principal could silence; the silence follows the check
--     everywhere it reaches, as a policy check's silence always did;
--   alert_suppression_agents: each device the check was attached to directly,
--     with its monitoring scope then; the silence holds there only while the
--     device keeps that scope, as a device check's silence always did.
ALTER TABLE alert_suppressions ADD COLUMN IF NOT EXISTS covers_policy_reach BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS alert_suppression_agents (
    suppression_id         UUID NOT NULL REFERENCES alert_suppressions(id) ON DELETE CASCADE,
    agent_id               UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    monitoring_scope_since TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (suppression_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_suppression_agents_agent ON alert_suppression_agents (agent_id);

UPDATE alert_suppressions s SET covers_policy_reach = true
  FROM checks c
 WHERE s.scope_type = 'check' AND c.id = s.scope_id AND c.policy_id IS NOT NULL;
INSERT INTO alert_suppression_agents (suppression_id, agent_id, monitoring_scope_since)
     SELECT s.id, c.agent_id, s.agent_monitoring_scope_since
       FROM alert_suppressions s
       JOIN checks c ON c.id = s.scope_id
      WHERE s.scope_type = 'check' AND c.agent_id IS NOT NULL AND s.agent_monitoring_scope_since IS NOT NULL
ON CONFLICT DO NOTHING;

ALTER TABLE checks DROP COLUMN IF EXISTS agent_id, DROP COLUMN IF EXISTS policy_id;
ALTER TABLE tasks DROP COLUMN IF EXISTS agent_id, DROP COLUMN IF EXISTS policy_id;
