-- A timeout must count as one failure, not two, and a check can ignore timeouts.
--
-- The server deadline used to be exactly timeout_sec. The agent starts its own
-- timer only when the order arrives, so the server often recorded the timeout
-- and then counted the agent's late result for the same run again.
-- timeout_effect remembers what this run already did to the failure counter:
-- '' not counted (including an offline run that became unknown), 'counted',
-- or 'ignored'. A late result replaces a counted timeout instead of adding one.

ALTER TABLE check_executions
    ADD COLUMN IF NOT EXISTS timeout_effect TEXT NOT NULL DEFAULT '';
ALTER TABLE check_executions
    DROP CONSTRAINT IF EXISTS check_executions_timeout_effect_valid;
ALTER TABLE check_executions
    ADD CONSTRAINT check_executions_timeout_effect_valid
    CHECK (timeout_effect IN ('', 'counted', 'ignored'));

ALTER TABLE checks
    ADD COLUMN IF NOT EXISTS timeout_policy TEXT NOT NULL DEFAULT 'count';
ALTER TABLE checks
    DROP CONSTRAINT IF EXISTS checks_timeout_policy_valid;
ALTER TABLE checks
    ADD CONSTRAINT checks_timeout_policy_valid
    CHECK (timeout_policy IN ('count', 'ignore'));
