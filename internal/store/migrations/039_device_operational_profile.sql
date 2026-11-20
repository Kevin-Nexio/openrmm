CREATE TABLE device_operations_profiles (
    agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL DEFAULT '' CHECK (char_length(purpose) <= 2000),
    applications TEXT NOT NULL DEFAULT '' CHECK (char_length(applications) <= 8000),
    dependencies TEXT NOT NULL DEFAULT '' CHECK (char_length(dependencies) <= 8000),
    criticality TEXT NOT NULL DEFAULT 'unknown' CHECK (criticality IN ('unknown','low','normal','high','critical')),
    maintenance_window TEXT NOT NULL DEFAULT '' CHECK (char_length(maintenance_window) <= 1000),
    maintenance_timezone TEXT NOT NULL DEFAULT '' CHECK (char_length(maintenance_timezone) <= 100),
    backup_notes TEXT NOT NULL DEFAULT '' CHECK (char_length(backup_notes) <= 8000),
    backup_verified_on DATE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION audit_chain_link() RETURNS TRIGGER AS $$
DECLARE
    previous TEXT;
    previous_created_at TIMESTAMPTZ;
BEGIN
    IF audit_is_machine_written(NEW.action) THEN
        NEW.prev_hash  := '';
        NEW.entry_hash := '';
        RETURN NEW;
    END IF;

    -- Serialises chained inserts for the length of the transaction. Two
    -- concurrent inserts would otherwise both read the same predecessor under
    -- READ COMMITTED and fork the chain into two branches with one parent.
    --
    -- Affordable because this covers human actions only: an operator approving
    -- a job, changing a scope, editing settings. The machine entries — the ones
    -- that arrive thousands per day — skip this path entirely.
    PERFORM pg_advisory_xact_lock(hashtext('audit_log_chain'));

    SELECT entry_hash, created_at INTO previous, previous_created_at
    FROM audit_log
    WHERE entry_hash <> ''
    ORDER BY created_at DESC, id DESC
    LIMIT 1;

    -- Transaction-start timestamps can precede a row committed while we waited.
    -- Keep the existing verifier ordering strictly aligned with the chain.
    NEW.created_at := GREATEST(NEW.created_at, previous_created_at + interval '1 microsecond');
    NEW.prev_hash := COALESCE(previous, '');
    -- Every field a reader would rely on goes into the digest. Leaving one out
    -- would let it be edited without breaking the chain, which is worse than no
    -- chain at all: it would carry an assurance it does not provide.
    NEW.entry_hash := encode(sha256(convert_to(
        NEW.prev_hash || '|' || NEW.id::text || '|' || NEW.actor || '|' ||
        NEW.action || '|' || NEW.target || '|' || NEW.detail::text || '|' ||
        to_char(NEW.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
        'UTF8')), 'hex');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

