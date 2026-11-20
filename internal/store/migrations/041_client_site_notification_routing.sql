CREATE TABLE notification_routes (
    id UUID PRIMARY KEY,
    client_id UUID UNIQUE REFERENCES clients(id) ON DELETE CASCADE,
    site_id UUID UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('inherit','selected')),
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by TEXT NOT NULL,
    CHECK ((client_id IS NOT NULL)::int + (site_id IS NOT NULL)::int = 1)
);
CREATE TABLE notification_route_users (
    route_id UUID NOT NULL REFERENCES notification_routes(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (route_id,user_id)
);
ALTER TABLE alerts ADD COLUMN notification_route_snapshot JSONB NOT NULL DEFAULT '{"mode":"automatic"}'
    CHECK (jsonb_typeof(notification_route_snapshot) = 'object');

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

