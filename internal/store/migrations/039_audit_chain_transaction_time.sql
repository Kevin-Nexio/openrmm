-- Give human audit rows with the default timestamp a strict chronological
-- order under the chain lock. This also permits several human audit entries
-- to commit atomically with a configuration edit. Existing rows and explicit
-- timestamps are preserved. The present trigger uses the replacement function.
CREATE OR REPLACE FUNCTION audit_chain_link() RETURNS TRIGGER AS $$
DECLARE
    previous TEXT;
    previous_at TIMESTAMPTZ;
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

    SELECT entry_hash, created_at INTO previous, previous_at
    FROM audit_log
    WHERE entry_hash <> ''
    ORDER BY created_at DESC, id DESC
    LIMIT 1;

    -- The default now() is the transaction's start time. Multiple records
    -- in one transaction share it, and a transaction starting earlier may
    -- acquire the chain lock later. Order default timestamps under that lock
    -- so the hash predecessor and chronological verifier agree.
    IF NEW.created_at = transaction_timestamp() THEN
        NEW.created_at := GREATEST(clock_timestamp(), previous_at + interval '1 microsecond');
    END IF;

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
