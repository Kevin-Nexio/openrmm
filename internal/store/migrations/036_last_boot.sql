-- When a device last booted (Devices ▸ Last boot): the time the server stored
-- an inventory snapshot minus the uptime the agent reported in it. Set when an
-- inventory arrives; NULL until the first one. Filled here from the snapshots
-- already stored, skipping any uptime that is not a plausible number.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_boot_at TIMESTAMPTZ;
UPDATE agents a
   SET last_boot_at = i.collected_at - make_interval(secs => (i.data->>'uptime_sec')::double precision)
  FROM inventory i
 WHERE i.agent_id = a.id
   AND a.last_boot_at IS NULL
   AND CASE WHEN jsonb_typeof(i.data->'uptime_sec') = 'number'
            THEN (i.data->>'uptime_sec')::numeric BETWEEN 0 AND 631152000
            ELSE false END;
