-- End-to-end encryption for native remote sessions and guest chat.
--
-- agents.device_public_key pins the device's durable P-256 identity key on
-- first contact (ratchet: once recorded, sessions to this device require E2E).
-- remote_sessions.e2e records whether a brokered relay session uses E2E.
-- remote_shares stores the guest's ephemeral ECDH/ECDSA public keys and the
-- technician-sealed chat room key so the server never sees chat plaintext.

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS device_public_key TEXT NOT NULL DEFAULT '';

ALTER TABLE remote_sessions
    ADD COLUMN IF NOT EXISTS e2e BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE remote_shares
    ADD COLUMN IF NOT EXISTS guest_public_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS guest_sign_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS wrapped_chat_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS chat_key_id TEXT NOT NULL DEFAULT '';
