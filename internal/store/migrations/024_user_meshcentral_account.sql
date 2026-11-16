-- The MeshCentral account a user's remote sessions sign in as when the server
-- mints MeshCentral login tokens. An administrator sets it; empty means none,
-- and then only a user with access to every device may use the shared
-- account (remote.meshcentral_user). Ordinary MeshCentral usernames are
-- normalized to lowercase; OIDC identifiers preserve their original case.
ALTER TABLE users ADD COLUMN IF NOT EXISTS meshcentral_user TEXT NOT NULL DEFAULT '';
