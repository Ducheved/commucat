BEGIN;

CREATE TABLE IF NOT EXISTS device_pairing (
    pair_code TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES app_user(user_id) ON DELETE CASCADE,
    issuer_device_id TEXT NOT NULL REFERENCES user_device(opaque_id) ON DELETE CASCADE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    redeemed_at TIMESTAMPTZ,
    redeemed_device_id TEXT REFERENCES user_device(opaque_id) ON DELETE SET NULL,
    public_key BYTEA,
    attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS device_pairing_user_idx ON device_pairing(user_id);
CREATE INDEX IF NOT EXISTS device_pairing_expiry_idx ON device_pairing(expires_at);

COMMIT;
