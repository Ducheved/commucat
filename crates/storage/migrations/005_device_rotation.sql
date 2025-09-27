BEGIN;

CREATE TABLE IF NOT EXISTS device_rotation_audit (
    rotation_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES user_device(opaque_id) ON DELETE CASCADE,
    old_public_key BYTEA NOT NULL,
    new_public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    nonce BYTEA,
    proof_expires_at TIMESTAMPTZ NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL,
    UNIQUE (device_id, new_public_key)
);

CREATE INDEX IF NOT EXISTS device_rotation_device_idx
    ON device_rotation_audit(device_id, applied_at DESC);

COMMIT;
