BEGIN;

CREATE TABLE IF NOT EXISTS device_pq_keys (
    device_id TEXT PRIMARY KEY REFERENCES user_device(opaque_id) ON DELETE CASCADE,
    kem_public BYTEA NOT NULL,
    signature_public BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
