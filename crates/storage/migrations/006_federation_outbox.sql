CREATE TABLE IF NOT EXISTS federation_outbox (
    outbox_id TEXT PRIMARY KEY,
    destination_domain TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    payload JSONB NOT NULL,
    public_key BYTEA NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_federation_outbox_next_attempt
    ON federation_outbox (next_attempt_at);
