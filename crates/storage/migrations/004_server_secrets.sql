CREATE TABLE IF NOT EXISTS server_secret (
    name TEXT NOT NULL,
    version BIGINT NOT NULL,
    secret BYTEA NOT NULL,
    public BYTEA,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_after TIMESTAMPTZ NOT NULL,
    rotates_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (name, version)
);

CREATE INDEX IF NOT EXISTS idx_server_secret_name_desc
    ON server_secret (name, version DESC);

CREATE INDEX IF NOT EXISTS idx_server_secret_active
    ON server_secret (name, valid_after, expires_at);
