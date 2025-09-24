BEGIN;

CREATE TABLE IF NOT EXISTS user_device (
    opaque_id TEXT PRIMARY KEY,
    pubkey BYTEA NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS session (
    opaque_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES user_device(opaque_id) ON DELETE CASCADE,
    tls_fingerprint TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    ttl_seconds BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS session_device_idx ON session(device_id);

CREATE TABLE IF NOT EXISTS device_key_event (
    event_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES user_device(opaque_id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_group (
    group_id TEXT PRIMARY KEY,
    owner_device TEXT NOT NULL REFERENCES user_device(opaque_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS group_member (
    group_id TEXT NOT NULL REFERENCES chat_group(group_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES user_device(opaque_id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    joined_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(group_id, device_id)
);

CREATE TABLE IF NOT EXISTS federation_peer (
    domain TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    status TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(key, scope)
);

CREATE TABLE IF NOT EXISTS relay_queue (
    envelope_id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL,
    payload BYTEA NOT NULL,
    deliver_after TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS relay_queue_channel_idx ON relay_queue(channel_id, deliver_after);

CREATE TABLE IF NOT EXISTS inbox_offset (
    entity_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    last_envelope_id TEXT,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(entity_id, channel_id)
);

COMMIT;
