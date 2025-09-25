BEGIN;

CREATE TABLE IF NOT EXISTS user_blob (
    user_id TEXT NOT NULL REFERENCES app_user(user_id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    payload TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, key)
);

COMMIT;
