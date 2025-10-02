-- Migration 008: Federated user identifiers
-- Adds domain support and remote user caching

BEGIN;

-- Add domain field to users
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS domain TEXT NOT NULL DEFAULT 'local';

-- Create index for domain lookups
CREATE INDEX IF NOT EXISTS idx_app_user_domain ON app_user(domain);

-- Create unique constraint on handle@domain
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_user_handle_domain ON app_user(handle, domain);

-- Table for caching remote user profiles
CREATE TABLE IF NOT EXISTS remote_user_cache (
    user_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    handle TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    profile_data JSONB NOT NULL,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_remote_user_cache_domain ON remote_user_cache(domain);
CREATE INDEX IF NOT EXISTS idx_remote_user_cache_expires ON remote_user_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_remote_user_cache_handle_domain ON remote_user_cache(handle, domain);

-- Table for tracking federation peer connections
CREATE TABLE IF NOT EXISTS federation_peer_status (
    domain TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    public_key BYTEA NOT NULL,
    last_seen_at TIMESTAMPTZ,
    last_error TEXT,
    error_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'unknown', -- unknown, online, offline, unreachable
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_federation_peer_status_updated ON federation_peer_status(updated_at);

-- Table for federated friend requests (cross-server)
CREATE TABLE IF NOT EXISTS federated_friend_requests (
    request_id TEXT PRIMARY KEY,
    from_user_id TEXT NOT NULL, -- full federated ID: user@domain
    to_user_id TEXT NOT NULL,   -- full federated ID: user@domain
    from_domain TEXT NOT NULL,
    to_domain TEXT NOT NULL,
    message TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, accepted, rejected, cancelled
    federation_event_id TEXT, -- reference to federation event
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_federated_friend_requests_from ON federated_friend_requests(from_user_id);
CREATE INDEX IF NOT EXISTS idx_federated_friend_requests_to ON federated_friend_requests(to_user_id);
CREATE INDEX IF NOT EXISTS idx_federated_friend_requests_status ON federated_friend_requests(status);
CREATE INDEX IF NOT EXISTS idx_federated_friend_requests_from_domain ON federated_friend_requests(from_domain);
CREATE INDEX IF NOT EXISTS idx_federated_friend_requests_to_domain ON federated_friend_requests(to_domain);

COMMIT;
