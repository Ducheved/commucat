# CommuCat Architecture Overview (2025-10)

This document captures the current layout of the CommuCat server, supporting crates, and major data flows. It reflects the code in this repository as of October 2025.

> **Status:** work-in-progress. The system is pre-alpha; many subsystems are still stubs. Use this document as a map, not a guarantee of behaviour.

---

## 1. High-level goals

- Provide a secure routing core for CCP‑1 chats: Noise-authenticated device sessions, durable message relaying, and simple federation hooks.
- Keep state in standards-compliant components (PostgreSQL, Redis, JSONL ledger) to simplify operations and auditability.
- Enable future experiments: post-quantum handshakes, stealth/multipath transports, richer media pipeline, and cross-domain federation.

Several planned capabilities (stealth transports, PQ, full federation) are still placeholders—see the [Roadmap](ROADMAP.md).

---

## 2. Component map

```
┌──────────┐    HTTPS (TLS 1.3 / h2)    ┌────────────┐
│  Client  │ ─────────────────────────▶ │  Pingora    │
│ (Noise)  │ ◀────────────────────────┐ │  Listener   │
└──────────┘                          │ └────────────┘
                                       │        │
                                       ▼        ▼
                              ┌────────────────────────┐
                              │   CommuCatApp (server) │
                              │  crates/server/src/... │
                              └────────────────────────┘
                                 │      │        │
                                 │      │        │
          ┌──────────────────────┘      │        └───────────────────┐
          ▼                             ▼                            ▼
┌────────────────┐          ┌─────────────────────┐        ┌────────────────┐
│ PostgreSQL     │          │ Redis               │        │ Ledger Adapter │
│ devices, users │◀───────▶│ presence, cache     │ ─────▶ │ file/debug/null│
│ relay_queue    │          │ pairing TTL         │        │ JSONL          │
└────────────────┘          └─────────────────────┘        └────────────────┘
```

Supporting crates:

- `commucat_proto`: frame codec and CCP-1 control envelopes.
- `commucat_crypto`: Noise builders, device certificates, ZK proofs.
- `commucat_storage`: type-safe DAO for PostgreSQL/Redis, migrations, pairing tokens.
- `commucat_ledger`: JSONL appenders (`File`, `Debug`, `Null`).
- `commucat_cli`: operational tooling (migrate, register-user, rotate-keys, diagnostics).
- `commucat_media` / `commucat_media-types`: codec abstractions (Opus/VP8 implemented; AV1/H.264 planned).
- `commucat_federation`: signed event helpers (dispatcher is incomplete).

---

## 3. Request lifecycle

### 3.1 `/connect` bootstrap

1. **TLS / HTTP/2 accept:** Pingora accepts the stream, hands it to `CommuCatApp::accept`.
2. **Rate limiting:** `/connect` requests are gated by `RateLimiter` (tokens per IP, defined in `commucat.toml`).
3. **Noise handshake:**
   - `FrameType::Hello` parsed in `process_handshake_frame`.
   - `SecretManager::active_noise_keys` provides candidate static keys.
   - Device/user records fetched via `Storage::load_device` / `load_user`.
   - Certificates verified against `device_ca_public`; if absent, new certificate issued.
   - Pairing limits enforced via `ensure_pairing_limit` when auto-approval disabled.
   - On failure: `emit_handshake_failure` logs and writes ledger entry.
4. **Session establishment:**
   - Noise transport stored in `HandshakeContext::transport` (Arc<Mutex<NoiseTransport>>).
   - Presence published (`Storage::publish_presence`).
   - `SessionRecord` persisted (`Storage::store_session`).
   - Connection registered in `AppState::connections` (per-device channel map).
   - Pending envelopes drained from `relay_queue` (up to 128, can be tuned).

### 3.2 REST API

- `GET /api/server-info`: exposes current Noise catalog, session TTLs, pairing settings.
- `POST /api/pairing`: authenticated session requests a pairing code (stored in Postgres, mirrored to Redis for TTL enforcement).
- `POST /api/pairing/claim`: unauthenticated device redeems code, obtains keys/certificate.
- `GET /healthz`, `/readyz`, `/metrics`: operational endpoints (metrics require admin token if configured).
- Upload APIs (`/uploads/*`) stream files to disk if enabled by config.

### 3.3 Call/media flow (experimental)

Media endpoints live under `app::media`. They currently support:
- Opus audio and VP8 video conversion using libopus/libvpx.
- In-memory transcoding hooks for future SFU integration.
- Recording of call events into the ledger via `emit_call_event`.

The SFU/relay portion is skeletal; negotiation and bitrate adaptation remain TODOs.

---

## 4. State management

### PostgreSQL schema highlights

- `users`, `devices`, `device_certificates`
- `pairing_tokens`, `device_rotations`
- `relay_queue`, `inbox_offsets`
- `sessions`, `call_sessions`, `call_media_tracks`
- Migration files live in `crates/storage/migrations/*.sql`. The CLI `commucat-cli migrate` applies them in order.

### Redis usage

- Presence snapshots keyed by `presence:<device_id>` with TTL = `presence_ttl_seconds`.
- Rendezvous / pairing codes cached to enforce expiration.
- Rate-limiter buckets (if Redis is available; otherwise an in-memory limiter is used with reduced guarantees).

### Ledger

- Configured via `[ledger]` in `commucat.toml`.
- `mode = "file"` appends newline-delimited JSON objects; ensure parent directory permissions.
- JSON structure documented in [PROTOCOL.md](PROTOCOL.md#6-ledger-mapping).

---

## 5. Security notes

- **TLS termination** is mandatory. Self-signed certificates are fine for local testing; production deployments should use ACME or a trusted CA.
- **Noise handshake** currently verifies a ZK proof binding `device_id` and the server domain. There is no server-to-client pairing requirement beyond certificate checks.
- **Auto-approval** (`auto_approve_devices`) should be disabled in production; rely on pairing codes and manual review.
- **Admin token** (optional) guards `/metrics` and `/api/security-stats`. Rotate via `[security.rotation]` or CLI helpers.
- **Stealth transports**, **PQ keys**, and **federation ACLs** are not yet implemented—treat advertised options as informational only.

---

## 6. Observability & operations

- Structured logs via `tracing_subscriber::fmt().json()`. Configure verbosity with `RUST_LOG`.
- Health probes: `/healthz` (liveness) and `/readyz` (storage connectivity).
- Metrics: Prometheus text at `/metrics` (requires admin token if configured).
- Systemd reference unit: [docs/systemd/commucat.service](docs/systemd/commucat.service). Remember to allow write access to `/var/log/commucat` for the ledger.

---

## 7. Known gaps / TODOs

- Ledger success events for handshakes, deliveries, and calls.
- Actual implementations for transports beyond the default Noise/TLS tunnel.
- Federation dispatcher queue processing and remote signature verification.
- Media SFU, adaptive bitrate, and GPU acceleration.
- Comprehensive error handling for uploads, pairing throttling, and rate limiter exhaustion.

See [docs/todo.md](docs/todo.md) for granular tasks and [ROADMAP.md](ROADMAP.md) for milestone planning.
