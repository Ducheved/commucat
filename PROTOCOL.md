# CommuCat CCP-1 Protocol (2025-10 draft)

This document describes the current control-plane protocol spoken between CommuCat clients and the server ("CCP-1"). The code lives primarily in `crates/server`, `crates/proto`, and `crates/crypto`.

> **Status:** draft / pre-alpha. CCP-1 is still evolving; field names, framing, and timing rules may change. Post-quantum extensions, stealth transports, and multipath negotiation are not implemented yet.

---

## 1. Transport assumptions

1. Clients establish a **TLS 1.3** session (Pingora listener). Default endpoints: `https://host:443` in production, `https://host:8443` for development.
2. The bootstrap happens over **HTTP/2** (`h2` ALPN). Clients perform a **duplex POST** to `/connect`. The request body streams CCP-1 frames upstream; the response body streams frames downstream.
   - Alternative delivery modes are available on `/connect`:
     - **SSE (`mode=sse` or `Accept: text/event-stream`)** — downstream frames are emitted as `event: frame` entries with base64 payloads, upstream traffic remains the request body.
     - **NDJSON long-poll (`mode=long-poll`)** — downstream frames are newline-delimited JSON objects carrying base64 payloads.
     - **WebSocket (`mode=websocket` or standard `Upgrade` handshake)** — CCP-1 frames are exchanged as binary WebSocket messages after a RFC 6455 upgrade.
   - Modes that rely on HTTP (SSE/long-poll) still require the client to stream upstream frames over the POST body.
3. Every CCP-1 frame is length-prefixed with a **varint** and encoded/decoded with `commucat_proto::Frame::{encode,decode}`.
4. If the client closes the HTTP/2 stream before the handshake completes, the server reports `reason="client-closed"` (ledger) and logs `handshake read failed` with stage `hello`.

---

## 2. Bootstrap sequence

| Step | Direction | Payload | Description |
|------|-----------|---------|-------------|
| (pre-flight) | client → REST | `GET /api/server-info` | Fetch Noise catalog, supported protocol versions, session TTL, and the device CA public key. Optional but recommended. |
| (pre-flight) | client → REST | `/api/pairing` / `/api/pairing/claim` | Issue or redeem pairing codes when auto-approval is disabled. Produces device seed, `device_ca_public`, and optional certificate. |
| 1 | client → server | `FrameType::Hello` | Starts Noise XK or IK handshake. Includes ZK proof tied to `device_id` and the server domain. |
| 2 | server → client | `FrameType::Auth` | Returns Noise message 2 plus bootstrap metadata (session id, server static key, supported versions). |
| 3 | client → server | `FrameType::Auth` | Sends Noise message 3, finalising the handshake. |
| 4 | server → client | `FrameType::Ack` | Confirms bootstrap, optionally pushes queued envelopes from storage. |

Once step 3 succeeds the server:
- marks the connection as `Established`;
- publishes presence to Redis (TTL = `presence_ttl_seconds` from config);
- persists the `SessionRecord` to PostgreSQL;
- writes an audit record (`scope = "handshake"`, `result = "success"`) to the ledger.

---

## 3. Frame schema

All frames contain the following fields:

| Field | Meaning |
|-------|---------|
| `channel_id: u64` | Logical channel. Bootstrap always uses `0`.
| `sequence: u64` | Per-channel monotonically increasing counter. Each side maintains its own counter.
| `frame_type` | Enum (`Hello`, `Auth`, `Ack`, `Data`, `Error`, `Keepalive`, ...).
| `payload` | For bootstrap: `FramePayload::Control` wrapping a JSON object. Data frames may carry binary payloads.

### 3.1 `FrameType::Hello`

JSON keys used today:

| Key | Type | Required | Notes |
|-----|------|----------|-------|
| `pattern` | string | yes | `"XK"` or `"IK"`. The server currently accepts both.
| `supported_versions` | array<number> | recommended | List of protocol versions (e.g. `[1]`). Server negotiates the highest supported version.
| `protocol_version` | number | optional | Legacy single value if `supported_versions` omitted. Must match server support.
| `device_id` | string | yes | Unique per device, e.g. `device-<epoch>-<suffix>`.
| `handshake` | hex string | yes | Noise message 1 (client -> server). Encoded with `hex` lower-case.
| `client_static` | hex string | yes | Client static Noise public key.
| `device_public` | hex string | yes | Long-lived device public key (will be stored/rotated).
| `capabilities` | array<string> | optional | Advertised feature flags (unused today).
| `zkp` | object | yes | Zero-knowledge proof generated with `commucat_crypto::zkp::prove_handshake`.
| `device_ca_public` | hex string | optional | Public key of device CA certificate used to sign device certificates.
| `user` | object | optional | Hints about the user (`id`/`user_id`, `handle`, `display_name`, `avatar_url`).
| `certificate` | object | optional | Serialized `DeviceCertificate`. Allows resuming known devices.

### 3.2 Server processing of `Hello`

1. **Protocol negotiation:** server inspects `supported_versions`/`protocol_version` and chooses a value present in `SUPPORTED_PROTOCOL_VERSIONS`. Otherwise returns `ServerError::ProtocolNegotiation`.
2. **Pattern check:** only `XK`/`IK` are valid. Unknown patterns trigger `ServerError::Invalid`.
3. **Proof verification:** server reconstructs the ZKP challenge using configured `domain`, `device_id`, `device_public`, `client_static`. Failures yield `ServerError::Invalid` (ledger `reason="invalid"`).
4. **Noise candidate selection:** iterates over active Noise static keys (`SecretManager::active_noise_keys`), attempting to read message 1. Failure results in `ServerError::Invalid`.
5. **User/device lookup:**
   - If `device_id` already exists, verifies status `active`, matches hints, and rotates `public_key` if necessary (ledger action `rotate`).
   - If missing and auto approval is enabled (or pairing provided a certificate), creates a `DeviceRecord` and optionally a `UserProfile` (ledger action `register`).
   - If a certificate is provided, validates signature, expiry, and device/user binding.
6. **Certificate issuance:** if no certificate provided, the server issues one signed by `device_ca_public`.
7. **Context enrichment:** `HandshakeContext` stores `device_id`, `user_id`, `user_profile`, `certificate`, selected Noise key, and whether the device was known (`device_known`).

### 3.3 Server → client `FrameType::Auth`

Keys:

| Key | Description |
|-----|-------------|
| `session` | Newly generated session id (string).
| `device_id` | Echo of the client device id.
| `handshake` | Noise message 2 (hex encoded).
| `server_static` | Server static Noise public key (hex).
| `protocol_version` | Negotiated version.
| `supported_versions` | Array of versions still accepted (for future renegotiation).
| `device_ca_public` | Hex-encoded certificate signer public key.
| `user` | JSON snapshot of the user profile.
| `certificate` | The finalized device certificate.

### 3.4 Client → server `FrameType::Auth`

Contains only `handshake` (Noise message 3). On success the server transitions `context.stage` to `Established`, creates a `NoiseTransport`, registers the session, and writes a ledger entry (`scope="handshake", result="success"`).

---

## 4. Post-bootstrap traffic

Once established, the `/connect` stream is used for:

- **Keepalive:** server enforces `connection_keepalive` seconds; clients should send `Keepalive` frames before the TTL/2 window.
- **Presence:** the server publishes `PresenceSnapshot` with TTL `presence_ttl_seconds` in Redis.
- **Relay delivery:** queued envelopes (`relay_queue`) are drained and re-framed with updated `sequence` numbers.
- **Calls / media:** `FrameType::Data` with call control payloads (Opus/VP8 only) are relayed if enabled. Advanced SFU features are stubbed.
- **Errors:** failures throw `FrameType::Error` with `properties` describing the cause (e.g. `{ "error": "handshake" }`).

---

## 5. Pairing API quick reference

- `POST /api/pairing` (authenticated device) → issues a code, expiry, and a fresh `device_seed` plus `device_ca_public`.
- `POST /api/pairing/claim` (unauthenticated) → consumes the code, generates a `device_id`, derives keys from `device_seed`, and returns `device_private/public`, `device_certificate`, and the target user profile.

When auto approval is disabled, the claim path is mandatory; otherwise `Hello` without prior pairing will be rejected with `ServerError::Invalid`.

---

## 6. Ledger mapping

Every handshake failure calls `emit_handshake_failure`, logging and recording structured metadata:

- `scope = "handshake"`
- `result = "failure"`
- `reason` ∈ { `"read"`, `"decode"`, `"handshake"`, `"client-closed"`, ... }
- `stage` ∈ { `"hello"`, `"await_client"`, `"established"` }
- Additional fields: `remote_addr`, `device`, `user`, `device_known`, `noise_key_active`, `noise_key_version`, `has_user_profile`, `has_certificate`, `session`, `protocol_version`, `detail`

Successful handshakes are logged separately (`info` level) but do not yet emit a ledger record; planned work will add `result="success"` entries.

---

## 7. Planned evolutions / stubs

| Area | Current state | Planned work |
|------|---------------|--------------|
| **Stealth transports** | Catalog items exist (AmnesiaWg, QuicMasque, Onion, Reality) but return placeholder values. | Implement actual tunnelling, key material negotiation, failure propagation. |
| **Post-quantum handshakes** | ML-KEM/ML-DSA deps compiled but not used during bootstrap. | Offer hybrid Noise handshake with PQ static keys and update server-info hints. |
| **Federation events** | Federation signer/verifier exist; dispatch loop mostly mocked. | Complete outbound queue, deliver to remote peers, add authentication/ACL. |
| **Media SFU** | Opus/VP8 encoders run locally; network forwarding is basic. | Add adaptive bitrate, AV1/H.264 codecs, GPU paths, per-call metrics. |
| **Ledger coverage** | Handshake failures recorded; many success paths missing. | Emit `success` entries and per-channel delivery records. |

Contributions are welcome—see [ROADMAP.md](ROADMAP.md) for prioritised tasks.
