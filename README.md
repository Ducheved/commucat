# CommuCat Secure Routing Server (pre‑alpha)

[![CI](https://github.com/ducheved/commucat/actions/workflows/ci.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/ci.yml)
[![Release](https://github.com/ducheved/commucat/actions/workflows/release.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/release.yml)
[![Deploy](https://github.com/ducheved/commucat/actions/workflows/deploy.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/deploy.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-orange.svg)](LICENSE)

CommuCat is an experimental secure messaging relay built around TLS 1.3 (via [Pingora](https://github.com/cloudflare/pingora)) and a Noise-based CCP‑1 control protocol. The server multiplexes device sessions over HTTP/2, keeps durable state in PostgreSQL/Redis, and records audit events in a JSONL ledger.

> **Project status:** pre‑alpha. The codebase is under active development; several advertised features (stealth/multipath transports, post‑quantum handshakes, advanced federation, rich media pipeline) are still stubs. Expect breaking changes, missing validation, and incomplete observability.

---

## What works today

- **Noise XK/IK bootstrap** over TLS: clients POST `FrameType::Hello` to `/connect`; the server negotiates protocol version, verifies a ZKP commitment, provisions (or rehydrates) device state, and returns `FrameType::Auth`.
- **Connect channel variants:** `/connect` now supports SSE (`mode=sse`/`Accept: text/event-stream`), NDJSON long-poll (`mode=long-poll`), and WebSocket upgrades (`mode=websocket` or standard `Upgrade` headers). All variants reuse the CCP-1 frame codec; SSE/long-poll payloads are base64 encoded, while WebSocket frames remain binary.
- **Stateful storage:** PostgreSQL holds users, devices, pairing tokens, relay queues, and ledger metadata; Redis backs presence and rendezvous caches.
- **Device ledger:** JSONL append-only file (or in-memory null/debug adapter) captures registration, rotation, and call events with digest metadata.
- **Pairing API:** `/api/pairing` and `/api/pairing/claim` mint short-lived codes so new devices can derive keys, even when auto-approval is disabled.
- **Presence & relay queue:** established sessions publish presence and drain queued envelopes, supporting asynchronous delivery.
- **Basic observability:** `/healthz`, `/readyz`, `/metrics` (Prometheus text) and structured `tracing` JSON logs.

## What is still a stub

- **Stealth & multipath transports:** catalog items such as `AmnesiaWg`, `QuicMasque`, `Onion`, `Reality` only expose scaffolding; there is no production-ready obfuscation or path diversity yet.
- **Post-quantum (ML-KEM/ML-DSA) handshakes:** PQ crates are vendored but not wired into the Noise bootstrap.
- **Media and SFU pipeline:** the `commucat-media` crate currently exercises Opus/VP8 codecs locally; remote SFU relay, adaptive bitrate, and GPU acceleration are not implemented.
- **Federation dispatcher:** queues exist, but cross-domain event exchange is limited to mocks.
- **Fine-grained policy & auditing:** RBAC, trace propagation, and per-tenant isolation are planned but not shipped.

See [ROADMAP.md](ROADMAP.md) and [docs/todo.md](docs/todo.md) for the latest task tracking.

---

## Workspace layout

| Crate | Purpose |
|-------|---------|
| `crates/server` | Pingora-based HTTP/2 server, Noise handshake, REST API, CCP‑1 session management, metrics, pairing, ledger orchestration |
| `crates/proto` | CCP‑1 frame definitions, varint codec, JSON control envelopes |
| `crates/crypto` | Noise patterns, device certificates, ZK proof helpers, seed/key rotation utilities |
| `crates/storage` | PostgreSQL/Redis integration, schema migrations, pairing tokens, presence snapshots |
| `crates/ledger` | File/Debug/Null adapters for JSONL audit trail |
| `crates/federation` | Signed event schema and verification (dispatcher is partially stubbed) |
| `crates/media`, `crates/media-types` | Media codec abstractions (Opus/VP8 implemented; AV1/H.264 placeholders) |
| `crates/cli` | Operational CLI: migrations, key rotation, diagnostics |

Supporting documents:

- [ARCHITECT.md](ARCHITECT.md) — high-level architecture and data flow.
- [PROTOCOL.md](PROTOCOL.md) — CCP‑1 bootstrap, frame types, timing expectations.
- [docs/quickstart.md](docs/quickstart.md) — local setup, migrations, first connection.
- [docs/openapi-server.spec.yaml](docs/openapi-server.spec.yaml) — REST surface (generated, some endpoints still marked TBD).

---

## Getting started

1. **Install dependencies:** Rust nightly toolchain, PostgreSQL ≥15, Redis ≥6, OpenSSL (for key generation), and codec toolchains (libvpx, opus) if you plan to build media crates.
2. **Configure environment:** copy `commucat.toml` and adjust PostgreSQL/Redis DSNs, Noise keys, TLS certificate paths. Optionally export overrides via environment variables (`COMMUCAT_*`).
3. **Provision database:**
   ```bash
   cargo run -p commucat-cli -- migrate
   cargo run -p commucat-cli -- register-user alice "Alice" "https://example.com/avatar.png"
   cargo run -p commucat-cli -- rotate-keys --handle alice
   ```
4. **Generate TLS & Noise keys:** see [docs/quickstart.md](docs/quickstart.md#32-generate-noise-keys-and-tls-cert) for exact commands.
5. **Run the server:** `cargo run -p commucat-server --release`. Check `journalctl -u commucat` (or stdout) for `"commucat listening"`.
6. **Bootstrap a device:** follow the pairing and Noise HELLO flow in [PROTOCOL.md](PROTOCOL.md#noise-bootstrap).

> On Windows, WSL2/MSYS2 plus `pkg-config` for libvpx/opus is required; see quickstart caveats.

---

## Observability & operations

- **Health:** `GET /healthz` (always returns `ok` when listener is alive). `GET /readyz` checks PostgreSQL/Redis connectivity.
- **Metrics:** `GET /metrics` returns Prometheus metrics (`Authorization: Bearer <admin token>` if configured).
- **Ledger:** when `ledger.mode = "file"`, entries are written to `/var/log/commucat/commucat-ledger.jsonl` (ensure service user has write access).
- **Systemd unit:** see [docs/systemd/commucat.service](docs/systemd/commucat.service) for the maintained production unit (requires manual `LogsDirectory=` or `ReadWritePaths` override).

---

## Contributing & support

The project is research software: issues and PRs are welcome, but production support is not yet offered. Please review [ROADMAP.md](ROADMAP.md) for current priorities before proposing large changes.

Licensed under [MPL-2.0](LICENSE).
