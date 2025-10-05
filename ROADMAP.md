# CommuCat Roadmap (2025–2026)

_Last updated: 2025-10-05 — reflects the current repository state._

The project is pre-alpha. Items below describe intended milestones; delivery dates are aspirational and may shift as core functionality stabilises.

---

## 0. Completed foundations (2024–mid 2025)

- ✅ TLS 1.3 + Noise XK/IK bootstrap over HTTP/2 (`/connect`).
- ✅ PostgreSQL + Redis integration, CLI migrations (`commucat-cli migrate`).
- ✅ Pairing API (`/api/pairing`, `/api/pairing/claim`) and auto-approval toggle.
- ✅ JSONL ledger with file/debug/null adapters.
- ✅ Basic Opus/VP8 media pipeline (no SFU yet).
- ✅ Prometheus metrics, `/healthz`, `/readyz`, `/metrics`.

---

## 1. Remainder of 2025 (CommuCat 1.1 / 1.2)

### 1.1 Reliability & onboarding

| Item | Target | Status |
|------|--------|--------|
| Harden ledger success-path coverage (handshake, delivery, calls) | Q4 2025 | ⏳ In progress |
| CLI onboarding helpers (`commucat-cli autopair`, diagnostics) | Q4 2025 | ⏳ Draft design |
| Systemd packaging polish (tmpfiles, LogsDirectory, sandbox tuning) | Q4 2025 | ⏳ Needs work |
| Quick start & protocol docs refresh | Q4 2025 | ✅ (this update) |

### 1.2 Protocol polish

- Capability renegotiation (codec fallback, feature flags).
- Error taxonomy for bootstrap (map common failures to stable codes).
- Expand REST coverage in OpenAPI spec (`docs/openapi-server.spec.yaml`).

---

## 2. 2026 H1 (CommuCat 1.3 / 1.4)

### 2.1 Transport & stealth experimentation

| Item | Description | Status |
|------|-------------|--------|
| Reality / AmnesiaWG transport prototypes | Integrate proto definitions, minimal handshake | ☐ Not started |
| Shadowsocks / Onion wrappers | Evaluate pluggable obfuscation layers | ☐ Not started |
| Traffic-shaping / padding | Basic timing obfuscation on `/connect` stream | ☐ Not started |

### 2.2 Post-quantum bootstrap

- Hybrid Noise handshake (ML-KEM static, ML-DSA signatures).
- Surfacing PQ capabilities through `/api/server-info`.
- Benchmarks and size impact analysis.

### 2.3 Federation MVP

- Finish dispatcher loop (deliver `federation_outbox` to remote peers).
- Signed event verification and retry/backoff.
- Administrative tooling to manage peer allow-lists.

---

## 3. 2026 H2 (towards CommuCat 2.0)

### 3.1 CCP-2 draft

- Structured payloads (CBOR/Protobuf) for control messages.
- Negotiable capability sets and application-level auth contexts.
- Backwards-compatible migration path from CCP-1.

### 3.2 Media & SFU upgrades

- AV1 / H.264 codec support (software first, GPU optional).
- Adaptive bitrate and simulcast/FEC experimentation.
- Distributed SFU prototype for multi-party calls.

### 3.3 Mesh & multipath

- QUIC-based relay with multipath scheduling.
- NAT traversal helpers (ICE-lite, TURN integration).
- Offline/mesh sync research (Wi-Fi Direct/BLE).

---

## 4. Stretch goals / vision (post-2026)

- Seamless bridges to other protocols (Matrix, Signal, XMPP).
- Wallet / micropayment integrations for tipping and relaying.
- Production deployment tooling (Helm charts, operators, cloud images).
- Advanced traffic analysis resistance (steganography, ML-based evasion).

---

## 5. How to help

We are especially interested in contributions around:

- Rust development (server, crypto, storage, transports).
- Security (Noise, PQ, ZKP audits).
- Infrastructure & deployment automation.
- Client implementations (Flutter, Swift, C#/MAUI, web).
- Documentation & UX.

Open an issue or reach out to `team@commucat.tech` before starting large tasks. Please align proposals with the roadmap above to avoid duplicate effort.
