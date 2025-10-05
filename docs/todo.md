# CommuCat TODO Tracker

This list captures granular tasks that are not yet captured in the main roadmap. Use it for day-to-day planning; sync periodically with [ROADMAP.md](../ROADMAP.md).

| Area | Task | Target release | Status | Notes |
|------|------|----------------|--------|-------|
| DX / Ops | Harden ledger success-path coverage (handshake success, deliveries, calls) | 1.2 | In progress | `emit_handshake_failure` exists; need matching `emit_handshake_success` + delivery records. |
| DX / Ops | CLI `autopair` command (generate pairing code + claim script) | 1.2 | Planned | Should wrap `/api/pairing` + `/api/pairing/claim` and emit device config bundle. |
| DX / Ops | Systemd packaging polish (tmpfiles.d, `LogsDirectory`, documentation) | 1.2 | Planned | Current unit requires manual `ReadWritePaths`. Provide turnkey instructions. |
| Protocol | Capability renegotiation (codec fallback, feature toggles) | 1.2 | Planned | Extend CCP-1 control envelope to advertise codec sets. |
| Media | Software H.264 (OpenH264) feature flag | 1.2 | Planned | Add `media-h264` feature with runtime detection and docs. |
| Protocol | Error taxonomy for bootstrap | 1.2 | Planned | Map common handshake failures to stable codes for clients. |
| Docs | Expand OpenAPI spec coverage | 1.2 | Planned | Audit endpoints, mark stubs, add pairing/call APIs. |
| Transports | Reality / AmnesiaWG prototype implementation | 1.3 | Planned | Flesh out `transport::default_manager` entries beyond placeholders. |
| Transports | Shadowsocks / Onion wrappers with policy knobs | 1.3 | Planned | Provide minimal obfuscation layer with config toggles. |
| Crypto | Hybrid Noise + ML-KEM/ML-DSA handshake | 1.3 | Planned | Wire PQ crates into bootstrap and surface via `/api/server-info`. |
| Federation | Complete dispatcher loop (deliver `federation_outbox`) | 1.3 | Planned | Implement HTTP push, retries, backoff, signature verification. |
| Media | Adaptive bitrate (simulcast/FEC experimentation) | 1.4 | Planned | Integrate raptorQ/FEC knobs and per-call metrics. |
| Mesh | QUIC/multipath experimental relay | 1.4 | Planned | Prototype alternate transport for group sessions. |
| Security | Admin token rotation CLI | 1.2 | Planned | Wrap `SecretManager::rotation` hooks with CLI command. |
| Observability | Structured tracing guide + examples | 1.2 | Planned | Document `RUST_LOG` presets and common log patterns. |
| QA | Integration test harness (docker-compose Postgres+Redis) | 1.2 | Planned | Automate migrations + smoke bootstrap in CI. |

_Completed items should move to ROADMAP or be removed from this table._
