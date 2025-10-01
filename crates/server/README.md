# commucat-server

Core binary of the CommuCat project. The server terminates TLS 1.3 (Pingora), performs the CCP-1 Noise XK/IK handshake, exposes REST endpoints and routes frames between devices, groups and federated peers.

Key subsystems:

- `app::CommuCatApp` – HTTP/2 application that handles handshakes, session orchestration, frame routing and REST endpoints.
- `app::media` – server-side transcoding for RAW PCM/I420 → Opus/VP8 and pass-through for pre-encoded media.
- `app::federation` – background dispatcher for the `federation_outbox` queue and inbound `/federation/events` processing with signature verification.
- `security::secrets` – Noise static/admin-token rotation backed by PostgreSQL and exposed through `/api/server-info`.
- `transport` – pluggable transport abstraction (Reality/QUIC/WebSocket scaffolding) and forward error correction helpers.
- `/metrics`, `/healthz`, `/readyz`, `/api/p2p/assist`, `/api/device/csr`, `/api/friends`, `/api/friends/{user_id}/devices` and other operational endpoints.

The binary expects a valid `commucat.toml`, PostgreSQL and Redis. Refer to the workspace `README.md` and `docs/quickstart.md` for deployment guidance.