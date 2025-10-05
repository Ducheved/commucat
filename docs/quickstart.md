# CommuCat Quick Start (2025-10)

This guide shows how to bring up a development CommuCat stack on a single host, provision the database, and perform the first Noise bootstrap with a client.

> **Pre-alpha warning:** the project is still evolving. Interfaces will change, migrations may be destructive, and several advertised features are placeholders. Do **not** expose this setup directly to untrusted networks.

---

## 0. Requirements

| Component | Minimum version | Notes |
|-----------|-----------------|-------|
| Rust toolchain | nightly 2024-02-01 or newer | Install with `rustup toolchain install nightly` and run `rustup override set nightly` inside the workspace. |
| PostgreSQL | 15+ | Creates and owns the `commucat` database. Enable `pgcrypto` if you plan to extend migrations. |
| Redis | 6+ | Used for presence and rendezvous caches. |
| OpenSSL / LibreSSL | Any recent release | Needed for TLS key generation. |
| libvpx / opus toolchains | Optional | Required if you build the media crates (default feature set). |
| `pkg-config` | Required on Linux/macOS/WSL | Needed to detect libvpx/libopus when compiling `commucat-media`. |

> Windows developers should use **WSL2** (Ubuntu/Debian) or MSYS2. Native Windows builds require manual installation of `pkg-config`, `libvpx`, and `opus`.

---

## 1. Clone & prepare the workspace

```bash
# Clone the repository
git clone https://github.com/ducheved/commucat.git
cd commucat

# Ensure nightly toolchain is active
rustup override set nightly

# Pre-fetch dependencies to surface toolchain issues early
cargo fetch
```

---

## 2. Generate configuration & secrets

1. Copy the sample config and edit as needed:
   ```bash
   cp commucat.toml commucat.local.toml
   $EDITOR commucat.local.toml
   ```
   Update:
   - `[server]` → `bind`, `domain`, `tls_cert`, `tls_key`
   - `[storage]` → `postgres_dsn`, `redis_url`
   - `[crypto]` → `noise_private`, `noise_public`, `federation_seed`
   - `[ledger]` → `mode = "file"`, `target = "/var/log/commucat/commucat-ledger.jsonl"` (or any writable path)

2. Generate TLS material (self-signed for dev):
   ```bash
   mkdir -p certs
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
     -days 365 -nodes -subj '/CN=commucat.local'
   ```

3. Produce Noise keys (32-byte hex each). You can use the CLI helper:
   ```bash
   cargo run -p commucat-cli -- rotate-keys --handle bootstrap --device noise-bootstrap \
     | rg 'public_key=' | cut -d '=' -f2
   ```
   Copy the `public_key` into `crypto.noise_public`. The corresponding private key is printed earlier in the command output; paste it into `crypto.noise_private`.

4. Export environment overrides (optional):
   ```bash
   cat > commucat.env <<'EOF'
   COMMUCAT_CONFIG=$(pwd)/commucat.local.toml
   COMMUCAT_PG_DSN=postgres://commucat:commucat@localhost/commucat
   COMMUCAT_REDIS_URL=redis://127.0.0.1:6379
   EOF
   ```

---

## 3. Provision PostgreSQL & Redis

```bash
# PostgreSQL (run as a superuser)
createdb commucat
createuser commucat
psql -d postgres -c "ALTER USER commucat WITH PASSWORD 'commucat'"
psql -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE commucat TO commucat"

# Redis (if not already running)
redis-server --daemonize yes
```

Apply database migrations and create a test user:

```bash
cargo run -p commucat-cli -- migrate
cargo run -p commucat-cli -- register-user alice "Alice" "https://example.com/avatar.png"
cargo run -p commucat-cli -- rotate-keys --handle alice
```

> The CLI currently performs minimal validation; failed commands may leave partial records. Use `psql` to clean up when experimenting.

---

## 4. Run the server

```bash
# Use the config prepared earlier
COMMUCAT_CONFIG=$(pwd)/commucat.local.toml \
  cargo run -p commucat-server --release
```

You should see JSON log lines similar to:

```json
{"level":"INFO","message":"commucat listening","address":"0.0.0.0:8443"}
```

Health & readiness probes:

```bash
curl -k https://commucat.local:8443/healthz
curl -k https://commucat.local:8443/readyz
```

If `ledger.mode = "file"`, ensure the target directory exists and is writable by the service user:

```bash
sudo install -d -o "$USER" -g "$USER" /var/log/commucat
```

---

## 5. Bootstrap a device manually (reference flow)

1. **Fetch server info**
   ```bash
   curl -k https://commucat.local:8443/api/server-info | jq
   ```
   Save `noise_public`, `device_ca_public`, `supported_versions`, and `session.keepalive_interval`.

2. **(Optional) Pairing** — when `auto_approve_devices = false`:
   - Authenticated device calls `POST /api/pairing` to mint a code.
   - New device posts `{ "pair_code": "XYZ123" }` to `POST /api/pairing/claim` to receive `device_seed`, keys, and certificate.

3. **Noise HELLO** — craft a CCP-1 `FrameType::Hello` with:
   - `pattern`: `"XK"`
   - `supported_versions`: `[1]`
   - `device_id`: unique string
   - `handshake`: Noise message 1 (use `commucat_crypto::build_handshake` helpers)
   - `client_static` / `device_public`: hex keys
   - `zkp`: proof generated with `commucat_crypto::zkp::prove_handshake`
   - Optional `user` hints and `certificate`

4. **Submit HELLO** over HTTP/2 using a tool or custom client. The server responds with `FrameType::Auth` containing `session`, `server_static`, `certificate`, and Noise message 2.

5. **Send AUTH** — write Noise message 3 back as `FrameType::Auth`. On success you will receive an `Ack` and possibly pending envelopes.

Monitor the ledger (`/var/log/commucat/commucat-ledger.jsonl`) for entries like:

```json
{"scope":"handshake","result":"failure","reason":"read", ...}
```

Use these to debug bootstrap issues; they include `remote_addr`, `stage`, and contextual flags (`device_known`, `has_certificate`, etc.).

---

## 6. Systemd deployment (preview)

A reference unit is available at [docs/systemd/commucat.service](systemd/commucat.service). Key points:

- Runs as user/group `commucat`, `ProtectSystem=full`, `ProtectHome=read-only`.
- Requires `LogsDirectory=commucat` or `ReadWritePaths=/var/log/commucat` in the final unit to let the ledger write to disk.
- Expects environment variables from `/etc/commucat/commucat.env` (optional) and main config at `/etc/commucat/commucat.toml`.

Edit the unit to match your environment, then:

```bash
sudo cp docs/systemd/commucat.service /etc/systemd/system/commucat.service
sudo systemctl daemon-reload
sudo systemctl enable --now commucat
```

---

## 7. Troubleshooting tips

- **`handshake read failed` / `reason="read"`** — client cancelled the HTTP/2 stream (common with aggressive timeouts in OkHttp). Disable `callTimeout` and keep the duplex body open.
- **`ledger mode is 'file' but ledger.target is not configured`** — set an absolute path in `ledger.target`.
- **`pkg-config` errors during build** — install `pkg-config` and codec development headers (`libvpx-dev`, `libopus-dev`).
- **`readyz` returns `degraded`** — verify PostgreSQL/Redis DSNs, credentials, and connectivity.
- **Pairing fails with 403** — pairing code expired (`pairing_ttl`), or auto-approval disabled without a valid pairing claim.

---

## 8. Next steps

- Review [PROTOCOL.md](../PROTOCOL.md) for a deep dive into CCP-1 framing.
- Inspect [ARCHITECT.md](../ARCHITECT.md) for component interactions.
- Track planned work in [ROADMAP.md](../ROADMAP.md) and [docs/todo.md](todo.md).

Happy hacking!
