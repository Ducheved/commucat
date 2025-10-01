# commucat-cli

Operational command-line utilities for CommuCat administrators.

## Available commands

- `migrate` – applies the bundled PostgreSQL migrations.
- `register-user` – provisions a user profile and prints the identifiers to stdout.
- `rotate-keys` – generates a device key pair, signs a certificate and records the audit entry (prototype: the private key is printed to stdout, store it securely).
- `diagnose` – creates a diagnostic device/session and publishes presence information.
- `call-simulate [frames]` – runs the Opus media pipeline locally to sanity-check codecs.

The CLI expects the following environment variables: `COMMUCAT_PG_DSN`, `COMMUCAT_REDIS_URL`, `COMMUCAT_FEDERATION_SEED`. Entropy for `rotate-keys` is read from `/dev/urandom`; on Windows use WSL/MSYS2 or provide an alternate entropy source.