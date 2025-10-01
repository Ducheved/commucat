# commucat-ledger

Lightweight adapters for exporting CommuCat audit digests.

- `NullLedger` – no-op sink used in tests and local development.
- `FileLedgerAdapter` – appends newline-delimited JSON to a file, creating parent directories when necessary.
- `DebugLedgerAdapter` – emits digests via `tracing` (target `commucat::ledger`).

The server and CLI use these adapters to record device key rotations, session events and other audit trails.