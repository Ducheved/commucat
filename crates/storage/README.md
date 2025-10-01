# commucat-storage

Asynchronous PostgreSQL + Redis data access layer for CommuCat.

- Migrations (`migrations/*.sql`) provision users, devices, pairing tokens, relay queue, secret rotation, federation peers, outbox and audit logs.
- `connect`, `migrate`, `readiness` wire up the database backends and run lightweight health probes.
- CRUD helpers for users/devices, CSR-based rotations, pairing flows, groups and federation peers.
- Offline message delivery via `relay_queue`/`InboxOffset`, presence and routing state in Redis (`presence:*`, `route:*`).
- Federation support: enqueue/claim/delete/reschedule helpers for the `federation_outbox`, idempotency tracking and access to device rotation history.

Limitations: there is no connection pooling yet and the Redis connection is wrapped in a `Mutex`, so production setups should introduce pooling/backpressure before heavy use.