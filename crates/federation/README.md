# commucat-federation

Utilities for signing and validating inter-domain events.

- `FederationEvent` – canonical representation of an outbound event (identifier, origin domain, JSON payload, scope).
- `sign_event` / `verify_event` – Ed25519 signatures over a BLAKE3 digest, compatible with `commucat-crypto::EventSigner` / `EventVerifier`.
- `PeerDescriptor` – metadata describing trusted peers (domain, endpoint, public key, last-seen timestamp).

The crate is used by the server to enqueue outbound events into the federation outbox and to verify inbound payloads delivered through `/federation/events`. It focuses purely on message authenticity; transport, retries and monitoring are handled by the server crate.