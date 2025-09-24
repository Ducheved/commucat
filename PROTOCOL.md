# CommuCat CCP-1 Specification

CCP-1 (CommuCat Protocol v1) is a binary framing protocol transported over a duplex HTTP/2 or HTTP/1.1 (chunked) stream that is upgraded at `/connect`. The tunnel is TLS 1.3, with an application-layer Noise handshake layered on top of the HTTP stream to deliver forward secrecy. Frames are encrypted end-to-end by the clients; the server forwards ciphertext without access to content.

## Transport

* **Upgrade endpoint**: `POST /connect`
* **Encapsulation**: HTTP/2 data frames or HTTP/1.1 chunked body
* **Session selection**: single request multiplexes virtual channels via the `channel_id` field
* **Tracing**: incoming `traceparent` header is echoed in structured logs

Once the HTTP response headers (status `200`) are emitted, both peers exchange CCP-1 frames until one closes the stream.

## Frame Format

Every frame is length-prefixed using LEB128/varint encoding:

```
frame      = frame_len *frame_bytes
frame_len  = varint (octet length of frame_bytes)
frame_bytes = frame_type channel_id sequence payload_len payload_bytes
frame_type  = u8 enum
channel_id  = varint
sequence    = varint (monotonic per sender)
payload_len = varint
payload_bytes = opaque bytes interpreted per frame type
```

### Frame Types

| Type | Code | Payload semantics |
|------|------|-------------------|
| `HELLO` | `0x01` | JSON control envelope initiating Noise handshake |
| `AUTH` | `0x02` | JSON control envelope carrying handshake continuations |
| `JOIN` | `0x03` | JSON control, membership declaration for channel |
| `LEAVE` | `0x04` | JSON control removing membership |
| `MSG` | `0x05` | Ciphertext payload delivered end-to-end |
| `ACK` | `0x06` | JSON control acknowledging specific sequences |
| `TYPING` | `0x07` | Ciphertext or lightweight hint routed like `MSG` |
| `PRESENCE` | `0x08` | JSON control heartbeat/availability update |
| `KEY_UPDATE` | `0x09` | Ciphertext with new encryption material |
| `GROUP_CREATE` | `0x0a` | JSON control describing new group |
| `GROUP_INVITE` | `0x0b` | JSON control inviting member to group |
| `GROUP_EVENT` | `0x0c` | Ciphertext or control for group fanout |
| `ERROR` | `0x0d` | JSON control describing protocol errors |

Control payloads are UTF-8 JSON documents carried inside the CCP frame. Ciphertext payloads are arbitrary byte arrays produced by the clients after Noise handshake completion.

### Varint Encoding

CCP-1 encodes integers in little-endian base-128 with continuation bit (`0x80`). Implementations must reject integers that overflow 64 bits or consume more than 10 bytes.

## Handshake

1. **Client → Server (`HELLO`)**
   ```jsonc
   {
     "pattern": "XK" | "IK",
     "device_id": "opaque",
     "client_static": "hex(x25519_public_key)",
     "handshake": "hex(noise_message_1)",
     "user": {
       "id": "existing-user-id",
       "handle": "desired-handle",
       "display_name": "optional nickname",
       "avatar_url": "https://..."
     },
     "capabilities": ["noise", "zstd", ...]
   }
   ```
   The server loads the device metadata, validates the static key, and prepares a Noise responder state using the configured prologue.

2. **Server → Client (`AUTH`)**
   ```jsonc
   {
     "session": "opaque_session_id",
     "handshake": "hex(noise_message_2)",
     "server_static": "hex(server_x25519_public)",
     "user": {
       "id": "resolved-user-id",
       "handle": "effective-handle",
       "display_name": "optional nickname",
       "avatar_url": "https://..."
     }
   }
   ```

3. **Client → Server (`AUTH`)**
   ```jsonc
   { "handshake": "hex(noise_message_3)" }
   ```

After message three the Noise state switches into transport mode. The server never accesses plaintext payloads. A final `ACK` frame with `{ "handshake": "ok", "user": {...} }` confirms tunnel readiness.

*Profile provisioning*: the `user` object in `HELLO` lets clients attach devices to existing profiles (`id`) or request new profiles (`handle`, plus optional `display_name` and `avatar_url`). When auto-approval is enabled, absent `id` instructs the server to mint a fresh user. The server echoes canonical profile fields in the `AUTH` response and completion `ACK`, ensuring clients persist consistent identifiers.

*Noise parameters*: `Noise_XK_25519_ChaChaPoly_BLAKE2s` or `Noise_IK_25519_ChaChaPoly_BLAKE2s` with empty PSKs and configurable prologue. Clients derive AEAD keys for subsequent ciphertext frames.

## Routing Semantics

* `channel_id` identifies the virtual channel. Clients must send a `JOIN` control frame before routing ciphertext on a new channel.
* `JOIN` payload example:
  ```json
  {
    "members": ["deviceA", "deviceB"],
    "relay": false
  }
  ```
  Setting `relay=true` forces server fan-out even if direct connectivity is possible.
* `LEAVE` removes the sender from server-side routing tables.
* For direct channels the server distributes observed socket addresses via `PRESENCE` control frames, enabling UDP/TCP hole punching attempts. Clients fall back to server relay upon timeout.

## Federation

When a `JOIN` announces members outside the local domain (`device@remote.example`), or a ciphertext targets an offline remote member, CommuCat signs an event:
```json
{
  "event_id": "opaque",
  "origin": "example.org",
  "scope": "remote.example",
  "payload": {
    "channel": 42,
    "sequence": 12,
    "payload": "hex(ccp_frame)"
  }
}
```
The payload is hashed with BLAKE3 and signed using the configured Ed25519 key. The signed envelope is queued for HTTPS (HTTP/2) delivery to the peer domain.

## Error Frames

`ERROR` control payloads follow [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) shape:
```json
{
  "type": "about:blank",
  "title": "Handshake Failed",
  "status": 403,
  "detail": "invalid static key"
}
```
Clients should treat receipt of `ERROR` as fatal for the stream.

## Sequence Numbers

* Each sender maintains an independent 64-bit sequence per connection.
* The server asserts monotonic behaviour but does not reset numbers across reconnects.
* `ACK` frames echo the confirmed sequence in the control payload. Clients can resend unacknowledged frames as idempotent envelopes when needed.

## Offline Delivery

Encrypted frames destined for offline members are persisted in PostgreSQL (`relay_queue`) under key `inbox:{device_id}`. Upon reconnect the server replays stored frames assigning fresh sequence numbers for the recipient.

## Presence Metadata

Redis presence keys capture profile context so peers can render nicknames and avatars:

```
{
  "entity": "device-id",
  "state": "online" | "offline",
  "expires_at": "RFC3339 timestamp",
  "user": {
    "id": "user-id",
    "handle": "nick",
    "display_name": "optional",
    "avatar_url": "optional"
  }
}
```

## P2P Negotiation

* Observed socket addresses (`client_addr`) are published to channel peers as:
  ```json
  {
    "channel": 7,
    "peer": "deviceA",
    "candidate": "198.51.100.10:52345"
  }
  ```
* Clients attempt simultaneous hole punching. Failure to confirm within client-defined timeout results in continued relay mode.

## Compression and Extensions

* CCP-1 starts uncompressed. After negotiation (e.g., via control frame `{ "compression": "zstd" }`) peers MAY wrap ciphertext payloads in per-message zstd. Negotiation outcome is opaque to the server.
* Additional frame types must be assigned new numeric codes and documented for interoperability.

## Security Considerations

* TLS 1.3 is mandatory; ECH can be enabled on the terminating proxy if supported.
* Noise handshake authenticates devices through pre-registered static keys; the server merely validates and records session metadata.
* Control frames must never contain personally identifiable data; device IDs remain opaque.
* Replay protection is delegated to clients (through sequence tracking) and storage deduplication (`idempotency` table).
