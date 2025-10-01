# commucat-proto

Framing and data structures for the CommuCat CCP-1 protocol.

- Frames are encoded as varint length + frame type + `channel_id` + `sequence` + payload bytes.
- Control payloads serialize as JSON (`ControlEnvelope`); media payloads remain opaque (`FramePayload::Opaque`).
- The `call` module contains the signalling models (`CallOffer/Answer/End/Stats`, `CallTransport`, incremental ICE updates).
- The optional `obfuscation` feature enables experimental helpers (hashing + noise injection).

The crate is shared by the server and client libraries to serialize/deserialize CCP-1 frames and enforce protocol limits.