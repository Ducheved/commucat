# commucat-crypto

Cryptographic primitives shared across the CommuCat stack.

- Noise XK/IK helpers (`build_handshake`, `NoiseHandshake`, `NoiseTransport`).
- Deterministic device key material (`DeviceKeyPair`) and certificate issuance (`DeviceCertificateData`, `EventSigner`).
- Federation signature verification (`EventVerifier`).
- ZKP helpers for proving device key ownership (`zkp` module).
- Optional `pq` feature: hybrid ML-KEM + ML-DSA utilities (`PqxdhBundle`, `HybridRatchet`, `SessionKeys`).

The crate is consumed by the server, CLI and federation layers for handshakes, signing and device key rotation workflows.