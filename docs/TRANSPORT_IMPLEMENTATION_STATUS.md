# Transport Layer Implementation Status

## Overview

CommuCat ships a pluggable transport layer that can dynamically select the most suitable transport per connection. As of this iteration we have moved beyond pure scaffolding in three critical areas:

- **WebSocket transport** performs a real handshake against the P2P ingress endpoint and exposes an `AsyncRead + AsyncWrite` adapter backed by `tokio_tungstenite`.
- **Reality transport** performs active reachability probing (TCP connect with fingerprint validation) before exposing the transport.
- **TransportManager** now performs lightweight RTT/loss/bandwidth estimation by probing the intended endpoint with bounded TCP dials before ranking transports.
- **ICE-lite/TURN services** expose a built-in STUN listener and coturn-compatible TURN credentials so clients can bootstrap NAT traversal immediately from the assist response.

Forward error correction (RaptorQ) and multipath scheduling remain production ready; additional transports continue to reuse those facilities once they gain real I/O implementations.

## ✅ Implemented Pieces

### WebSocket Transport
- Location: `crates/server/src/transport/mod.rs`
- Uses `tokio_tungstenite::connect_async` to negotiate a real `ws://` / `wss://` session (10s timeout).
- Wraps the socket with `WebSocketAdapter` which translates framed WebSocket messages into a byte stream consumable by the Noise layer.
- Surfaces structured logs and error handling for connect / timeouts.
- Fully integrates with `TransportManager` scoring and multipath sampling.

### Network Probing
- Function: `assess_network_conditions(endpoint)`
- Performs up to three TCP dials with a 200 ms deadline to the target endpoint and records:
  - Best observed RTT (ms)
  - Success ratio → approximated loss rate
  - Heuristic bandwidth tier derived from RTT/availability
- The snapshot feeds into transport scoring and P2P assist recommendations.

### Reality Transport Censorship Detection
- Validates supplied PEM fingerprint with `blake3` before attempting probes.
- Executes two TCP probes; escalates status to `Suspected`/`Active` when connections fail or time out.
- On active censorship the handshake short-circuits with `TransportError::Censorship` so fallback transports are tried immediately.

### P2P Assist Endpoint
- Location: `crates/server/src/app/p2p.rs`
- Establishes temporary multipath tunnels using live transports (respecting min path count).
- Runs an FEC sample over the resulting paths, verifies recovery with `RaptorqDecoder`, and records segment mix per path.
- Returns actual transport profiles (resistance/performance tiers) and the primary path ID, along with `SampleBreakdown` statistics derived from the encoded segments.

### ICE-lite & TURN Integration
- `build_ice_runtime` seeds TURN configuration and spawns an ICE-lite UDP listener when enabled (`ice.lite_*` in config).
- `build_ice_advice` now surfaces:
  - Coturn-compatible TURN credentials (HMAC-SHA1) when a server entry defines `secret`.
  - Static TURN credentials for entries with explicit `username`/`password`.
  - Server-advertised ICE-lite host candidate so WebRTC clients can connect without extra STUN round-trips.
- `Metrics` expose `commucat_ice_binding_requests` / `commucat_ice_binding_failures` to observe STUN volume.

## 🚧 Remaining Scaffolding

The following transports still expose logical scaffolding (in-memory duplex streams) and require full network integrations:

1. **Reality Transport – data path** (handshake probing is real, tunnel still uses `memory_stream`).
2. **Shadowsocks Transport** – needs AEAD cipher setup and UDP/TCP tunnelling.
3. **Onion Transport** – needs Tor circuit establishment (`arti`).
4. **AmnesiaWG Transport** – requires WireGuard handshake and UDP transport.
5. **QUIC-MASQUE Transport** – needs QUIC/HTTP3 CONNECT-UDP implementation (`quinn`).
6. **DNS Transport** – needs DoH/DoT carrier and payload encoding.

Each of these transports already advertises resistance/performance metadata; once the handshake returns a real stream the multipath/FEC layers will function unchanged.

## Updated Network Measurement

```rust
async fn assess_network_conditions(endpoint: &Endpoint) -> NetworkSnapshot {
    const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
    const ATTEMPTS: u32 = 3;
    let target = format!("{}:{}", endpoint.address, endpoint.port);
    let mut best_rtt = None;
    let mut successes = 0u32;

    for attempt in 0..ATTEMPTS {
        let started = Instant::now();
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await {
            Ok(Ok(mut stream)) => {
                let elapsed = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
                best_rtt = Some(best_rtt.map_or(elapsed, |current| current.min(elapsed)));
                successes += 1;
                let _ = stream.shutdown().await;
            }
            Ok(Err(err)) => debug!(target = %target, attempt = attempt + 1, error = %err, "tcp probe failed"),
            Err(_) => debug!(target = %target, attempt = attempt + 1, "tcp probe timed out"),
        }
    }

    if successes == 0 {
        return NetworkSnapshot::degraded(0.08, 1_000, 280);
    }

    let rtt_ms = best_rtt.unwrap_or(220);
    let bandwidth_kbps = match rtt_ms {
        0..=40 => 12_000,
        41..=80 => 9_000,
        81..=150 => 6_000,
        151..=220 => 3_500,
        _ => 1_500,
    };
    let loss = 1.0f32 - (successes as f32 / ATTEMPTS as f32);
    let loss_rate = (0.01 + loss * 0.25).min(0.2);

    NetworkSnapshot::degraded(loss_rate, bandwidth_kbps, rtt_ms)
}
```

This measurement feeds directly into:
- Transport ranking (`score_transport`)
- Assist recommendations (`P2P Assist` response)
- Metrics (`Metrics::security_snapshot`).

## P2P Assist Response Improvements

- Builds transport advice using live multipath sessions instead of static heuristics.
- Records FEC sample mix per path and publishes it via `sample_segments`.
- Uses real obfuscation hints based on active `MultipathPathInfo` (e.g., domain fronting, Shadowsocks mimicry).
- Falls back to heuristic advice only when every transport fails, while logging censorship signals.

## Next Steps

1. **Wire actual data paths** for Reality, Shadowsocks, QUIC-MASQUE – these are now bottlenecked purely by transport implementations.
2. **Extend probes** with optional HTTPS HEAD (bandwidth) and jitter statistics when endpoints provide probe URLs.
3. **Expose measurement metrics** via Prometheus (`commucat_transport_rtt_ms`, `commucat_transport_loss_ratio`).
4. **Add integration tests** for WebSocket assist sampling (`#[tokio::test]` guarded by feature flag).

## References

- [P2P_ASSIST_CLIENT_GUIDE.md](P2P_ASSIST_CLIENT_GUIDE.md)
- [PROTOCOL.md](../PROTOCOL.md)
- `crates/server/src/transport/mod.rs`
- `crates/server/src/app/p2p.rs`
