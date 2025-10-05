# Transport Layer Implementation Status

## Overview

CommuCat defines a **pluggable transport architecture** with 7 transport protocols. Currently, most transports are **scaffolding/stubs** that return in-memory streams for testing and development.

## Current Implementation Status

### ✅ Fully Implemented

**None** - All transports currently use `memory_stream()` stubs.

### 🚧 Scaffolding (Stubs)

All 7 transports have the **interface implemented** but use **in-memory duplex streams** instead of real network connections:

#### 1. **WebSocket Transport**
- **Status**: Scaffolding
- **Resistance**: Basic
- **Performance**: Medium latency, Medium throughput
- **Implementation**: Returns `tokio::io::duplex(64)` - in-memory stream
- **TODO**: Implement real WebSocket handshake and framing
- **Code**: `crates/server/src/transport/mod.rs:821-858`

```rust
async fn handshake(&self, _ctx: &TransportContext<'_>) -> Result<TransportSession, TransportError> {
    let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
    // ^ This is a stub! Should be:
    // let stream = tokio_tungstenite::connect_async(url).await?;
    Ok(TransportSession::new(
        TransportType::WebSocket,
        self.resistance_level(),
        self.performance_profile(),
        client,
    ))
}
```

#### 2. **Reality Transport**
- **Status**: Scaffolding
- **Resistance**: Maximum
- **Performance**: High latency, High throughput
- **Implementation**: Validates fingerprint, but returns in-memory stream
- **TODO**: 
  - Implement TLS fingerprint masking
  - Active probing with REALITY tickets
  - Integration with xray-core/v2ray
- **Code**: `crates/server/src/transport/mod.rs:602-647`

```rust
async fn handshake(&self, ctx: &TransportContext<'_>) -> Result<TransportSession, TransportError> {
    if let Some(reality) = &ctx.endpoint.reality
        && reality.fingerprint != self.fingerprint
    {
        return Err(TransportError::NotSupported);
    }
    let cert_len = self.certificate.len();
    debug!(cert_len, "reality certificate available");
    let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
    // ^ Stub! Should implement Reality TLS handshake
    Ok(TransportSession::new(...))
}
```

#### 3. **Shadowsocks Transport**
- **Status**: Scaffolding
- **Resistance**: Enhanced
- **Performance**: Medium latency, High throughput
- **Implementation**: Returns in-memory stream
- **TODO**: 
  - Implement AEAD cipher (AES-256-GCM/ChaCha20-Poly1305)
  - SOCKS5 handshake
  - Integration with shadowsocks-rust
- **Code**: `crates/server/src/transport/mod.rs:653-687`

#### 4. **Onion (Tor) Transport**
- **Status**: Scaffolding
- **Resistance**: Paranoid
- **Performance**: Low latency, Low throughput
- **Implementation**: Returns in-memory stream
- **TODO**:
  - Tor circuit establishment
  - Hidden service connection (.onion)
  - Integration with arti (Tor in Rust)
- **Code**: `crates/server/src/transport/mod.rs:693-731`

#### 5. **AmnesiaWg Transport**
- **Status**: Scaffolding
- **Resistance**: Maximum
- **Performance**: Medium latency, Medium throughput
- **Implementation**: Returns in-memory stream
- **TODO**:
  - WireGuard handshake implementation
  - Ephemeral keys (no logs)
  - UDP tunnel
  - Integration with boringtun
- **Code**: `crates/server/src/transport/mod.rs:737-771`

#### 6. **QUIC-MASQUE Transport**
- **Status**: Scaffolding
- **Resistance**: Enhanced
- **Performance**: High latency, High throughput
- **Implementation**: Returns in-memory stream
- **TODO**:
  - QUIC connection (HTTP/3)
  - CONNECT-UDP proxy (RFC 9298)
  - Integration with quinn
- **Code**: `crates/server/src/transport/mod.rs:777-815`

#### 7. **DNS Tunneling Transport**
- **Status**: Scaffolding
- **Resistance**: Enhanced
- **Performance**: Low latency, Low throughput
- **Implementation**: Returns in-memory stream
- **TODO**:
  - DNS over HTTPS (DoH) / DNS over TLS (DoT)
  - Data encoding in DNS queries/responses
  - Integration with hickory-dns
- **Code**: `crates/server/src/transport/mod.rs:861-899`

## Architecture

### Memory Stream Stub

All transports currently use this helper:

```rust
fn memory_stream() -> io::Result<(TransportStream, TransportStream)> {
    let (upstream, downstream): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
    Ok((
        Box::new(upstream) as TransportStream,
        Box::new(downstream) as TransportStream,
    ))
}
```

This creates an **in-memory bidirectional stream** (64 byte buffer) suitable for:
- ✅ Testing transport selection logic
- ✅ Benchmarking multipath aggregation
- ✅ FEC encoding/decoding validation
- ❌ **NOT for production use** - no real network I/O

### Transport Interface

Each transport implements the `PluggableTransport` trait:

```rust
#[async_trait]
pub trait PluggableTransport: Send + Sync {
    fn kind(&self) -> TransportType;
    fn resistance_level(&self) -> ResistanceLevel;
    fn performance_profile(&self) -> PerformanceProfile;
    
    async fn detect_censorship(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<CensorshipStatus, TransportError>;
    
    async fn handshake(
        &self,
        ctx: &TransportContext<'_>,
    ) -> Result<TransportSession, TransportError>;
}
```

**What's implemented:**
- ✅ Metadata (kind, resistance, performance)
- ✅ Censorship detection logic
- ✅ Interface scaffolding
- ❌ Actual network handshakes

## Why Scaffolding?

The current implementation prioritizes:

1. **Core Protocol First**: CommuCat Frame Protocol, Noise handshake, federation are fully working
2. **Multipath Architecture**: FEC, path selection, load balancing logic is complete
3. **Testing Infrastructure**: In-memory streams allow unit testing without network
4. **Gradual Rollout**: Transports can be implemented independently

## Implementation Priority

Recommended order for implementing real transports:

### Phase 1: Essential (High Priority)

1. **WebSocket** ⭐
   - Already partially implemented in `app/mod.rs` (`/connect` endpoint)
   - Client support exists
   - Simplest to complete
   - **Effort**: Low (1-2 days)

2. **QUIC-MASQUE** ⭐
   - Modern, fast, built-in multiplexing
   - Good NAT traversal
   - **Effort**: Medium (3-5 days)

### Phase 2: Censorship Resistance (Medium Priority)

3. **Reality TLS** 🔒
   - Critical for censorship circumvention
   - Mimics legitimate TLS traffic
   - **Effort**: High (1-2 weeks)
   - Requires xray-core integration

4. **Shadowsocks** 🔒
   - Proven censorship resistance
   - Widely deployed
   - **Effort**: Medium (5-7 days)

### Phase 3: Extreme Cases (Low Priority)

5. **Tor/Onion** 🧅
   - Maximum anonymity
   - High latency penalty
   - **Effort**: High (2-3 weeks)
   - Complex Tor circuit management

6. **DNS Tunneling** 🔍
   - Last resort for extreme censorship
   - Very low throughput
   - **Effort**: Medium (5-7 days)

7. **AmnesiaWg** 🔐
   - WireGuard without logs
   - Requires kernel/userspace WG
   - **Effort**: High (2-3 weeks)

## Testing Strategy

### Current Testing (With Stubs)

```rust
#[tokio::test]
async fn test_multipath_fec_encoding() {
    let manager = TransportManager::default();
    let endpoints = vec![
        MultipathEndpoint::new("primary", endpoint1),
        MultipathEndpoint::new("backup", endpoint2),
    ];
    
    // Works with memory_stream() stubs!
    let tunnel = manager.establish_multipath(&endpoints, 2, fec_profile).await?;
    let sample = tunnel.encode_frame(b"test data");
    
    assert!(sample.segments.len() > 0);
}
```

### Future Testing (With Real Transports)

```rust
#[tokio::test]
async fn test_websocket_handshake() {
    let transport = WebSocketTransport;
    let ctx = TransportContext {
        endpoint: Endpoint {
            address: "commucat.tech".to_string(),
            port: 443,
            server_name: Some("commucat.tech".to_string()),
            reality: None,
        },
        censorship: CensorshipStatus::None,
        network: NetworkSnapshot::default(),
    };
    
    let session = transport.handshake(&ctx).await?;
    
    // Should establish real WebSocket connection
    assert_eq!(session.transport, TransportType::WebSocket);
    
    // Test actual I/O
    session.stream.write_all(b"hello").await?;
    let mut buf = [0u8; 5];
    session.stream.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"hello");
}
```

## Migration Path

To implement a real transport:

### 1. Add Dependencies

```toml
# Cargo.toml
[dependencies]
tokio-tungstenite = "0.20"  # WebSocket
quinn = "0.10"               # QUIC
shadowsocks = "1.16"         # Shadowsocks
arti-client = "0.10"         # Tor
hickory-dns = "0.24"         # DNS
```

### 2. Replace `memory_stream()` Call

```rust
// Before (stub):
async fn handshake(&self, _ctx: &TransportContext<'_>) -> Result<TransportSession, TransportError> {
    let (client, _server) = memory_stream().map_err(|_| TransportError::Network)?;
    Ok(TransportSession::new(TransportType::WebSocket, ...))
}

// After (real implementation):
async fn handshake(&self, ctx: &TransportContext<'_>) -> Result<TransportSession, TransportError> {
    use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
    
    let url = format!("wss://{}:{}/connect", ctx.endpoint.address, ctx.endpoint.port);
    let (ws_stream, _) = connect_async(&url)
        .await
        .map_err(|_| TransportError::Network)?;
    
    let stream: TransportStream = Box::new(WebSocketAdapter::new(ws_stream));
    
    Ok(TransportSession::new(
        TransportType::WebSocket,
        self.resistance_level(),
        self.performance_profile(),
        stream,
    ))
}
```

### 3. Add Protocol-Specific Adapter

Some protocols need an adapter to implement `AsyncRead + AsyncWrite`:

```rust
struct WebSocketAdapter {
    inner: WebSocketStream<...>,
    read_buf: BytesMut,
}

impl AsyncRead for WebSocketAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Convert WebSocket messages to bytes
        ...
    }
}

impl AsyncWrite for WebSocketAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Convert bytes to WebSocket messages
        ...
    }
    
    // ... poll_flush, poll_shutdown
}
```

### 4. Add Integration Tests

```rust
#[tokio::test]
#[ignore] // Requires running server
async fn test_websocket_real_connection() {
    let transport = WebSocketTransport;
    let session = transport.handshake(&test_context()).await.unwrap();
    
    // Test real I/O
    test_bidirectional_io(session.stream).await;
}
```

## Network Measurement TODOs

```rust
// TODO: integrate actual RTT/bandwidth sampling against measurement endpoints
async fn probe_network_quality(endpoint: &Endpoint) -> NetworkSnapshot {
    // Current stub:
    sleep(Duration::from_millis(5)).await;
    NetworkSnapshot::degraded(0.012, 4_800, 90)
    
    // Should implement:
    // 1. ICMP echo (ping) for RTT
    // 2. HTTP GET small file for latency
    // 3. HTTP GET large file for throughput
    // 4. UDP probe for packet loss
}
```

## P2P Assist Behavior

**Current**: P2P Assist API returns all transports with **simulated metrics**.

**After Real Implementation**: P2P Assist will:
1. Actually probe each transport path
2. Measure real RTT, throughput, packet loss
3. Detect actual censorship (connection refused, timeout)
4. Return only **working transports** with accurate metrics

## See Also

- [P2P_ASSIST_CLIENT_GUIDE.md](P2P_ASSIST_CLIENT_GUIDE.md) - Client integration guide
- [PROTOCOL.md](../PROTOCOL.md) - Frame protocol specification
- [ARCHITECT.md](../ARCHITECT.md) - System architecture
- `crates/server/src/transport/mod.rs` - Transport implementation
- `crates/server/src/transport/fec.rs` - Forward Error Correction (RaptorQ)
