# P2P Assist API - Client Integration Guide

## Overview

The CommuCat P2P Assist API helps establish peer-to-peer connections by providing:
- **Multipath transport** configuration with live performance metrics captured during the request
- **ICE credentials** for NAT traversal (STUN/TURN)
- **Cryptographic parameters** (Noise Protocol + Post-Quantum)
- **Forward Error Correction (FEC)** settings for packet loss resilience with RaptorQ sampling results
- **Obfuscation advice** for censorship resistance derived from active transport probing

## Endpoint

```
POST /api/p2p/assist
Authorization: Bearer <session_token>
Content-Type: application/json
```

## Request Format

### Basic Request (Server Chooses Paths)

```json
{
  "prefer_reality": false,
  "min_paths": 2
}
```

### Advanced Request (Custom Paths)

```json
{
  "peer_hint": "relay.commucat.tech",
  "prefer_reality": true,
  "min_paths": 3,
  "paths": [
    {
      "address": "commucat.tech",
      "port": 443,
      "server_name": "commucat.tech",
      "priority": 0,
      "reality_fingerprint": "a1b2c3d4...",
      "reality_pem": "-----BEGIN CERTIFICATE-----\n..."
    },
    {
      "address": "backup.commucat.tech",
      "port": 443,
      "priority": 1
    }
  ],
  "fec": {
    "mtu": 1200,
    "repair_overhead": 0.4
  }
}
```

### Request Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `peer_hint` | string | No | Fallback relay server address |
| `prefer_reality` | boolean | No | Use Reality TLS obfuscation (default: false) |
| `min_paths` | integer | No | Minimum transport paths (default: 2) |
| `paths` | array | No | Custom path configurations (empty = server decides) |
| `fec` | object | No | FEC encoding parameters |

#### Path Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `address` | string | Yes | Server hostname or IP |
| `port` | integer | No | Port number (default: 443) |
| `id` | string | No | Custom path identifier |
| `server_name` | string | No | TLS SNI server name |
| `priority` | integer | No | Path priority (lower = higher priority) |
| `reality_fingerprint` | string | No | Reality TLS fingerprint (hex) |
| `reality_pem` | string | No | Reality certificate (PEM format) |

#### FEC Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mtu` | integer | No | Maximum transmission unit (default: 1152) |
| `repair_overhead` | float | No | FEC redundancy ratio (default: 0.35) |

## Response Format

### Success Response (200 OK)

```json
{
  "noise": {
    "pattern": "XK",
    "prologue_hex": "636f6d6d75636174",
    "device_seed_hex": "90144b6eb668cca2780759e8492d72445b2762a45564230f767471469a655eea",
    "static_public_hex": "4ee4ecee64e8b9041184ac845dbd7950f01e86f798869e757711abd9cd4d0166"
  },
  "pq": {
    "identity_public_hex": "a1b2c3d4e5f6...",
    "signed_prekey_public_hex": "7890abcdef...",
    "kem_public_hex": "fedcba9876...",
    "signature_public_hex": "0123456789..."
  },
  "ice": {
    "username_fragment": "ice-ufrag123456",
    "password": "long-random-password-for-ice-authentication",
    "ttl_secs": 600,
    "keepalive_interval_secs": 30,
    "trickle": true,
    "servers": [
      {
        "urls": [
          "turn:turn.commucat.tech:3478?transport=udp",
          "turns:turn.commucat.tech:5349?transport=tcp"
        ],
        "username": "1712332800:ice-ufrag123456",
        "credential": "base64-hmac-of-shared-secret",
        "ttl_secs": 600,
        "expires_at": "2025-10-06T12:00:00Z",
        "realm": "commucat"
      }
    ],
    "lite_candidates": [
      {
        "candidate": "candidate:a1b2c3d4 1 udp 2130706431 198.51.100.10 3478 typ host generation 0",
        "component": 1,
        "protocol": "udp",
        "foundation": "a1b2c3d4",
        "priority": 2130706431,
        "ip": "198.51.100.10",
        "port": 3478,
        "typ": "host"
      }
    ]
  },
  "transports": [
    {
      "path_id": "primary",
      "transport": "WebSocket",
      "resistance": "Basic",
      "latency": "Low",
      "throughput": "High"
    },
    {
      "path_id": "backup",
      "transport": "Reality",
      "resistance": "Maximum",
      "latency": "Medium",
      "throughput": "Medium"
    }
  ],
  "multipath": {
    "fec_mtu": 1152,
    "fec_overhead": 0.35,
    "primary_path": "primary",
    "sample_segments": {
      "primary": {
        "total": 24,
        "repair": 7
      },
      "backup": {
        "total": 18,
        "repair": 6
      }
    }
  },
  "obfuscation": {
    "reality_fingerprint_hex": "a1b2c3d4...",
    "domain_fronting": true,
    "protocol_mimicry": true,
    "tor_bridge": false
  },
  "security": {
    "noise_handshakes": 1234,
    "pq_handshakes": 567,
    "active_connections": 89,
    "rate_limited_ips": 12
  }
}
```

### Response Fields

#### `noise` Object - Noise Protocol Configuration

| Field | Type | Description |
|-------|------|-------------|
| `pattern` | string | Handshake pattern: "XK" or "IK" |
| `prologue_hex` | string | Protocol identifier (hex) |
| `device_seed_hex` | string | Temporary device key seed (32 bytes hex) |
| `static_public_hex` | string | Device static public key (32 bytes hex) |

#### `pq` Object - Post-Quantum Cryptography

| Field | Type | Description |
|-------|------|-------------|
| `identity_public_hex` | string | Ed25519 identity public key |
| `signed_prekey_public_hex` | string | X25519 signed prekey |
| `kem_public_hex` | string | ML-KEM public key (quantum-resistant) |
| `signature_public_hex` | string | ML-DSA signature public key |

#### `ice` Object - ICE Parameters for NAT Traversal

| Field | Type | Description |
|-------|------|-------------|
| `username_fragment` | string | ICE ufrag (16 chars) |
| `password` | string | ICE password (64 chars) |
| `ttl_secs` | integer | Credential validity period |
| `keepalive_interval_secs` | integer | STUN/TURN keepalive interval |
| `trickle` | boolean | Support trickle ICE |
| `servers` | array | TURN servers with credentials |
| `lite_candidates` | array | ICE-lite host candidates advertised by the server |

##### `servers[]` entries

| Field | Type | Description |
|-------|------|-------------|
| `urls` | array | TURN URIs (e.g., `turn:` / `turns:`) |
| `username` | string | TURN username (may include expiry prefix) |
| `credential` | string | TURN credential (static or HMAC-SHA1) |
| `ttl_secs` | integer | Remaining credential lifetime (0 for static creds) |
| `expires_at` | string | RFC 3339 expiry timestamp when present |
| `realm` | string | Optional TURN realm hint |

##### `lite_candidates[]` entries

| Field | Type | Description |
|-------|------|-------------|
| `candidate` | string | SDP candidate line (ICE-lite host candidate) |
| `component` | integer | RTP component (1 = RTP, 2 = RTCP) |
| `protocol` | string | Transport protocol (`udp`) |
| `foundation` | string | Candidate foundation (hash of public IP) |
| `priority` | integer | Candidate priority (RFC 5245) |
| `ip` | string | Advertised IP address |
| `port` | integer | Advertised UDP port |
| `typ` | string | Candidate type (`host`) |

> **Note**
> - TURN entries configured with `secret` use coturn-compatible temporary credentials: `username = "<expires>:<username_fragment>"` and `credential = BASE64(HMAC-SHA1(secret, username))`. `ttl_secs` and `expires_at` mirror `ice.turn_ttl`.
> - Entries with static `username` / `password` are returned verbatim with `ttl_secs = 0`.
> - `lite_candidates` expose the server’s ICE-lite host candidate so WebRTC stacks can bootstrap connectivity without waiting for a full STUN gathering cycle.

#### `transports` Array - Available Transport Paths

| Field | Type | Description |
|-------|------|-------------|
| `path_id` | string | Unique path identifier |
| `transport` | string | Transport type: `WebSocket`, `QuicMasque`, `Dns`, `Shadowsocks`, `Onion`, `Reality`, `AmnesiaWG` |
| `resistance` | string | Censorship resistance tier (`Basic`, `Enhanced`, `Maximum`, `Paranoid`) |
| `latency` | string | Measured latency tier (`Low`, `Medium`, `High`) |
| `throughput` | string | Estimated throughput tier (`Low`, `Medium`, `High`) |

#### `multipath` Object - Multipath Configuration

| Field | Type | Description |
|-------|------|-------------|
| `fec_mtu` | integer | Maximum transmission unit for FEC |
| `fec_overhead` | float | Repair packet ratio (e.g., 0.35 = 35% redundancy) |
| `primary_path` | string | Primary path ID |
| `sample_segments` | object | FEC test results per path (derived from on-the-fly RaptorQ encode) |

#### `obfuscation` Object - Censorship Circumvention

| Field | Type | Description |
|-------|------|-------------|
| `reality_fingerprint_hex` | string | Reality TLS fingerprint (if available) |
| `domain_fronting` | boolean | Domain fronting supported |
| `protocol_mimicry` | boolean | Protocol mimicry (Shadowsocks) supported |
| `tor_bridge` | boolean | Tor bridge available |

#### `security` Object - Server Security Metrics

| Field | Type | Description |
|-------|------|-------------|
| `noise_handshakes` | integer | Total Noise handshakes completed |
| `pq_handshakes` | integer | Total PQ handshakes completed |
| `active_connections` | integer | Current active connections |
| `rate_limited_ips` | integer | IPs currently rate-limited |

## Client Integration Examples

### JavaScript/TypeScript

```typescript
interface P2pAssistRequest {
  peer_hint?: string;
  paths?: PathHint[];
  prefer_reality?: boolean;
  fec?: FecHint;
  min_paths?: number;
}

interface PathHint {
  address: string;
  id?: string;
  port?: number;
  server_name?: string;
  priority?: number;
  reality_fingerprint?: string;
  reality_pem?: string;
}

interface FecHint {
  mtu?: number;
  repair_overhead?: number;
}

async function requestP2pAssist(
  serverUrl: string,
  token: string,
  request: P2pAssistRequest = {}
): Promise<P2pAssistResponse> {
  const response = await fetch(`${serverUrl}/api/p2p/assist`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(request)
  });

  if (!response.ok) {
    throw new Error(`P2P assist failed: ${response.status}`);
  }

  return await response.json();
}

// Example usage
const assist = await requestP2pAssist('https://commucat.tech', sessionToken, {
  prefer_reality: false,
  min_paths: 2
});

console.log('Primary path:', assist.multipath.primary_path);
console.log('Available transports:', assist.transports.length);
console.log('ICE credentials:', assist.ice);
```

### Kotlin (Android)

```kotlin
data class P2pAssistRequest(
    val peerHint: String? = null,
    val paths: List<PathHint>? = null,
    val preferReality: Boolean = false,
    val fec: FecHint? = null,
    val minPaths: Int = 2
)

data class PathHint(
    val address: String,
    val id: String? = null,
    val port: Int? = null,
    val serverName: String? = null,
    val priority: Int? = null,
    val realityFingerprint: String? = null,
    val realityPem: String? = null
)

data class FecHint(
    val mtu: Int? = null,
    val repairOverhead: Float? = null
)

suspend fun requestP2pAssist(
    apiClient: ApiClient,
    request: P2pAssistRequest = P2pAssistRequest()
): P2pAssistResponse {
    return apiClient.post("/api/p2p/assist", request)
}

// Example usage
val assist = requestP2pAssist(
    apiClient = apiClient,
    request = P2pAssistRequest(
        preferReality = false,
        minPaths = 2
    )
)

Log.d("P2P", "Primary path: ${assist.multipath.primaryPath}")
Log.d("P2P", "Transports: ${assist.transports.size}")
Log.d("P2P", "ICE username: ${assist.ice.usernameFragment}")
```

### Python

```python
import requests
from typing import Optional, List, Dict, Any

class P2pAssistClient:
    def __init__(self, server_url: str, token: str):
        self.server_url = server_url
        self.token = token
    
    def request_assist(
        self,
        peer_hint: Optional[str] = None,
        paths: Optional[List[Dict[str, Any]]] = None,
        prefer_reality: bool = False,
        fec: Optional[Dict[str, Any]] = None,
        min_paths: int = 2
    ) -> Dict[str, Any]:
        """Request P2P assistance from server."""
        
        payload = {
            "prefer_reality": prefer_reality,
            "min_paths": min_paths
        }
        
        if peer_hint:
            payload["peer_hint"] = peer_hint
        if paths:
            payload["paths"] = paths
        if fec:
            payload["fec"] = fec
        
        response = requests.post(
            f"{self.server_url}/api/p2p/assist",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            },
            json=payload
        )
        
        response.raise_for_status()
        return response.json()

# Example usage
client = P2pAssistClient("https://commucat.tech", session_token)
assist = client.request_assist(prefer_reality=False, min_paths=2)

print(f"Primary path: {assist['multipath']['primary_path']}")
print(f"Available transports: {len(assist['transports'])}")
print(f"ICE username: {assist['ice']['username_fragment']}")
```

## Usage Workflow

### 1. Request P2P Assist

Before establishing a peer-to-peer connection, both clients request assistance:

```javascript
const alice_assist = await requestP2pAssist(serverUrl, aliceToken);
const bob_assist = await requestP2pAssist(serverUrl, bobToken);
```

### 2. Exchange Assist Information

Clients exchange their assist responses through the server (via encrypted messaging):

```javascript
// Alice sends her assist info to Bob
await sendMessage(bobUserId, {
  type: "p2p_offer",
  assist: alice_assist
});

// Bob receives and responds
await sendMessage(aliceUserId, {
  type: "p2p_answer",
  assist: bob_assist
});
```

### 3. Configure Noise Protocol

Use the Noise parameters from the assist response:

```javascript
import { NoiseHandshake } from '@commucat/noise';

const noise = new NoiseHandshake({
  pattern: assist.noise.pattern, // "XK" or "IK"
  prologue: Buffer.from(assist.noise.prologue_hex, 'hex'),
  localStaticPrivate: derivePrivateKey(assist.noise.device_seed_hex),
  localStaticPublic: Buffer.from(assist.noise.static_public_hex, 'hex'),
  remoteStaticPublic: Buffer.from(peerAssist.noise.static_public_hex, 'hex')
});
```

### 4. Initialize Post-Quantum Crypto

```javascript
import { PqxdhClient } from '@commucat/pq-crypto';

const pq = new PqxdhClient({
  identityPublic: Buffer.from(assist.pq.identity_public_hex, 'hex'),
  signedPrekeyPublic: Buffer.from(assist.pq.signed_prekey_public_hex, 'hex'),
  kemPublic: Buffer.from(assist.pq.kem_public_hex, 'hex'),
  signaturePublic: Buffer.from(assist.pq.signature_public_hex, 'hex')
});
```

### 5. Setup ICE for NAT Traversal

```javascript
import { RTCPeerConnection, RTCIceServer } from 'webrtc';

const iceConfig = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    {
      urls: 'turn:turn.commucat.tech:3478',
      username: assist.ice.username_fragment,
      credential: assist.ice.password
    }
  ],
  iceTransportPolicy: 'all',
  bundlePolicy: 'max-bundle'
};

const peerConnection = new RTCPeerConnection(iceConfig);

// Send keepalive every keepalive_interval_secs
setInterval(() => {
  peerConnection.getStats().then(stats => {
    // Check connection health
  });
}, assist.ice.keepalive_interval_secs * 1000);
```

### 6. Establish Multipath Transport

```javascript
// Select transports by priority
const primaryTransport = assist.transports.find(
  t => t.path_id === assist.multipath.primary_path
);

const backupTransports = assist.transports.filter(
  t => t.path_id !== assist.multipath.primary_path
);

// Connect via primary path
const primaryConnection = await connectTransport(primaryTransport);

// Connect backup paths in parallel
const backupConnections = await Promise.all(
  backupTransports.map(t => connectTransport(t))
);
```

### 7. Configure FEC Encoding

```javascript
import { RaptorQEncoder } from '@commucat/fec';

const encoder = new RaptorQEncoder({
  mtu: assist.multipath.fec_mtu,
  repairOverhead: assist.multipath.fec_overhead
});

// Encode data with redundancy
const message = Buffer.from("Hello, peer!");
const segments = encoder.encode(message);

// Send segments across multiple paths
for (const segment of segments) {
  const pathId = selectPath(segment);
  await sendOnPath(pathId, segment);
}
```

### 8. Handle Obfuscation (Optional)

If censorship resistance is needed:

```javascript
if (assist.obfuscation.reality_fingerprint_hex) {
  // Use Reality TLS obfuscation
  const realityConfig = {
    fingerprint: assist.obfuscation.reality_fingerprint_hex,
    serverName: 'cloudflare.com' // Mimic legitimate traffic
  };
  
  connection.enableReality(realityConfig);
}

if (assist.obfuscation.domain_fronting) {
  // Use domain fronting
  connection.setHost('cdn.cloudflare.net');
  connection.setSNI('commucat.tech');
}

if (assist.obfuscation.tor_bridge) {
  // Route through Tor
  connection.enableTor();
}
```

## Best Practices

### 1. Request Assist Early
Request P2P assist **before** initiating the connection to minimize latency:

```javascript
// Good: Request assist immediately after authentication
await authenticate();
const assist = await requestP2pAssist(serverUrl, token);
cachedAssist = assist;

// Later, when starting P2P call
await initiateP2pConnection(cachedAssist);
```

### 2. Handle Network Changes
Re-request assist if network conditions change:

```javascript
window.addEventListener('online', async () => {
  console.log('Network changed, refreshing P2P assist');
  assist = await requestP2pAssist(serverUrl, token);
  await reconnectP2p(assist);
});
```

### 3. Respect TTL
ICE credentials expire after `ttl_secs`:

```javascript
const assistTimestamp = Date.now();
const ttlMs = assist.ice.ttl_secs * 1000;

// Refresh before expiration
setTimeout(async () => {
  console.log('ICE credentials expiring, refreshing assist');
  assist = await requestP2pAssist(serverUrl, token);
}, ttlMs - 60000); // Refresh 1 minute before expiration
```

### 4. Monitor Transport Health
Use `keepalive_interval_secs` to detect dead connections:

```javascript
let lastPacketTime = Date.now();

connection.on('packet', () => {
  lastPacketTime = Date.now();
});

setInterval(() => {
  const timeSinceLastPacket = Date.now() - lastPacketTime;
  const threshold = assist.ice.keepalive_interval_secs * 2 * 1000;
  
  if (timeSinceLastPacket > threshold) {
    console.warn('Connection appears dead, reconnecting');
    reconnectP2p();
  }
}, assist.ice.keepalive_interval_secs * 1000);
```

### 5. Graceful Degradation
Handle partial path failures:

```javascript
const workingPaths = [];

for (const transport of assist.transports) {
  try {
    const conn = await connectTransport(transport);
    workingPaths.push(conn);
  } catch (err) {
    console.warn(`Path ${transport.path_id} failed:`, err);
  }
}

if (workingPaths.length === 0) {
  throw new Error('All transport paths failed');
}

// Use available paths even if not all succeeded
establishMultipathConnection(workingPaths, assist.multipath);
```

### 6. Privacy Considerations
- **Rotate assist requests**: Request new assist for each P2P session
- **Don't share PQ keys**: Each assist contains unique temporary keys
- **Use obfuscation in restricted networks**: Check `assist.obfuscation` flags

## Troubleshooting

### Error: 401 Unauthorized
```json
{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401
}
```
**Solution**: Ensure valid session token in `Authorization` header.

### Error: 400 Bad Request
```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "no paths provided"
}
```
**Solution**: Provide at least one path in `paths` array or let server choose (empty `paths`).

### Error: 429 Too Many Requests
```json
{
  "type": "about:blank",
  "title": "Rate Limited",
  "status": 429,
  "retry_after_seconds": 30
}
```
**Solution**: Wait `retry_after_seconds` before retrying. Cache assist responses to reduce requests.

### Error: 500 Internal Server Error
```json
{
  "type": "about:blank",
  "title": "Internal Server Error",
  "status": 500
}
```
**Solution**: Server-side issue. Check server logs. Retry with exponential backoff.

## Advanced: Custom Path Configuration

For specialized deployments (e.g., corporate networks, extreme censorship):

```javascript
const customAssist = await requestP2pAssist(serverUrl, token, {
  paths: [
    {
      address: 'corporate-proxy.example.com',
      port: 8443,
      server_name: 'mail.google.com', // Domain fronting
      priority: 0
    },
    {
      address: 'commucat.tech',
      port: 443,
      priority: 1,
      reality_fingerprint: 'a1b2c3d4...', // Reality obfuscation
      reality_pem: '-----BEGIN CERTIFICATE-----\n...'
    },
    {
      address: 'onion-bridge.tor',
      port: 9001,
      priority: 2
    }
  ],
  fec: {
    mtu: 1024, // Smaller MTU for restricted networks
    repair_overhead: 0.5 // Higher redundancy
  },
  min_paths: 1, // Accept single working path
  prefer_reality: true
});
```

## Performance Tips

1. **Parallel Requests**: Request assist for multiple peers simultaneously
2. **Cache Transports**: Reuse transport configurations for multiple connections
3. **Prefer Primary Path**: Use `multipath.primary_path` for best performance
4. **Monitor Metrics**: Use `transports[].latency` and `throughput` to select optimal paths
5. **FEC Tuning**: Adjust `fec.repair_overhead` based on network conditions:
   - Low loss networks: 0.2 - 0.3
   - Medium loss: 0.35 - 0.4
   - High loss: 0.5 - 0.7

## See Also

- [PROTOCOL.md](../PROTOCOL.md) - Protocol specification
- [SECURITY_ANALYSIS_DEVICES_USERS.md](SECURITY_ANALYSIS_DEVICES_USERS.md) - Security architecture
- [ARCHITECT.md](../ARCHITECT.md) - System architecture
- [CommuCat Server OpenAPI Spec](openapi-server.spec.yaml)
