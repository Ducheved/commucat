# CommuCat Connect Modes Troubleshooting

## Overview

The `/connect` endpoint supports **4 connection modes**:
1. **Binary** (default) - Raw binary frames over HTTP/2
2. **SSE** - Server-Sent Events (text/event-stream)
3. **LongPoll** - HTTP long polling (JSON-RPC style)
4. **WebSocket** - Full-duplex WebSocket connection

## Mode Detection Logic

The server detects the connection mode in this order:

### 1. Query Parameter (Highest Priority)
```
POST /connect?mode=sse
POST /connect?transport=websocket
POST /connect?mode=long-poll
```

Supported values:
- `mode=binary` or `mode=stream` → Binary
- `mode=sse`, `mode=event-stream`, `mode=eventstream` → SSE
- `mode=long-poll`, `mode=longpoll`, `mode=poll` → LongPoll
- `mode=websocket` or `mode=ws` → WebSocket

### 2. Custom Headers
```
X-Connect-Mode: sse
X-CommuCat-Connect-Mode: websocket
```

### 3. Standard Headers
- **WebSocket**: `Upgrade: websocket` + `Connection: upgrade` → WebSocket mode
- **SSE**: `Accept: text/event-stream` → SSE mode

### 4. Default
If none of the above match → **Binary** mode

## SSE (Server-Sent Events) Issues

### ❌ Common Problem: Client gets Binary instead of SSE

**Symptom:**
```javascript
// Client expects SSE:
const evtSource = new EventSource('/connect');

// But server sends binary data
```

**Root Causes:**

#### 1. Wrong HTTP Method

**❌ Wrong (GET):**
```javascript
const evtSource = new EventSource('/connect'); // Uses GET
```

**✅ Correct (POST):**
```javascript
fetch('/connect?mode=sse', {
  method: 'POST',
  headers: {
    'Accept': 'text/event-stream',
    'Cache-Control': 'no-cache'
  }
});
```

**Note:** Native `EventSource` API only supports GET! Use custom implementation or query parameter.

#### 2. Missing Accept Header

**❌ Wrong:**
```javascript
fetch('/connect', { method: 'POST' });
// Server defaults to Binary mode
```

**✅ Correct:**
```javascript
fetch('/connect', {
  method: 'POST',
  headers: { 'Accept': 'text/event-stream' }
});
```

#### 3. Not Using Query Parameter

**✅ Best approach (explicit):**
```javascript
fetch('/connect?mode=sse', {
  method: 'POST',
  headers: { 'Accept': 'text/event-stream' }
});
```

### SSE Response Format

**Server sends:**
```
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-store
Connection: keep-alive
X-CommuCat-Connect-Mode: sse

:ready

event: frame
id: 1
data: <base64-encoded-frame>

event: frame
id: 2
data: <base64-encoded-frame>

```

**Client parsing:**
```javascript
const response = await fetch('/connect?mode=sse', {
  method: 'POST',
  headers: { 'Accept': 'text/event-stream' }
});

const reader = response.body.getReader();
const decoder = new TextDecoder();
let buffer = '';

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  
  buffer += decoder.decode(value, { stream: true });
  
  // Parse SSE messages
  const lines = buffer.split('\n\n');
  buffer = lines.pop(); // Keep incomplete message
  
  for (const message of lines) {
    if (message.startsWith(':')) continue; // Comment (e.g., :ready)
    
    const eventMatch = message.match(/^event: (.+)$/m);
    const idMatch = message.match(/^id: (.+)$/m);
    const dataMatch = message.match(/^data: (.+)$/m);
    
    if (dataMatch) {
      const base64Data = dataMatch[1];
      const frameData = atob(base64Data); // Decode base64
      // Process frame...
    }
  }
}
```

## WebSocket Issues

### ❌ Common Problem: 404 Not Found

**Symptom:**
```javascript
const ws = new WebSocket('wss://commucat.tech/connect');
// Error: WebSocket connection failed (404)
```

**Root Cause:** WebSocket requires **GET** method, but server only accepts `/connect` with **POST** (before fix).

**✅ Fixed in commit:** Changed `/connect` to accept both GET and POST methods.

**Correct WebSocket connection:**
```javascript
// WebSocket automatically uses GET with Upgrade header
const ws = new WebSocket('wss://commucat.tech/connect');

ws.onopen = () => {
  console.log('WebSocket connected');
};

ws.onmessage = (event) => {
  // Binary frame data
  const frame = parseFrame(event.data);
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};
```

**Alternative: Explicit mode via query:**
```javascript
const ws = new WebSocket('wss://commucat.tech/connect?mode=websocket');
```

### WebSocket Handshake Headers

**Client sends:**
```
GET /connect HTTP/1.1
Host: commucat.tech
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

**Server responds:**
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

## LongPoll Issues

### ❌ Common Problem: Connection hangs

**Symptom:**
```javascript
const response = await fetch('/connect?mode=long-poll', {
  method: 'POST'
});
// Request never completes
```

**Root Cause:** LongPoll keeps connection open until data arrives or timeout.

**✅ Correct usage:**
```javascript
async function longPollLoop() {
  while (true) {
    try {
      const response = await fetch('/connect?mode=long-poll', {
        method: 'POST',
        signal: AbortSignal.timeout(30000) // 30s timeout
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log('Received:', data);
        // Process data...
      }
    } catch (error) {
      if (error.name === 'TimeoutError') {
        // Normal - retry
        continue;
      }
      console.error('LongPoll error:', error);
      await new Promise(r => setTimeout(r, 1000)); // Wait before retry
    }
  }
}

longPollLoop();
```

**LongPoll response format:**
```json
{
  "channel": 0,
  "sequence": 1,
  "type": "Msg",
  "data": "<base64-encoded-payload>"
}
```

## Binary Mode Issues

### ❌ Common Problem: Cannot parse frames

**Symptom:**
```javascript
const response = await fetch('/connect', { method: 'POST' });
const data = await response.arrayBuffer();
// How to parse binary frame?
```

**Solution:** Binary mode uses CommuCat Frame Protocol encoding.

**Frame structure:**
```
[4 bytes: length prefix (big-endian u32)]
[length bytes: protobuf-encoded frame]
```

**Parsing:**
```javascript
const response = await fetch('/connect', { method: 'POST' });
const reader = response.body.getReader();
let buffer = new Uint8Array(0);

while (true) {
  const { done, value } = await reader.read();
  if (done) break;
  
  // Append to buffer
  const newBuffer = new Uint8Array(buffer.length + value.length);
  newBuffer.set(buffer);
  newBuffer.set(value, buffer.length);
  buffer = newBuffer;
  
  // Parse frames
  while (buffer.length >= 4) {
    const view = new DataView(buffer.buffer);
    const frameLength = view.getUint32(0, false); // Big-endian
    
    if (buffer.length < 4 + frameLength) break; // Incomplete frame
    
    const frameData = buffer.slice(4, 4 + frameLength);
    buffer = buffer.slice(4 + frameLength);
    
    // Decode frame (requires protobuf decoder)
    const frame = decodeFrame(frameData);
    console.log('Frame:', frame);
  }
}
```

## Debugging Tips

### 1. Check Server Logs

Look for connection mode detection:
```
INFO connect channel opened remote_addr=... mode=sse
INFO connect channel opened remote_addr=... mode=websocket
INFO connect channel opened remote_addr=... mode=binary
```

### 2. Check Response Headers

```bash
curl -X POST https://commucat.tech/connect?mode=sse -v
# Look for:
# < Content-Type: text/event-stream
# < X-CommuCat-Connect-Mode: sse
```

### 3. Browser DevTools

**Network tab:**
- Check request method (GET/POST)
- Check request headers (Accept, Upgrade, etc.)
- Check response headers (Content-Type)
- Check response body format

### 4. Test with curl

**SSE:**
```bash
curl -X POST 'https://commucat.tech/connect?mode=sse' \
  -H 'Accept: text/event-stream' \
  --no-buffer
```

**WebSocket:**
```bash
websocat wss://commucat.tech/connect
```

**LongPoll:**
```bash
curl -X POST 'https://commucat.tech/connect?mode=long-poll' \
  -H 'Content-Type: application/json'
```

## Best Practices

### 1. Always Use Query Parameter

Most reliable method:
```javascript
// ✅ Explicit mode
const url = '/connect?mode=sse';
const url = '/connect?mode=websocket';
const url = '/connect?mode=long-poll';
```

### 2. Set Correct Headers

```javascript
// For SSE:
headers: {
  'Accept': 'text/event-stream',
  'Cache-Control': 'no-cache'
}

// For LongPoll:
headers: {
  'Content-Type': 'application/json'
}

// For WebSocket: handled automatically by WebSocket API
```

### 3. Handle Reconnection

```javascript
async function connectWithRetry(mode, maxRetries = 5) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(`/connect?mode=${mode}`, {
        method: 'POST',
        headers: getHeadersForMode(mode)
      });
      
      if (response.ok) {
        return response;
      }
      
      console.warn(`Connection attempt ${i + 1} failed`);
    } catch (error) {
      console.error(`Connection error:`, error);
    }
    
    // Exponential backoff
    await new Promise(r => setTimeout(r, Math.pow(2, i) * 1000));
  }
  
  throw new Error('Max retries exceeded');
}
```

### 4. Respect Keepalive


## Summary

| Mode | Method | Headers | Best For |
|------|--------|---------|----------|
| **Binary** | POST | (none) | High performance, raw frames |
| **SSE** | POST | `Accept: text/event-stream` | Server→Client streaming |
| **LongPoll** | POST | `Content-Type: application/json` | Firewall-restricted networks |
| **WebSocket** | GET | `Upgrade: websocket` | Real-time bidirectional |

**Key Takeaway:** Always use query parameter (`?mode=...`) for explicit mode selection!

## TODO / Pending Work

- **CLI engine parity**: implement ConnectMode-aware reader/writer stacks for SSE, long-poll, and WebSocket in `commucat-cli-client` (currently only binary works).
- **WebSocket handshake**: reuse TLS connector + `tokio-tungstenite` so `/connect?mode=websocket` works end-to-end in the CLI.
- **Streaming decoders**: add incremental SSE / NDJSON frame decoding helpers (base64 + framing) shared between engine and tests.
- **TUI affordances**: surface mode selection in the UI, show active mode, and allow quick switching; redesign layout with friend list sidebar and handle search.
- **Regression tests**: add integration tests or fixtures for each mode (server + CLI) and document expected request / response snapshots.
- **Docs**: update quickstart/README once client-side support ships, including examples per mode and known limitations.

## See Also

- [PROTOCOL.md](../PROTOCOL.md) - Frame protocol specification
- [CLIENT_SESSION_EXPIRED_401.md](CLIENT_SESSION_EXPIRED_401.md) - Session keepalive guide
- [P2P_ASSIST_CLIENT_GUIDE.md](P2P_ASSIST_CLIENT_GUIDE.md) - P2P connection guide
