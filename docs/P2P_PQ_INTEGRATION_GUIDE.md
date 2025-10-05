# CommuCat P2P & Post-Quantum Integration Guide

_Версия: 1.3.0_  
_Дата: 2025-10-05_

Данное руководство описывает как клиенты могут подключиться к новым возможностям CommuCat: Post-Quantum криптографии и P2P NAT traversal с ICE/TURN.

---

## 📋 Содержание

1. [Обзор новых возможностей](#обзор-новых-возможностей)
2. [Discovery: Проверка возможностей сервера](#discovery-проверка-возможностей-сервера)
3. [P2P Assist: Получение параметров соединения](#p2p-assist-получение-параметров-соединения)
4. [Post-Quantum Handshake](#post-quantum-handshake)
5. [ICE/TURN NAT Traversal](#iceturn-nat-traversal)
6. [Примеры запросов](#примеры-запросов)
7. [Troubleshooting](#troubleshooting)

---

## 🚀 Обзор новых возможностей

### Post-Quantum Криптография (PQ)

CommuCat поддерживает гибридный handshake комбинирующий:
- **Classical**: X25519 (ECDH) + Noise протокол
- **Post-Quantum**: ML-KEM-768 (CRYSTALS-Kyber) + ML-DSA-65 (CRYSTALS-Dilithium)

**Преимущества:**
- ✅ Защита от атак квантовых компьютеров будущего
- ✅ Обратная совместимость (если PQ не доступен, используется только classical)
- ✅ Forward secrecy с hybrid ratcheting

### P2P NAT Traversal

- **ICE-lite**: Lightweight ICE implementation для прямых P2P соединений
- **TURN**: Relay сервера для случаев когда прямое соединение невозможно
- **STUN**: Определение публичного адреса за NAT
- **Multipath FEC**: RaptorQ forward error correction для надёжности

---

## 🔍 Discovery: Проверка возможностей сервера

### Endpoint: `GET /api/server-info`

**Описание:** Возвращает конфигурацию сервера, включая PQ возможности.

**Request:**
```http
GET /api/server-info HTTP/1.1
Host: commucat.example.org
```

**Response:**
```json
{
  "domain": "commucat.example.org",
  "noise_public": "a1b2c3d4...",
  "noise_keys": [
    {
      "version": 1,
      "public": "a1b2c3d4...",
      "valid_after": "2025-10-01T00:00:00Z",
      "rotates_at": "2025-10-08T00:00:00Z",
      "expires_at": "2025-10-15T00:00:00Z"
    }
  ],
  "device_ca_public": "5e6f7g8h...",
  "supported_patterns": ["XK", "IK"],
  "supported_versions": [1, 2],
  "session": {
    "ttl_seconds": 60,
    "keepalive_interval": 30
  },
  "presence": {
    "ttl_seconds": 30
  },
  "device_rotation": {
    "enabled": true,
    "min_interval_seconds": 86400,
    "proof_ttl_seconds": 600
  },
  "pairing": {
    "auto_approve": false,
    "pairing_ttl": 300,
    "max_auto_devices": 1
  },
  "post_quantum": {
    "enabled": true,
    "kem_algorithm": "ML-KEM-768",
    "signature_algorithm": "ML-DSA-65",
    "kem_public_hex": "9a0b1c2d3e4f..."
  }
}
```

**Ключевые поля:**

| Поле | Тип | Описание |
|------|-----|----------|
| `post_quantum.enabled` | boolean | Поддерживает ли сервер PQ крипто |
| `post_quantum.kem_algorithm` | string | Алгоритм обмена ключами (ML-KEM-768) |
| `post_quantum.signature_algorithm` | string | Алгоритм подписи (ML-DSA-65) |
| `post_quantum.kem_public_hex` | string | Публичный KEM ключ сервера (hex) |

**Логика клиента:**
```python
response = requests.get("https://commucat.example.org/api/server-info")
server_info = response.json()

# Проверка поддержки PQ
if server_info.get("post_quantum", {}).get("enabled", False):
    print("✅ Сервер поддерживает Post-Quantum криптографию")
    kem_public = bytes.fromhex(server_info["post_quantum"]["kem_public_hex"])
    # Использовать гибридный handshake
else:
    print("⚠️  Сервер использует только классическую криптографию")
    # Fallback на Noise XK/IK
```

---

## 🤝 P2P Assist: Получение параметров соединения

### Endpoint: `GET /api/p2p/assist` или `POST /api/p2p/assist`

**Описание:** Возвращает параметры для установления P2P соединения между клиентами.

### GET Request (без параметров)

**Простейший вызов для получения дефолтных параметров:**

```http
GET /api/p2p/assist HTTP/1.1
Host: commucat.example.org
```

**Response структура:**
```json
{
  "noise": { ... },
  "pq": { ... },
  "ice": { ... },
  "transports": [ ... ],
  "multipath": { ... },
  "obfuscation": { ... },
  "security": { ... }
}
```

### POST Request (с кастомными параметрами)

**Request Body:**
```json
{
  "peer_hint": "peer-device-id-abc123",
  "paths": [
    {
      "address": "relay.example.org",
      "port": 443,
      "id": "path-primary",
      "server_name": "relay.example.org",
      "priority": 0
    }
  ],
  "prefer_reality": true,
  "fec": {
    "mtu": 1152,
    "repair_overhead": 0.35
  },
  "min_paths": 2
}
```

**Параметры:**

| Поле | Тип | Обязательно | Описание |
|------|-----|-------------|----------|
| `peer_hint` | string | Нет | ID устройства пира (для оптимизации) |
| `paths` | array | Нет | Список возможных путей соединения |
| `prefer_reality` | boolean | Нет | Предпочитать Reality transport (обфускация) |
| `fec.mtu` | number | Нет | MTU для FEC пакетов (default: 1152) |
| `fec.repair_overhead` | float | Нет | Overhead repair пакетов (default: 0.35) |
| `min_paths` | number | Нет | Минимум путей для multipath (default: 2) |

### Response детально

#### 1. **Noise Advice** (Classical Crypto)

```json
"noise": {
  "pattern": "Xk",
  "prologue_hex": "636f6d6d75636174",
  "device_seed_hex": "a1b2c3d4e5f6...",
  "static_public_hex": "9a8b7c6d5e4f..."
}
```

- `pattern`: Noise handshake pattern (XK = responder identity известен)
- `prologue`: Context-binding data для handshake
- `device_seed_hex`: Ephemeral seed для генерации ключей
- `static_public_hex`: Публичный X25519 ключ устройства

#### 2. **PQ Advice** (Post-Quantum Crypto) — опциональный

```json
"pq": {
  "identity_public_hex": "",
  "signed_prekey_public_hex": "",
  "kem_public_hex": "5a6b7c8d9e0f1a2b3c4d5e6f...",
  "signature_public_hex": ""
}
```

⚠️ **Важно:** 
- Если поле `pq` отсутствует или `null`, сервер **НЕ** поддерживает PQ
- `kem_public_hex` — публичный ML-KEM-768 ключ для encapsulation
- Пустые поля (`identity_public_hex`, etc.) заполняются клиентом при полном PQXDH

#### 3. **ICE Advice** (NAT Traversal)

```json
"ice": {
  "username_fragment": "a1b2c3d4e5f6g7h8",
  "password": "9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c0d1e2f3g4h5i6j7k8l9m0",
  "ttl_secs": 600,
  "keepalive_interval_secs": 30,
  "trickle": true,
  "servers": [
    {
      "urls": ["turn:turn.example.org:3478", "turns:turn.example.org:5349"],
      "username": "1730800000:a1b2c3d4e5f6g7h8",
      "credential": "base64-encoded-hmac-sha1",
      "ttl_secs": 600,
      "expires_at": "2025-10-05T12:00:00Z",
      "realm": "commucat"
    }
  ],
  "lite_candidates": [
    {
      "candidate": "candidate:a1b2c3d4 1 udp 2130706431 203.0.113.42 3478 typ host generation 0",
      "component": 1,
      "protocol": "udp",
      "foundation": "a1b2c3d4",
      "priority": 2130706431,
      "ip": "203.0.113.42",
      "port": 3478,
      "typ": "host"
    }
  ],
  "expires_at": "2025-10-05T12:10:00Z"
}
```

**Ключевые моменты:**

- **Username/Password**: ICE credentials для STUN/TURN аутентификации
- **TTL**: Время жизни credentials (обычно 10 минут)
- **TURN servers**: 
  - `username` формат: `<unix_timestamp>:<ufrag>` для time-limited auth
  - `credential`: HMAC-SHA1(secret, username) в base64
  - `expires_at`: RFC3339 timestamp когда credentials истекут
- **ICE-lite candidates**: Pre-configured server-reflexive candidates
- **Trickle**: Включён incremental candidate discovery

#### 4. **Transports** (Пути соединения)

```json
"transports": [
  {
    "path_id": "path-primary",
    "transport": "websocket",
    "resistance": "basic",
    "latency": "low",
    "throughput": "high"
  }
]
```

Типы транспортов:
- `websocket` — WebSocket over TLS
- `reality` — Reality obfuscation (TLS fingerprinting resistant)
- `shadowsocks` — Shadowsocks proxy
- `quic-masque` — QUIC with MASQUE tunneling
- `dns` — DNS tunneling (extreme censorship)

#### 5. **Multipath** (FEC параметры)

```json
"multipath": {
  "fec_mtu": 1152,
  "fec_overhead": 0.35,
  "primary_path": "path-primary",
  "sample_segments": {
    "path-primary": {
      "total": 10,
      "repair": 3
    }
  }
}
```

- `fec_mtu`: Максимальный размер FEC сегмента
- `fec_overhead`: Процент repair пакетов (35% = на 10 data пакетов 3.5 repair)
- `sample_segments`: Тестовые данные о распределении пакетов

#### 6. **Obfuscation** (Resistance capabilities)

```json
"obfuscation": {
  "reality_fingerprint_hex": "3a4b5c6d7e8f9a0b...",
  "domain_fronting": false,
  "protocol_mimicry": true,
  "tor_bridge": false
}
```

#### 7. **Security** (Current server metrics)

```json
"security": {
  "noise_handshakes": 1234,
  "pq_handshakes": 567,
  "zkp_proofs": 890,
  "noise_rotations": 2,
  "uptime_seconds": 3600,
  "censorship_deflections": 5
}
```

---

## 🔐 Post-Quantum Handshake

### Hybrid Handshake Flow

```
Client                                    Server
  |                                         |
  | 1. GET /api/server-info                |
  |---------------------------------------> |
  |    {post_quantum: {enabled: true, ...}}|
  | <---------------------------------------| 
  |                                         |
  | 2. Generate ML-KEM-768 keypair         |
  |    (ek, dk) = MlKem768.keygen()        |
  |                                         |
  | 3. GET /api/p2p/assist                 |
  |---------------------------------------> |
  |    {pq: {kem_public_hex: "..."}, ...}  |
  | <---------------------------------------| 
  |                                         |
  | 4. Encapsulate                         |
  |    (ct, ss_client) = encapsulate(ek)   |
  |                                         |
  | 5. Noise handshake init                |
  |    + ML-KEM ciphertext in payload      |
  |---------------------------------------> |
  |                                         |
  |                                         | 6. Decapsulate
  |                                         |    ss_server = decapsulate(dk, ct)
  |                                         | 7. Hybrid KDF
  |                                         |    session_key = KDF(
  |                                         |      noise_dh || ml_kem_ss
  |                                         |    )
  |                                         |
  |    Encrypted session established       |
  | <======================================>|
```

### Код примера (Python псевдокод)

```python
from ml_kem import MlKem768
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# 1. Получить server PQ public key
server_info = get_server_info()
server_kem_public = bytes.fromhex(server_info["post_quantum"]["kem_public_hex"])

# 2. Encapsulate (клиент)
ek = MlKem768.decode_encapsulation_key(server_kem_public)
ciphertext, shared_secret_client = ek.encapsulate()

# 3. Noise handshake
noise_handshake = NoiseConnection.begin_session(
    pattern="XK",
    initiator=True,
    prologue=b"commucat",
    s=local_device_keypair
)

# Первое сообщение Noise + ML-KEM ciphertext
noise_msg1 = noise_handshake.write_message(b"")
hybrid_msg1 = noise_msg1 + ciphertext

# Отправить на сервер
send_to_server(hybrid_msg1)

# 4. Получить ответ сервера
noise_msg2 = receive_from_server()
noise_handshake.read_message(noise_msg2)

# 5. Derive hybrid session keys
classical_secret = noise_handshake.get_handshake_hash()
hybrid_material = classical_secret + shared_secret_client

kdf = HKDF(
    algorithm=hashes.SHA3_512(),
    length=96,  # 32*3 для root + send + recv
    salt=None,
    info=b"commucat.hybrid.session.v1"
)
key_material = kdf.derive(hybrid_material)

root_key = key_material[0:32]
sending_chain = key_material[32:64]
receiving_chain = key_material[64:96]

# Готово! Используем session keys для шифрования
```

---

## 🌐 ICE/TURN NAT Traversal

### Полный P2P Connection Flow

```
Client A                  CommuCat Server              Client B
   |                            |                          |
   | 1. GET /api/p2p/assist     |                          |
   |--------------------------->|                          |
   |    ICE credentials         |                          |
   |<---------------------------|                          |
   |                            |                          |
   |                            | 2. GET /api/p2p/assist   |
   |                            |<-------------------------|
   |                            |    ICE credentials       |
   |                            |------------------------->|
   |                            |                          |
   | 3. STUN Binding Request    |                          |
   |--------------------------->| (ICE-lite UDP:3478)      |
   |    XOR-MAPPED-ADDRESS      |                          |
   |<---------------------------|                          |
   |                            |                          |
   | 4. Exchange ICE candidates via signaling channel       |
   |<===========================================================>|
   |                            |                          |
   | 5a. Direct P2P (если возможно)                        |
   |<=========================================================>|
   |                            |                          |
   | 5b. TURN Relay (если NAT symmetric/firewall)          |
   |                            |                          |
   | TURN Allocate              |                          |
   |--------------------------->| (TURN server)            |
   |    Relayed address         |                          |
   |<---------------------------|                          |
   |                            |                          |
   | Data via TURN relay        |                          |
   |--------------------------->|------------------------->|
   |<---------------------------|<-------------------------|
```

### STUN Binding Example

```python
import socket
import struct
import hmac
import hashlib

def send_stun_binding(ice_ufrag, ice_pwd, server_addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # STUN Binding Request
    msg_type = 0x0001  # Binding Request
    magic_cookie = 0x2112A442
    txid = os.urandom(12)
    
    # Build message
    header = struct.pack('!HHI', msg_type, 0, magic_cookie) + txid
    
    # USERNAME attribute
    username = ice_ufrag.encode()
    username_attr = struct.pack('!HH', 0x0006, len(username)) + username
    
    # Padding to 4-byte boundary
    padding = (4 - (len(username) % 4)) % 4
    username_attr += b'\x00' * padding
    
    message = header + username_attr
    
    # Update length
    length = len(message) - 20
    message = struct.pack('!HHI', msg_type, length, magic_cookie) + txid + username_attr
    
    # Send
    sock.sendto(message, server_addr)
    
    # Receive response
    data, addr = sock.recvfrom(1024)
    
    # Parse XOR-MAPPED-ADDRESS
    # ... (см. RFC 5389)
    
    return parse_xor_mapped_address(data)
```

### TURN Allocation Example

```python
import requests
import base64
import time

def allocate_turn_relay(turn_servers, ice_ufrag, ice_pwd):
    # Выбираем первый TURN server
    server = turn_servers[0]
    turn_url = server["urls"][0]  # "turn:turn.example.org:3478"
    
    # Time-limited credentials
    timestamp = int(time.time()) + 600  # 10 минут
    username = f"{timestamp}:{ice_ufrag}"
    
    # HMAC-SHA1 credential
    secret = "your-turn-secret"  # из конфига сервера
    credential = base64.b64encode(
        hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    ).decode()
    
    # TURN REST API или native TURN protocol
    # Для простоты покажем REST-like подход
    
    response = requests.post(
        f"https://{turn_url}/allocate",
        json={
            "username": username,
            "credential": credential,
            "lifetime": 600
        }
    )
    
    relay_address = response.json()["relayed_address"]
    return relay_address
```

---

## 📝 Примеры запросов

### cURL

#### Проверка PQ поддержки
```bash
curl -X GET https://commucat.example.org/api/server-info \
  -H "Accept: application/json" | jq '.post_quantum'
```

**Ожидаемый ответ:**
```json
{
  "enabled": true,
  "kem_algorithm": "ML-KEM-768",
  "signature_algorithm": "ML-DSA-65",
  "kem_public_hex": "5a6b7c8d..."
}
```

#### Получение P2P assist (дефолтные параметры)
```bash
curl -X GET https://commucat.example.org/api/p2p/assist \
  -H "Accept: application/json" | jq '.'
```

#### Получение P2P assist (кастомные параметры)
```bash
curl -X POST https://commucat.example.org/api/p2p/assist \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "prefer_reality": true,
    "min_paths": 2,
    "fec": {
      "mtu": 1200,
      "repair_overhead": 0.4
    }
  }' | jq '.'
```

### Python (requests)

```python
import requests

# 1. Проверка PQ
response = requests.get("https://commucat.example.org/api/server-info")
server_info = response.json()

pq_enabled = server_info.get("post_quantum", {}).get("enabled", False)
print(f"PQ Enabled: {pq_enabled}")

if pq_enabled:
    kem_public = bytes.fromhex(server_info["post_quantum"]["kem_public_hex"])
    print(f"Server KEM public key: {len(kem_public)} bytes")

# 2. P2P Assist
assist_response = requests.post(
    "https://commucat.example.org/api/p2p/assist",
    json={
        "prefer_reality": True,
        "min_paths": 2
    }
)
assist_data = assist_response.json()

# Извлечение ICE credentials
ice = assist_data["ice"]
print(f"ICE username: {ice['username_fragment']}")
print(f"ICE expires: {ice['expires_at']}")
print(f"TURN servers: {len(ice['servers'])}")

# Извлечение PQ advice (если есть)
if "pq" in assist_data and assist_data["pq"]:
    pq = assist_data["pq"]
    print(f"PQ KEM public: {pq['kem_public_hex'][:32]}...")
else:
    print("PQ не предоставлен (используется classical only)")
```

### JavaScript (fetch)

```javascript
// 1. Проверка PQ
async function checkPqSupport() {
  const response = await fetch('https://commucat.example.org/api/server-info');
  const serverInfo = await response.json();
  
  if (serverInfo.post_quantum?.enabled) {
    console.log('✅ Post-Quantum enabled');
    console.log(`KEM: ${serverInfo.post_quantum.kem_algorithm}`);
    console.log(`Signature: ${serverInfo.post_quantum.signature_algorithm}`);
    return true;
  }
  console.log('⚠️  Classical crypto only');
  return false;
}

// 2. P2P Assist
async function getP2pAssist() {
  const response = await fetch('https://commucat.example.org/api/p2p/assist', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      prefer_reality: true,
      min_paths: 2,
      fec: {
        mtu: 1152,
        repair_overhead: 0.35
      }
    })
  });
  
  const data = await response.json();
  
  // ICE credentials
  console.log('ICE credentials:', {
    username: data.ice.username_fragment,
    password: data.ice.password.substring(0, 16) + '...',
    expiresAt: data.ice.expires_at
  });
  
  // TURN servers
  data.ice.servers.forEach(server => {
    console.log(`TURN: ${server.urls[0]}`);
    console.log(`  Username: ${server.username}`);
    console.log(`  Expires: ${server.expires_at}`);
  });
  
  // PQ advice
  if (data.pq) {
    console.log('PQ KEM public:', data.pq.kem_public_hex.substring(0, 32) + '...');
  }
  
  return data;
}

// Использование
(async () => {
  const pqSupported = await checkPqSupport();
  const assistData = await getP2pAssist();
  
  // Дальнейшее установление P2P соединения...
})();
```

---

## 🔧 Troubleshooting

### Проблема: `/api/p2p/assist` возвращает 500 ошибку

**Причины:**
1. ❌ PQ не настроен в конфигурации сервера
2. ❌ Transport manager не может установить paths
3. ❌ Ошибка генерации ключей

**Решение:**

1. **Проверьте конфигурацию сервера** (`commucat.toml`):
```toml
[crypto]
# Опционально: добавьте PQ ключи для полной поддержки
# Если не указано, PQ advice будет пропущен (это OK)
# pq_kem_public = "hex_encoded_public_key"
# pq_kem_secret = "hex_encoded_secret_key"
```

2. **Проверьте логи сервера:**
```bash
tail -f /var/log/commucat/server.log | jq 'select(.level == "ERROR")'
```

3. **Тест минимального запроса:**
```bash
curl -v https://commucat.example.org/api/p2p/assist
```

Если возвращается 500, проверьте response body для `application/problem+json`:
```json
{
  "type": "about:blank",
  "title": "Internal Server Error",
  "status": 500,
  "detail": "transport establishment failed",
  "trace_id": "abc123..."
}
```

### Проблема: PQ advice всегда пустой

**Симптомы:**
```json
{
  "pq": null
}
```
или поле `pq` отсутствует.

**Причина:** Сервер не настроен для PQ.

**Решение:**

1. **Проверьте `/api/server-info`:**
```bash
curl https://commucat.example.org/api/server-info | jq '.post_quantum'
```

Если `enabled: false` или `null`, значит PQ не активирован.

2. **Активация PQ на сервере:**

Добавьте в `commucat.toml`:
```toml
[crypto]
# Генерация ключей (выполните один раз):
# cargo run --bin commucat-cli generate-pq-keys > pq_keys.txt
pq_kem_public = "a1b2c3d4e5f6..."
pq_kem_secret = "9a8b7c6d5e4f..."
```

3. **Перезапустите сервер:**
```bash
systemctl restart commucat
```

4. **Проверьте снова:**
```bash
curl https://commucat.example.org/api/server-info | jq '.post_quantum.enabled'
# Должно вернуть: true
```

### Проблема: ICE candidates пустые

**Симптомы:**
```json
{
  "ice": {
    "lite_candidates": []
  }
}
```

**Причина:** ICE-lite не настроен или не запущен.

**Решение:**

1. **Проверьте конфигурацию:**
```toml
[ice]
lite_enabled = true
lite_bind = "0.0.0.0:3478"
lite_public_address = "203.0.113.42:3478"  # Ваш публичный IP
```

2. **Проверьте UDP порт открыт:**
```bash
netstat -ulnp | grep 3478
# Должно показать: commucat-server listening на UDP:3478
```

3. **Firewall rules:**
```bash
# Allow UDP 3478 (STUN)
ufw allow 3478/udp

# Проверка
nc -u -l 3478  # Слушаем UDP
nc -u 203.0.113.42 3478  # Отправка с другой машины
```

### Проблема: TURN credentials истекают слишком быстро

**Симптомы:**
- Соединение обрывается через 10 минут
- Ошибка `401 Unauthorized` при TURN allocation

**Причина:** TTL credentials короткий (по умолчанию 600 секунд).

**Решение:**

1. **Увеличьте TTL в конфиге:**
```toml
[ice]
turn_ttl = 3600  # 1 час
```

2. **Refresh credentials перед истечением:**
```python
import time

ice_advice = get_p2p_assist()
expires_at = datetime.fromisoformat(ice_advice["ice"]["expires_at"])

# Refresh за 1 минуту до истечения
while True:
    now = datetime.now(timezone.utc)
    time_until_expiry = (expires_at - now).total_seconds()
    
    if time_until_expiry < 60:
        # Refresh
        ice_advice = get_p2p_assist()
        expires_at = datetime.fromisoformat(ice_advice["ice"]["expires_at"])
    
    time.sleep(30)
```

### Проблема: Multipath FEC не работает

**Симптомы:**
- `sample_segments` пустой
- Нет repair пакетов

**Причина:** Недостаточно paths или ошибка transport manager.

**Решение:**

1. **Указывайте минимум 2 пути:**
```json
{
  "min_paths": 2,
  "paths": [
    {"address": "relay1.example.org", "port": 443},
    {"address": "relay2.example.org", "port": 443}
  ]
}
```

2. **Проверьте логи:**
```bash
journalctl -u commucat -f | grep "multipath"
```

3. **Проверьте метрики:**
```bash
curl https://commucat.example.org/metrics | grep multipath
```

---

## 📚 Дополнительные ресурсы

### Документация
- **PROTOCOL.md** — Спецификация CCP-1 протокола
- **P2P_ARCHITECTURE_OVERVIEW.md** — Архитектура P2P системы
- **P2P_ASSIST_CLIENT_GUIDE.md** — Детальный гайд для клиентских разработчиков
- **TRANSPORT_IMPLEMENTATION_STATUS.md** — Статус транспортов

### Спецификации
- [RFC 8489 - STUN](https://datatracker.ietf.org/doc/html/rfc8489)
- [RFC 8656 - TURN](https://datatracker.ietf.org/doc/html/rfc8656)
- [RFC 8445 - ICE](https://datatracker.ietf.org/doc/html/rfc8445)
- [ML-KEM FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [Noise Protocol Framework](https://noiseprotocol.org/)

### Инструменты для тестирования

**STUN/TURN тесты:**
```bash
# Проверка STUN
stunclient 203.0.113.42:3478

# Проверка TURN
turnutils_uclient -v -u username -w password turn.example.org
```

**PQ крипто тесты:**
```python
from ml_kem import MlKem768

# Генерация тестовых ключей
dk, ek = MlKem768.generate()
print(f"Encapsulation key size: {len(ek.as_bytes())} bytes")
print(f"Decapsulation key size: {len(dk.as_bytes())} bytes")

# Тест encapsulation
ct, ss1 = ek.encapsulate()
ss2 = dk.decapsulate(ct)
assert ss1 == ss2
print("✅ ML-KEM-768 test passed")
```

---

## ✅ Checklist для интеграции

### Минимальная интеграция (Classical only)

- [ ] Реализовать `/api/server-info` парсинг
- [ ] Проверять `post_quantum.enabled` для feature detection
- [ ] Реализовать Noise XK/IK handshake
- [ ] Вызывать `/api/p2p/assist` для получения ICE credentials
- [ ] Реализовать STUN binding для NAT discovery
- [ ] Опционально: TURN fallback для symmetric NAT

### Полная интеграция (PQ + P2P)

- [ ] Минимальная интеграция ✓
- [ ] Добавить ML-KEM-768 библиотеку (`ml-kem` crate или аналог)
- [ ] Реализовать hybrid handshake (Classical + PQ)
- [ ] Парсить `pq` advice из `/api/p2p/assist`
- [ ] Encapsulate с server KEM public key
- [ ] Отправлять ciphertext в Noise handshake payload
- [ ] Derive session keys с hybrid material (Classical DH + ML-KEM SS)
- [ ] Реализовать ICE candidate exchange
- [ ] Multipath FEC (RaptorQ) для надёжности
- [ ] Handling credential expiration и refresh

### Production Checklist

- [ ] Логирование всех PQ/P2P событий
- [ ] Метрики (handshake success/failure, NAT traversal stats)
- [ ] Graceful fallback если PQ недоступен
- [ ] Graceful fallback если P2P не работает (relay через сервер)
- [ ] Unit tests для PQ handshake
- [ ] Integration tests для ICE/TURN
- [ ] Load testing (сколько одновременных P2P сессий)
- [ ] Security audit (PQ implementation, credential handling)

---

## 🎯 Заключение

CommuCat предоставляет современный набор возможностей для защищённой P2P коммуникации:

1. **Post-Quantum готовность** — защита от квантовых угроз уже сегодня
2. **Flexible NAT traversal** — работает даже за самыми строгими NAT/firewall
3. **Automatic fallback** — если что-то не работает, система автоматически использует альтернативы
4. **Production-ready** — все API продуманы для real-world использования

**Начните с простого:**
1. `GET /api/server-info` — узнайте возможности
2. `GET /api/p2p/assist` — получите параметры
3. Установите соединение используя полученные данные

**Upgrade постепенно:**
- Classical → Classical + PQ
- Direct → Direct + TURN
- Single path → Multipath FEC

Если возникают вопросы, проверьте **Troubleshooting** раздел или откройте issue в [GitHub репозитории](https://github.com/ducheved/commucat).

Happy coding! 🚀
