# Спецификация CommuCat CCP-1 (редакция 2024-10)

Документ описывает всю транспортную и сервисную архитектуру CommuCat, а также состояние реализованных и запланированных компонентов. Все примеры приведены на основе актуального исходного кода из каталога `h:\commucat`.

## 1. Архитектура репозитория

| Crate | Назначение | Реализация | Ограничения/заглушки |
|-------|------------|------------|-----------------------|
| `crates/server` | Основное приложение (HTTP/2, Noise-туннель, REST, SFU) | Работает | Нет медиамикшера, нет PQ-гибрида, нет обфускации, AV1/H264 не поддерживаются |
| `crates/proto` | CCP-1: кадры, сериализация, структуры звонков, черновик обфускации | Работает | Capability-поля расширены, но сервер использует только профиль Opus/VP8 |
| `crates/media` | Кодеки и пайплайны (Opus/VP8, RAW PCM/I420) | Используется сервером для перекодирования RAW→Opus/VP8 | Бэкенды AV1/H264/GPU возвращают `MediaError::Unsupported` |
| `crates/media-types` | Общие enum/descriptor для кодеков | Работает | - |
| `crates/crypto` | Noise XK/IK, сертификаты устройств, PQ-хелперы | Работает | PQ-гибрид применяется только в `/api/p2p/assist` |
| `crates/storage` | PostgreSQL + Redis (профили, presence, relay-очередь, pairing) | Работает | Требует предварительных миграций |
| `crates/federation` | Подпись междоменных событий | Работает | Реальная федерация пока не включена |
| `crates/ledger` | Аудит ключей устройств | Работает | - |
| `crates/cli` | Служебные команды: миграции, регистрация пользователя, ротация ключей, диагностика | Работает | Использует те же DSN/URL, что сервер |

## 2. Конфигурация и запуск

### 2.1 Файл `commucat.toml`
Минимальные ключи (секция `server`):
```
[server]
bind = "0.0.0.0:9443"
domain = "commucat.local"
tls_cert = "certs/server.crt"
tls_key = "certs/server.key"

[storage]
postgres_dsn = "postgres://..."
redis_url = "redis://localhost:6379"

[crypto]
noise_private = "<hex32>"
noise_public = "<hex32>"
federation_seed = "<hex64>"
prologue = "commucat"

[admin]
token = "optional-manual-token"

[presence]
ttl_seconds = 60

[pairing]
ttl_seconds = 600

[server]
max_auto_devices_per_user = 5
connection_keepalive = 30
```

Любой ключ может быть переопределён переменными окружения (см. `load_configuration`):
- `COMMUCAT_BIND`, `COMMUCAT_TLS_CERT`, `COMMUCAT_TLS_KEY`
- `COMMUCAT_PG_DSN`, `COMMUCAT_REDIS_URL`, `COMMUCAT_DOMAIN`
- `COMMUCAT_NOISE_PRIVATE`, `COMMUCAT_NOISE_PUBLIC`, `COMMUCAT_FEDERATION_SEED`
- `COMMUCAT_ADMIN_TOKEN`, `COMMUCAT_NOISE_PROLOGUE`

### 2.2 Ротация секретов
`SecretManager` (`crates/server/src/security/secrets.rs`) управляет:
- Noise static key (с интервалом `rotation.noise.interval`).
- Административным токеном (если `rotation.admin.enabled = true`).
Ротация хранится в таблицах Postgres, поддерживаются несколько версий, grace-период задаётся в конфиге.

CLI команда `commucat-cli rotate-keys [--user <id>|--handle <handle>] [--device <id>]`:
1. Генерирует новый ключ устройства (`DeviceKeyPair`).
2. Выпускает сертификат с помощью `commucat_crypto::EventSigner` (сертификат действует 30 дней).
3. Записывает событие в Postgres/ledger.

### 2.3 Миграции и регистрация пользователей
- `commucat-cli migrate` — применяет SQL миграции.
- `commucat-cli register-user <handle> [display_name] [avatar_url]` — создаёт профиль пользователя.

## 3. Хранилища и фоновые задачи

| Компонент | Назначение |
|-----------|------------|
| PostgreSQL (`Storage`) | `users`, `devices`, `relay_queue`, `session`, `group_member`, `pairing_code`, `device_key_event`, `admin_token`, `noise_key`, `federation_peer` |
| Redis | Presence (`presence:{device}`), кеш друзей |
| `call_sessions` (в памяти) | Активные звонки: участники, профиль медиа, статистика |
| `media_transcoders` (в памяти) | Транскодеры Opus/VP8 для текущих звонков |
| Фоновые задачи | миграция pairing-кодов, транспортные пробы, ротация секретов |

## 4. Транспортный слой

### 4.1 HTTP/TLS
- Сервер построен на Pingora, слушает `bind` (TLS 1.3).
- Для обслуживания веб-страницы `/` возвращает статический landing page.
- `POST /connect` — основной долгоживущий поток, используемый CCP-1.
- Keep-alive отправляется каждые `connection_keepalive` секунд.

### 4.2 Rate limiting (`security::limiter`)
- Три зоны: HTTP (REST), CONNECT, pairing-claim.
- Параметры считываются из `RateLimitConfig` (burst, window, penalty).
- При превышении сервер отвечает 429 + `retry-after`.

### 4.3 Noise туннель
Handshake реализован в `app::handle_session`:
1. Клиент отправляет `HELLO` (`FrameType::Hello`) с полями:
   - `pattern`: `XK` или `IK`.
   - `device_id` / статический ключ устройства.
   - `supported_versions` (по умолчанию `[1]`).
   - `user` (создание/привязка профиля).
   - `capabilities` — массив строк (например, `"media.raw-audio"`).
2. Сервер отвечает `AUTH` с:
   - `session` (идентификатор подключения),
   - `server_static`,
   - `protocol_version`,
   - `accepted_capabilities` (фактически `["media.opus","media.vp8"]`).
3. Клиент завершает Noise (`AUTH` с третьим сообщением).
4. Сервер отправляет `ACK {"handshake":"ok", ...}`.

> **Ограничения:**
> - PQ-гибрид (`pq-hybrid`) и адаптивная обфускация проигнорированы.
> - Проверка capability сводится к записи в лог, медиапрофили выбираются статически.

## 5. Протокол CCP-1

### 5.1 Кадры
```
frame        = frame_len (varint) || frame_body
frame_body   = frame_type (u8) || channel_id (varint) || sequence (varint) || payload_len (varint) || payload
```
Ограничения: `frame_len ≤ 16 MiB`, JSON ≤ 256 KiB, `channel_id`/`sequence ≤ 2^32-1`.

### 5.2 Типы кадров
- Управляющие: `HELLO`, `AUTH`, `JOIN`, `LEAVE`, `ACK`, `ERROR`, `CALL_*`, `PRESENCE`, `CALL_STATS`, `TRANSPORT_UPDATE`.
- Контент: `MSG`, `TYPING`, `KEY_UPDATE`, `GROUP_EVENT`, `VOICE_FRAME`, `VIDEO_FRAME`.

`FramePayload::Control` содержит JSON (serde), `FramePayload::Opaque` — произвольные байты.

### 5.3 ACK/Sequencing
- Каждое приложение ведёт локальный `sequence` (u32). Сервер проверяет монотонность.
- На каждое входящее сообщение сервер отвечает `ACK` с `{"ack": <sequence>}`.
- Для `TRANSPORT_UPDATE` дополнительно возвращаются `call_id` и `update` (`candidate`, `selected_candidate_pair`, `consent_keepalive`).

### 5.4 Ошибки
`ERROR` следует [RFC 9457]. Типичные ошибки: `Invalid Frame Type`, `Protocol Version Mismatch`, `PairingRequired`, `Varint Overflow`, `Frame Too Large`.

## 6. Обработка каналов и сообщений

- `JOIN`: обновляет `channel_routes` (список участников, `relay` flag).
- `LEAVE`: удаляет участника; при пустом канале сервер чистит `channel_routes`.
- `KEY_UPDATE`: JSON-уведомление, рассылаемое сервером при выпуске нового сертификата устройства. Поля: `type` (`"device-key-rotated"`), `rotation_id`, `event_id`, `public_key`, `old_public_key`, `certificate`, `issued_at`, `expires_at`.

### Device Key Rotation Service

Устройства могут запускать ротацию собственных ключей без участия оператора:

1. Авторизованный клиент отправляет `POST /api/device/csr` с JSON:
   ```json
   {
     "public_key": "<hex32>",
     "signature": "<hex64>",
     "expires_at": "2025-09-27T12:00:00Z",
     "nonce": "<hex16...>"
   }
   ```
2. `signature` — Ed25519-подпись текущим ключом устройства от сообщения
   ```
   blake3("commucat:device-rotation:v1" || device_id || new_public_key || expires_at || nonce)
   ```
   где `new_public_key` и `nonce` представлены в бинарном виде.
3. Сервер проверяет минимальный интервал (`rotation.device.min_interval`), валидирует подпись, хранит событие в `device_rotation_audit`, выпускает сертификат и записывает его в Ledger.
4. HTTP-ответ содержит новый сертификат и метаданные (`rotation_id`, `event_id`).
5. Если устройство онлайн, сервер отправляет CCP `KeyUpdate` кадр на канал `rotation.device.notify_channel` (по умолчанию `0`). Оффлайн-устройства получают уведомление при следующем подключении в виде релэй-контента.
- `MSG` (и аналогичные) ретранслируются во все активные подключения (`broadcast_frame`).
- Оффлайн-клиентам кадры сохраняются в `relay_queue` (Postgres) c новым `sequence`.

### Presence
- Каждое подключение публикует `PRESENCE {"state":"online"}`.
- Сервер записывает `PresenceSnapshot` в Redis, TTL задаётся конфигом.
- При обрыве соединения состояние переводится в `offline` и активные звонки завершаются.

## 7. Звонки и медиа

### 7.1 Сигнализация
- `CALL_OFFER`: создаёт `CallSession` (канал, инициатор, профиль медиа, участники), запускает транскодер (`ensure_call_transcoder`).
- `CALL_ANSWER`: добавляет устройство в `accepted`, при необходимости обновляет профиль медиа (`update_call_transcoder`).
- `CALL_END`: удаляет `CallSession`, останавливает транскодер, пишет событие в метрики.
- `CALL_STATS`: сохраняются в `session.stats` без автоматической обратной связи.

### 7.2 Формат медиа-пакета
Каждый `VOICE_FRAME`/`VIDEO_FRAME` имеет 3-байтовый заголовок:
```
byte 0: версия (сейчас 1)
byte 1: источник (MediaSourceMode — 0 encoded, 1 raw, 2 hybrid)
byte 2: кодек (AudioCodec либо VideoCodec)
```
Дальше следует полезная нагрузка:
- RAW аудио — PCM `i16` (20 мс, mono/stereo по профилю).
- RAW видео — I420 (Y plane, затем U, V).
- Закодированное аудио — Opus пакет.
- Закодированное видео — VP8 кадр.

### 7.3 Серверное транскодирование
`media::CallMediaTranscoder` хранит опциональные энкодеры Opus/VP8.
- При получении RAW пакета выполняется перекодирование и пакет заменяется на закодированную версию.
- Уже закодированные пакеты проходят транзитом.
- Для видео используется libvpx (`VideoEncoder`/`VideoDecoder`). AV1/H264 отсутствуют.
- Состояние транскодера помещено в `Arc<Mutex<...>>`, связанное с `call_id`.
- Ошибки кодека конвертируются в `ServerError::Codec` (кадр отбрасывается, пишется warning).

### 7.4 Ограничения
- Нет адаптивного битрейта, нет SVC, нет FEC.
- `MediaSourceMode::Hybrid` пока не имеет особенной логики.
- Сервер не выполняет синхронизацию RTP/таймингов — только монотонный `sequence`.

### 7.5 ICE и trickle-кандидаты
- `CallTransport` теперь содержит `candidates` (расширенные ICE-кандидаты с `foundation`, `component`, `priority`, `candidate_type`, `related_*`, `tcp_type`, `sdp_mid`, `sdp_mline_index`, `url`), `ice_credentials` (`username_fragment`, `password`, `expires_at`), флаг `trickle` и `consent_interval_secs` (рекомендуемый интервал STUN Binding-запросов).
- Пример фрагмента `CallOffer`/`CallAnswer`:
  ```json
  {
    "transport": {
      "prefer_relay": false,
      "trickle": true,
      "consent_interval_secs": 20,
      "ice_credentials": {
        "username_fragment": "1f2e3d4c5b6a",
        "password": "4e39d8...",
        "expires_at": 1700000600
      },
      "candidates": [
        {
          "address": "198.51.100.12",
          "port": 60000,
          "protocol": "udp",
          "foundation": "f1",
          "component": 1,
          "priority": 12345678,
          "candidate_type": "srflx",
          "related_address": "10.0.0.5",
          "related_port": 52333,
          "sdp_mid": "0",
          "sdp_mline_index": 0
        }
      ],
      "fingerprints": ["sha-256 01:23:..." ]
    }
  }
  ```
- При включённой фиче `media-av1` сервер транскодирует RAW I420 в AV1 (rav1e) и возвращает VP8/VP9 при отсутствии пересечения `preferred_codecs`.
- Для incremental ICE используется `FrameType::TransportUpdate` (`CallTransportUpdate`). Сервер принимает JSON вида:
  ```json
  {"update":"candidate","call_id":"call-xyz","candidate":{...}}
  {"update":"selected_candidate_pair","call_id":"call-xyz","local":{...},"remote":{...},"rtt_ms":22}
  {"update":"consent_keepalive","call_id":"call-xyz","interval_secs":20}
  ```
  Проверяется принадлежность устройства звонку, обновляется `CallSession.transport_updates`, и в ответ приходит `ACK` с `{"ack":<seq>,"call_id":"call-xyz","update":"candidate"}`.
- Метрики фиксируют количество кандидатов (`commucat_transport_candidates`), выбор пар (`commucat_transport_pairs`) и keepalive-события (`commucat_transport_keepalive`).

## 8. P2P assist и дополнительные сервисы

### 8.1 `POST /api/p2p/assist`
Возвращает
- рекомендации по Noise/PQ ключам (черновик для прямых каналов),
- ICE-блок (`ice`): `username_fragment`, `password`, `ttl_secs`, `keepalive_interval_secs`, флаг `trickle`.
- список транспортов (TOR/Reality/AmnesiaWG/Shadowsocks) — сейчас заглушки, базируются на `tokio::io::duplex`.
- параметры FEC/Multi-path (только аналитика).

> Реальные туннели должны реализовать клиенты. Сервер лишь выдаёт конфигурацию.

### 8.2 Pluggable transports
`TransportManager` содержит приоритеты и health-метрики, но единственный реально используемый путь — TLS-туннель Pingora. Остальные транспорты — заглушки и применяются только в диагностических заданиях.

## 9. Безопасность и аудит

- **SecretManager**: хранит активные и будущие Noise ключи, админ-токены; выполняет ротацию и удаление просроченных записей (`prune_noise`, `prune_admin`).
- **Ledger**: записывает события изменения ключей (`DeviceKeyEvent`), интегрируется через `LedgerAdapter` (Null/File/Debug).
- **Metrics**: `Metrics` фиксирует количество подключений, медиа-кадров, успешных/завершённых звонков, ротаций и т.п. Экспортируются через `/metrics` (Prometheus).
- **CLI diagnose**: собирает сводную информацию (присутствие, очереди, счётчики).

## 10. Ограничения и TODO

1. **PQ-гибрид** — handshake описан, но в HTTP-туннеле capability игнорируется. Реально используется только в `/api/p2p/assist`.
2. **Адаптивная обфускация** — код `commucat_proto::obfuscation` не задействован сервером.
3. **Медиа** — только Opus/VP8. AV1/H264, GPU, SVC, FEC и автоматический renegotiation профилей не реализованы.
4. **Transport** — альтернативные транспорты (Reality/AmnesiaWG/Onion) заглушечные.
5. **Федерация** — события подписываются, но пересылка между доменами пока выключена.
6. **REST API** — защита только rate-limiter; finer-grained ACL отсутствуют.
7. **Ключи пользователей** — ротация через CLI, автоматического плана нет.
8. **Тесты** — есть unit-тесты на кодек, транскодер, storage, но отсутствие end-to-end.

## 11. Рекомендации по эксплуатации

1. Выполнить `commucat-cli migrate` на подготовленной базе.
2. Создать пользователя (`register-user`) и устройство (`rotate-keys`).
3. Сконфигурировать TLS и Noise ключи, разместить `commucat.toml` и запустить `commucat-server`.
4. Следить за `/metrics` и журналами (`commucat_security_*`, `commucat_call_*`).
5. Периодически запускать `rotate-keys` и чистить устаревшие pairing-коды.
6. Для медиаклиентов: отправлять либо готовые Opus/VP8, либо RAW (PCM/I420) в соответствии с описанным заголовком; в ответ можно ориентироваться на `CALL_STATS`.

---

*Последнее обновление: октябрь 2024. Если компонент помечен как заглушка, его необходимо доработать перед продакшн-развёртыванием.*
