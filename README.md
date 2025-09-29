# CommuCat Server 🐾

[![CI](https://github.com/ducheved/commucat/actions/workflows/ci.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/ci.yml)
[![Release](https://github.com/ducheved/commucat/actions/workflows/release.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/release.yml)
[![Deploy](https://github.com/ducheved/commucat/actions/workflows/deploy.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/deploy.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-orange.svg)](LICENSE)

> **Важно:** текущая реализация обеспечивает базовый Noise-туннель, хранение и ретрансляцию сообщений, а также серверное перекодирование RAW→Opus/VP8. Поддержка AV1/H264, обфускации, гибридных PQ-ключей и pluggable transports остаётся в статусе TODO. Полная спецификация — в [`PROTOCOL.md`](PROTOCOL.md).

---

## Сводка по компонентам

| Crate | Роль | Статус |
|-------|------|--------|
| `crates/server` | HTTP/2 сервер, REST API, Noise-туннель, SFU с перекодированием RAW→Opus/VP8 | Работает; нет микширования, PQ-гибрида, обфускации |
| `crates/proto` | CCP-1, управление звонками, capability negotiation, обфускация (черновик) | Работает для базовой схемы |
| `crates/media` | Кодеки Opus/VP8, транскодер PCM/I420→Opus/VP8, пайплайны | Используется сервером; AV1/H264/GPU возвращают `Unsupported` |
| `crates/media-types` | Общие типы кодеков/источников/приоритетов | Работает |
| `crates/crypto` | Noise XK/IK, сертификаты, вспомогательные PQ-функции | Работает; PQ-гибрид активен только в `/api/p2p/assist` |
| `crates/storage` | PostgreSQL/Redis доступ, миграции | Работает (требуются миграции) |
| `crates/federation` | Подписание междоменных событий | Реализовано, но не подключено к боевому потоку |
| `crates/ledger` | Аудит ключей устройств | Работает |
| `crates/cli` | Миграции, регистрация пользователей, ротация ключей, диагностика | Работает |

---

## Поток данных

1. **Клиент → Сервер**: TLS 1.3 (Pingora) → `POST /connect`.
2. **Handshake**: HTTP-обмен CCP-кадрами `HELLO/AUTH` (Noise XK/IK). Сервер проверяет профиль устройства, выполняет регистрацию и создаёт сессию.
3. **Фрейминг**: все сообщения кодируются в CCP-1 (`FrameType`, `channel_id`, `sequence`, payload). Лимиты: frame ≤ 16 MiB, JSON ≤ 256 KiB.
4. **Маршрутизация**: `JOIN` формирует `channel_routes`; `MSG`/`VOICE_FRAME`/`VIDEO_FRAME` ретранслируются активным участникам. Для оффлайн устройств кадры попадают в `relay_queue` (Postgres).
5. **Мультимедиа**:
   - Каждый медиакадр содержит 3-байтовый заголовок `(version, source, codec)`.
   - RAW аудио/видео (PCM/I420) автоматически перекодируются в Opus/VP8 на сервере.
   - Уже закодированные кадры идут транзитом.
6. **Хранилище**: PostgreSQL хранит пользователей, устройства, очереди сообщений, pairing-коды, ключи; Redis содержит presence.
7. **Telemetry**: `/metrics` отдаёт счётчики вызовов, транскодера, Noise/PQ операций. CLI `diagnose` выводит быстрый статус.

---

## Конфигурация

### Файл `commucat.toml`
```
[server]
bind = "0.0.0.0:9443"
domain = "commucat.local"
tls_cert = "certs/server.crt"
tls_key = "certs/server.key"
max_auto_devices_per_user = 5
connection_keepalive = 30

[storage]
postgres_dsn = "postgres://commucat:password@localhost/commucat"
redis_url = "redis://127.0.0.1:6379"

[crypto]
noise_private = "<hex32>"
noise_public  = "<hex32>"
federation_seed = "<hex64>"
prologue = "commucat"

[presence]
ttl_seconds = 60

[pairing]
ttl_seconds = 600

[admin]
token = "optional-manual-token"

[rotation.noise]
interval = 86400          # секунд
max_versions = 4

[rotation.admin]
enabled = true
interval = 604800
max_versions = 2

[rotation.device]
enabled = true
min_interval = 86400
proof_ttl = 600
notify_channel = 0

[transport.reality]
certificate_pem = "certs/reality.pem"
fingerprint = "0123..." # hex32
```

Все параметры можно переопределить через переменные окружения (см. `load_configuration`).

### Подготовка
1. Выполнить миграции: `commucat-cli migrate`.
2. Создать пользователя: `commucat-cli register-user <handle> [display_name] [avatar_url]`.
3. Выпустить ключ устройства (сертификат подписи): `commucat-cli rotate-keys --handle <handle>`.
4. Убедиться, что `noise_private`, `noise_public`, `federation_seed` указаны в конфиге.
5. Запустить `commucat-server --config commucat.toml`.

---

## Пользовательские команды CLI

| Команда | Назначение |
|---------|------------|
| `commucat-cli migrate` | Применить SQL миграции Postgres |
| `commucat-cli register-user <handle> [...]` | Создать профиль пользователя |
| `commucat-cli rotate-keys [--user <id> | --handle <handle>] [--device <id>]` | Выпустить новую пару ключей устройства и сертификат |
| `commucat-cli diagnose` | Быстрая диагностика (presence, сессии, очередь) |
| `commucat-cli call-simulate [frames]` | Синтетический прогон медиапайплайна Opus |

---

## Медиапайплайн

1. **Сигнализация** (`CALL_OFFER`/`CALL_ANSWER`/`CALL_END`): хранится в `call_sessions`. В профиле медиa (`CallMediaProfile`) фиксируются кодеки, разрешения и режим (`full_duplex`/`half_duplex`).
2. **Транскодер** (`CallMediaTranscoder`): при появлении RAW пакета,
   - аудио (PCM `i16`) → Opus (20 мс, mono/stereo);
   - видео (I420) → VP8 (libvpx, timebase = 1/frame_rate).
3. **Виды источников** (`MediaSourceMode`):
   - `encoded` — клиент уже прислал Opus/VP8 (пакет передаётся как есть);
   - `raw` — сервер перекодирует;
   - `hybrid` — зарезервировано под будущую адаптацию.
4. **Ограничения**: нет FEC, нет SVC, нет контроля битрейта. AV1/H264, GPU и capability renegotiation пока не реализованы.
5. **ICE/trickle**: `CallTransport` описывает кандидатов, ICE-креды и `consent_interval_secs`; incremental обновления летят через `FrameType::TransportUpdate`, сервер валидирует их, пишет в `CallSession.transport_updates` и подтверждает ACK с `call_id`/`update`.
6. **AV1**: при включённой фиче `media-av1` сервер транскодирует RAW I420 в AV1 (rav1e) и автоматически выбирает целевой кодек по `preferred_codecs`, откатываясь на VP8/VP9 для старых клиентов.

---

## Безопасность и ротация

- **Noise static ключи**: ротация по расписанию (`rotation.noise.interval`), поддерживаются одновременно несколько версий (grace-период `rotation.noise.grace`).
- **Админ-токен**: при включённой ротации генерируется новый токен, старые хранятся до истечения grace.
- **Ledger**: каждое изменение ключа устройства фиксируется (`DeviceKeyEvent`).
- **Device CSR авто-ротация**: авторизованные устройства вызывают `POST /api/device/csr`, сервер проверяет подпись нового ключа, выпускает сертификат и рассылает CCP `KeyUpdate` уведомление по каналу `rotation.device.notify_channel`.
- **Rate limiting**: HTTP, `/connect`, `/api/pair/claim` — отдельные лимиты (burst/window/penalty).
- **Presence**: Redis-записи обновляются при каждом heart-beat; при обрыве соединения сервер помечает устройство как offline и завершает звонки.

---

## Ограничения и TODO

- PQ-гибрид и adaptive obfuscation описаны, но не включены в основном туннеле.
- Pluggable transports (Reality/AmnesiaWG/Shadowsocks/Onion) — заглушки.
- AV1/H264, GPU, адаптивный битрейт и FEC в медиа — TODO.
- Нет автоматической повторной сигнализации при изменении профилей (capabilities используются только для Opus/VP8).
- Федерация событий ещё не используется в продакшене.
- REST API не имеет тонких ACL — защита только rate-limiter.

---

## Ссылки
- [Quick Start](docs/quickstart.md)
- [Подробная спецификация протокола](PROTOCOL.md)
- [Лицензия MPL-2.0](LICENSE)

Если при эксплуатации обнаружены несоответствия или недостающие функции, воспользуйтесь разделом TODO и откройте Issue/PR.
