# CommuCat Server 🐾

[![CI](https://github.com/ducheved/commucat/actions/workflows/ci.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/ci.yml)
[![Release](https://github.com/ducheved/commucat/actions/workflows/release.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/release.yml)
[![Deploy](https://github.com/ducheved/commucat/actions/workflows/deploy.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/deploy.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-orange.svg)](LICENSE)

CommuCat — экспериментальный сервер защищённых звонков и сообщений. Он завершает TLS 1.3 (через [Pingora](https://github.com/cloudflare/pingora)), разворачивает Noise-туннель CCP‑1 и маршрутизирует медиаканалы между устройствами. Код ориентирован на прототипирование безопасной маршрутизации: проверка устройств, ротация ключей, трансляция медиапотоков и подготовка к федерации доменов.

> ⚠️ **Проект ещё не готов для продакшена.** Альтернативные транспорты, антицензура, PQ-гибрид по умолчанию, capability renegotiation и операционный контур находятся в разработке. Ознакомьтесь с ограничениями и дорожной картой прежде чем планировать деплой.

---

## Назначение и поток

1. **Подключение клиента.** Клиент устанавливает TLS 1.3 (сертификат из `commucat.toml`), выполняет `POST /connect` и проходит Noise XK/IK handshake. На этом этапе сервер:
   - валидирует Zero-Knowledge доказательство владения устройством (`commucat_crypto::zkp`),
   - при необходимости создаёт профиль пользователя и устройство,
   - выдаёт сертификат устройства и публикует Presence в Redis,
   - возвращает активные Noise static ключи и сведения о ротации.
2. **Фрейминг CCP‑1.** Все сообщения — кадры `Frame` (TIP: `crates/proto`). Сервер гарантирует монотонный `sequence`, ACK для управляющих событий и оффлайн-доставку через Postgres.
3. **Маршрутизация.** Каналы (`JOIN/LEAVE`) описывают адресатов. Онлайн-участники получают сообщения через Web stream, оффлайн — через `relay_queue` (Postgres). Для групп используется `chat_group` и `group_member`.
4. **Звонки и медиа.** Модуль `app::media` перекодирует RAW PCM/I420 в Opus/VP8. Кодек выбирается по профилю `CallMediaProfile`; поддержка AV1/H.264 пока опциональна и ограничена.
5. **Идентичность и аудит.** Ротация Noise ключей/админ-токена (`SecretManager`) хранится в Postgres, журналируется через адаптеры Ledger. CLI покрывает миграции, регистрацию и выдачу сертификатов.
6. **Операционный контур.** `/healthz`, `/readyz` и `/metrics` представлены, но наблюдаемость ограничена агрегированными счётчиками; trace-id и глубокие метрики не реализованы.

---

## Workspace и роли крейтов

| Crate | Назначение | Ключевые элементы |
|-------|------------|-------------------|
| `crates/server` | Основной бинарь: TLS+HTTP/2, Noise handshake, REST API, CCP‑1 маршрутизация, медиатранскодер, ротация ключей | Pingora HTTP/2, `app::CommuCatApp`, `SecretManager`, `CallMediaTranscoder`, pluggable `TransportManager` (mock) |
| `crates/proto` | Фрейминг CCP‑1, структуры звонков, валидация payload | Varint-кодек, JSON control envelopes, эксперименты с обфускацией |
| `crates/media` | Кодеки Opus/VP8, I420↔encoded конвейер, опциональный захват аудио | `VoiceEncoder/Decoder`, `VideoEncoder`, адаптеры к `commucat-media-types` |
| `crates/media-types` | Общие enum/descriptor медиа-профилей | `AudioCodec`, `VideoCodec`, `MediaSourceMode`, capability структуры |
| `crates/crypto` | Noise XK/IK, сертификаты устройств, EventSigner, ZKP, PQ-хелперы | `DeviceKeyPair`, `EventSigner/Verifier`, `PqxdhBundle` (feature `pq`) |
| `crates/storage` | DAL к Postgres/Redis, миграции, presence, pairing, relay | Таблицы `app_user`, `user_device`, `relay_queue`, `server_secret`; Redis `presence:*`, `route:*` |
| `crates/federation` | Подпись и верификация междоменных событий | `FederationEvent`, `sign_event`, `verify_event` |
| `crates/ledger` | Адаптеры журнала (Null/File/Debug) | Экспорт digest в JSON/файл/`tracing` |
| `crates/cli` | Операционный CLI: миграции, регистрация, ротация ключей, диагностика, медиасимулятор | Команды `migrate`, `register-user`, `rotate-keys`, `diagnose`, `call-simulate` |

Дополнительные материалы: [архитектурный аудит](ARCHITECT.md), [спецификация CCP‑1](PROTOCOL.md), [дорожная карта](ROADMAP.md), [актуальный TODO](docs/todo.md).

---

## Основные возможности

- **Безопасное подключение.** Noise XK/IK поверх TLS 1.3, выдача сертификатов устройств, ротация Noise static ключей и админ-токена.
- **Профили пользователей и устройств.** Postgres хранит пользователи, устройства, pairing-коды, журнал смен ключей; Redis служит для presence и маршрутизации.
- **CCP‑1 каналы.** Поддержка управляющих кадров (`JOIN/LEAVE/CALL_*`), сообщений (`MSG/TYPING`), уведомлений о ключах (`KEY_UPDATE`), оффлайн-доставки и групповых чатов.
- **Медиатранспорт.** Сервер перекодирует RAW PCM → Opus и RAW I420 → VP8, поддерживает ограниченный транзит VP8/Vp9, собирает CallStats и транспортные обновления.
- **P2P assist.** `/api/p2p/assist` выдаёт рекомендации по Noise/PQ ключам, ICE-параметрам, мультипут/FEC и (пока) mock-транспортам.
- **Синхронизация устройств друзей.** `PUT /api/friends` и `GET /api/friends/{user_id}/devices` сразу возвращают публичные ключи, статусы и метки ротации устройств доверенных контактов.
- **Федерация.** Очередь `federation_outbox`, периодический диспетчер и входящая точка `/federation/events` позволяют доставлять фреймы между доменами с проверкой подписи.
- **CLI для эксплуатации.** Миграции, регистрация, ротация ключей (с печатью закрытого ключа — прототип!), диагностика presence и медиапайплайна.

---

## Ограничения и риски

- **Транспорты.** Reality/AmnesiaWG/Shadowsocks/VLESS/Onion и анти-DPI пока реализованы как заглушки. Фактический трафик идёт исключительно через основной Pingora-поток.
- **PQ-гибрид.** В основном туннеле выключен; экспериментальный код доступен только в соло-сценариях (`/api/p2p/assist`).
- **Наблюдаемость.** Нет `trace_id/span_id`, ProblemDetails используются точечно, метрики агрегированные. Требуются улучшения по RFC 9457 и OpenTelemetry.
- **Хранилище.** PostgreSQL и Redis используются без пулов подключений; CLI и сервер выполняют блокирующие вызовы внутри async-контекста.
- **CLI безопасность.** Команда `rotate-keys` выводит приватные ключи в stdout; нет RBAC и валидации ввода.
- **Медиа.** Нет адаптивного битрейта, FEC/SVC в прод-пути, H.264/AV1 включаются опционально и не покрыты тестами.

Подробности и предложения по исправлению см. в [ARCHITECT.md](ARCHITECT.md).

---

## Конфигурация

- Основной файл: [`commucat.toml`](commucat.toml). Все параметры доступны через переменные окружения `COMMUCAT_*` (см. `crates/server/src/config.rs`).
- Критичные ключи:
  - `server.bind`, `server.domain`, `server.tls_cert`, `server.tls_key`;
  - `storage.postgres_dsn`, `storage.redis_url`;
  - `crypto.noise_private`, `crypto.noise_public`, `crypto.federation_seed` (hex);
  - `rotation.*`, `limits.*`, `transport.reality_*` при использовании Reality.
- Пример сервиса — `docs/systemd/commucat.service` (пользователь `commucat`, sandboxing systemd).

Быстрый старт описан в [`docs/quickstart.md`](docs/quickstart.md) (обновляется по roadmap 1.2).

---

## CLI команды

| Команда | Назначение |
|---------|------------|
| `commucat-cli migrate` | Применение SQL миграций Postgres (таблицы пользователей, устройств, relay, секретов, федерации). |
| `commucat-cli register-user <handle> [display_name] [avatar_url]` | Создание профиля пользователя. Учётные данные выводятся в stdout. |
| `commucat-cli rotate-keys (--user <id> | --handle <handle>) [--device <id>]` | Генерация пары ключей устройства и сертификата; результат печатается (включая приватный ключ). |
| `commucat-cli diagnose` | Создание тестового профиля/устройства `diagnose`, публикация presence и сессии. |
| `commucat-cli call-simulate [frames]` | Прогон медиапайплайна Opus (кодирование/декодирование synthetic PCM). |

> ℹ️ CLI использует те же DSN/URL, что и сервер (`COMMUCAT_PG_DSN`, `COMMUCAT_REDIS_URL`, `COMMUCAT_FEDERATION_SEED`).

---

## Работа с репозиторием

```bash
# форматирование и проверки
cargo fmt --all
cargo clippy --all-targets --all-features

# сборка бинарей
cargo build --workspace --release

# тесты по крейту (пример)
cargo test -p commucat-proto
```

Некоторые модульные тесты в `crates/storage` требуют внешних сервисов (`COMMUCAT_TEST_PG_DSN`, `COMMUCAT_TEST_REDIS_URL`). Без них тесты пропускаются.

---

## Дальнейшие шаги

- Следите за прогрессом в [ROADMAP.md](ROADMAP.md) и обновляемой таблице [docs/todo.md](docs/todo.md).
- Для предложений и багрепортов открывайте issue/PR в GitHub или пишите на team@commucat.tech.

Если обнаружите расхождение между документацией и реализацией — обновите соответствующий `.md` файл или откройте заявку: мы стремимся к честному описанию текущего состояния прототипа.
