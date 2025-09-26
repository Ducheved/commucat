# CommuCat Server 🐾

[![CI](https://github.com/ducheved/commucat/actions/workflows/ci.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/ci.yml)
[![Release](https://github.com/ducheved/commucat/actions/workflows/release.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/release.yml)
[![Deploy](https://github.com/ducheved/commucat/actions/workflows/deploy.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/deploy.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-orange.svg)](LICENSE)
[![Website](https://img.shields.io/badge/commucat.tech-live-blue?logo=firefox)](https://commucat.tech)

> **NOTE:** Компоненты ниже отражают текущее состояние репозитория. Всё, что находится в TODO, ещё не реализовано.

---

## 🇷🇺 Обзор

CommuCat — сервер маршрутизации защищённых сообщений. На практике реализованы:
- входящий HTTP/2-туннель на Pingora с Noise XK/IK (`crates/server::app::process_connect`);
- регистрация устройств, friends-list и REST API для pairing (`/api/pair`, `/api/friends`);
- офлайн-доставка через PostgreSQL/Redis (`relay_queue`, presence, session tokens);
- пассивная ретрансляция голосовых/видеокадров (сервер выступает как простой SFU без микширования и транскодинга);
- P2P assist, выдающий рекомендации по мультипутям и PQ-ключам.

### Криптография и трафик
- Noise `XK`/`IK` (ChaCha20-Poly1305 + BLAKE2s) с настраиваемым prologue — `crates/crypto::build_handshake`.
- Пост-квантовые примитивы доступны для P2P assist (`build_pq_advice`), но **не встроены** в основной туннель.
- Автоматическая ротация Noise static ключей и административного токена, с грациозной поддержкой предыдущих версий.
- Rate limiting для `/connect`, REST API и заявок на pairing-коды защищает от DoS.
- RaptorQ и MultipathTunnel используются для расчёта советов в `/api/p2p/assist`, а не для боевого трафика.
- Адаптивная обфускация присутствует только как библиотека (`proto/obfuscation`), сервер её не задействует.

### Компоненты и зависимости
| Модуль | Назначение | Библиотеки |
|--------|------------|------------|
| `crates/server` | HTTP/2 туннель, REST API, presence, ретрансляция | `pingora`, `tokio`, `tracing`, `commucat-*` |
| `crates/proto` | Кодеки CCP-1, черновик обфускатора | `serde`, `serde_json`, `rand` (опц.) |
| `crates/crypto` | Noise, сертификаты, PQ-инструменты для P2P assist | `snow`, `blake3`, `ml-kem`, `ml-dsa` |
| `crates/storage` | PostgreSQL + Redis | `tokio-postgres`, `redis`, `serde` |
| `crates/federation` | Подписание событий федерации | `ed25519-dalek`, `serde` |
| `crates/ledger` | Аудит устройств | `serde`, `chrono` |
| `crates/cli` | Миграции, диагностика | `commucat-storage`, `tokio` |

### Настройка
1. Скопируйте `.env.sample` → `.env`, заполните переменные Postgres/Redis/TLS/federation.
2. Отредактируйте `commucat.toml` (все разделы уже перечислены в шаблоне).
3. Сгенерируйте Noise static key и federation seed (`commucat-cli rotate-keys`).
4. Запустите миграции `commucat-cli migrate`, затем `commucat-server --config commucat.toml`.

### Проверка
```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
```
Основные тесты покрывают: кодек CCP-1, Noise, хранилище и вспомогательные структуры (`crates/*/tests`).

---

## TODO / Planned
- **Post-quantum гибрид в основном туннеле.** Сейчас ML-KEM/ML-DSA применяются только в советах P2P. Требуется расширить `process_handshake_frame`, внедрить negotiation `HELLO.capabilities` и использовать `HybridRatchet` при установке сессии.
- **Полноценные pluggable transports.** Реализации `Reality`, `AmnesiaWG`, `Shadowsocks`, `Onion` — заглушки на `tokio::io::duplex`. Нужно заменить на реальные рукопожатия и интегрировать их в медиа/сообщения.
- **Адаптивная обфускация.** Включить `proto/obfuscation` в серверный pipeline: принимать/производить `ObfuscatedPacket`, синхронизировать ключи с клиентами.
- **RaptorQ multipath для сообщений.** Сейчас FEC рассчитывается лишь в `/api/p2p/assist`. Требуется подключить `MultipathTunnel` к реальному трафику и реализовать доставку по нескольким путям.
