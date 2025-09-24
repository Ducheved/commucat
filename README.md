# CommuCat Server 🐾

[![CI](https://github.com/ducheved/commucat/actions/workflows/ci.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/ci.yml)
[![Release](https://github.com/ducheved/commucat/actions/workflows/release.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/release.yml)
[![Deploy](https://github.com/ducheved/commucat/actions/workflows/deploy.yml/badge.svg)](https://github.com/ducheved/commucat/actions/workflows/deploy.yml)
[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-orange.svg)](LICENSE)

[![Website](https://img.shields.io/badge/commucat.tech-live-blue?logo=firefox)](https://commucat.tech)
[![Contact](https://img.shields.io/badge/Ducheved-me%40ducheved.ru-6f42c1?logo=minutemailer)](mailto:me@ducheved.ru)

> ❝Свободны как кошки!❞ CommuCat — минималистичный маршрутизатор для end-to-end зашифрованных чатов: Noise XK/IK поверх TLS 1.3, HTTP/2 стримы Pingora, федерация между доменами, Postgres/Redis и zero-PII политика.

---

## 🚀 Быстрое знакомство
- Центральный README → **этот файл**.
- Подробная спецификация протокола → [`docs/PROTOCOL.md`](docs/PROTOCOL.md).
- Архитектура, гайды, TODO → [`docs/SERVER_GUIDE.md`](docs/SERVER_GUIDE.md).
- История задач и рекомендации → [`ACat.md`](ACat.md).
- Клиентский CLI (UI) → [репозиторий `commucat-cli-client`](https://github.com/ducheved/commucat-cli-client).

---

## 📦 Структура проекта
```
commucat/
├── crates/
│   ├── server/        # бинарник CommuCat (Pingora, маршрутизация)
│   ├── cli/           # админ-команды (migrate, rotate-keys, diagnose)
│   ├── proto/         # CCP-1 кодек (crates.io)
│   ├── crypto/        # Noise/Ed25519 helper-ы (crates.io)
│   ├── federation/    # подпись и обработка S2S событий (crates.io)
│   ├── storage/       # Postgres + Redis слой (crates.io)
│   └── ledger/        # адаптеры для внешних ledger (null/debug/file)
├── migrations/        # SQL-миграции
├── certs/             # dev TLS материалы (самоподписанные)
├── commucat.toml      # пример конфигурации
├── .env.sample        # переменные окружения
├── docs/              # расширенные руководства
├── ACat.md            # хроника и планы
└── README.md          # вы здесь
```

Подробные схемы и диаграммы ищите в [`docs/SERVER_GUIDE.md`](docs/SERVER_GUIDE.md#архитектура).

---

## 🔧 Требования
| Компонент | Минимум | Примечание |
|-----------|---------|------------|
| Rust      | 1.75    | `rustup toolchain install stable`
| PostgreSQL| 12 (рекомендуем 17) | база для сессий и relay
| Redis     | 6       | presence, маршруты
| OpenSSL   | 1.1+    | генерация TLS (или certbot)
| systemd   | 245+    | рекомендуемый способ запуска

В проде также потребуется reverse proxy (например, nginx) для вынесения HTTP → HTTPS/HTTP2.

---

## ⚙️ Конфигурация (кратко)
- Все параметры доступны из `commucat.toml` и переменных окружения (см. `.env.sample`).
- Ключевые блоки конфигурации:
  - `[server]` — bind адрес, домен, TLS файлы, keepalive.
  - `[storage]` — DSN PostgreSQL, URL Redis.
  - `[crypto]` — Noise private/public, federation seed.
  - `[federation]` — список доверенных пиров.
  - `[ledger]` — null / debug / file адаптер.
  - `[limits]` — TTL presence/relay.
- Убедитесь, что `server.domain` совпадает с CN/SAN сертификата.

См. подробности в [`docs/SERVER_GUIDE.md`](docs/SERVER_GUIDE.md#конфигурация).

---

## 📚 Основные шаги развёртывания
1. Подготовьте инфраструктуру: PostgreSQL, Redis, TLS сертификат.
2. Клонируйте репо, скопируйте `.env.sample` → `.env`, отредактируйте.
3. `cargo build --release`.
4. `source .env && ./target/release/commucat-cli migrate`.
5. Настройте `commucat.toml` / переменные окружения.
6. Запустите `commucat-server` напрямую или через systemd unit (пример в `docs/SERVER_GUIDE.md#systemd`).
7. Поднимите клиент (см. [CLI README](https://github.com/ducheved/commucat-cli-client#readme)) и протестируйте соединение.

---

## 🛰️ Федерация и ledger
- Настройка пиров, подпись событий и обработка очередей описаны в [`docs/SERVER_GUIDE.md#федерация`](docs/SERVER_GUIDE.md#федерация).
- Адаптеры ledger (null/debug/file) описаны в [`docs/SERVER_GUIDE.md#ledger`](docs/SERVER_GUIDE.md#ledger).

---

## ⚙️ CI/CD
- `ci.yml` — fmt + clippy + test + doc.
- `release.yml` — версионирование `1.0.<git_count>`, публикация crates на crates.io, сборка и выкладка артефакта `commucat-server-linux-amd64.tar.gz`.
- `deploy.yml` — сборка на runner, доставка бинаря на bare-metal сервер под юзером `commucat`, `systemctl restart commucat`.

С подробностями и секретами ознакомьтесь в [`ACat.md`](ACat.md#требуемые-секретыпеременные).

---

## ❓ Частые проблемы
| Симптом | Решение |
|---------|---------|
| `tcp connect failed` | Убедитесь, что сервер слушает IPv6 или используйте IPv4 (`https://127.0.0.1:8443`).
| `tls connect failed` | Проверьте CN/SAN сертификата и доверие (`--tls-ca` для самоподписанного). |
| `handshake rejected` | Добавьте ключ устройства через `commucat-cli rotate-keys`; проверьте `user_device`. |
| `storage failure` | Проверить PostgreSQL/Redis; строки подключения. |
| `federation failure` | Актуализируйте `federation.peers`, убедитесь в доступности HTTPS.

Больше сценариев в [`docs/SERVER_GUIDE.md#troubleshooting`](docs/SERVER_GUIDE.md#troubleshooting).

---

## 🧪 Тесты
```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --no-deps
```
Перед релизом рекомендуется прогнать `cargo audit` и `cargo deny`.

---

## 📎 Дополнительные ресурсы
- [docs/SERVER_GUIDE.md](docs/SERVER_GUIDE.md)
- [docs/PROTOCOL.md](docs/PROTOCOL.md)
- [commucat-cli-client README](https://github.com/ducheved/commucat-cli-client#readme)
- [ACat.md](ACat.md)

---

## Simple English TL;DR
CommuCat server handles secure chats with Noise + TLS and federated routing. Steps:
1. Install Rust, PostgreSQL, Redis.
2. Configure `commucat.toml` (domain, TLS, DSN).
3. `cargo build --release`, run migrations `commucat-cli migrate`.
4. Start binary or systemd service.
5. Use CLI client with `--tls-ca` when cert is self-signed.

Read [`docs/SERVER_GUIDE.md`](docs/SERVER_GUIDE.md) for full deployment guide. Free like cats! 🐱
