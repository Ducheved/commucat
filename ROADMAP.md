# Дорожная карта CommuCat (2025–2026)

_Last updated: 28 сентября 2025_

## 0. Состояние проекта

### Реализовано к сегодняшнему дню
- TLS + Noise XK/IK туннель поверх HTTP/2 (`crates/server`).
- Учетная модель “без паролей”: регистрация устройств, friends-список, REST pairing.
- PostgreSQL + Redis хранилище, миграции и CLI (`commucat-cli`).
- Серверное перекодирование RAW PCM/I420 → Opus/VP8; SFU-передача media-кадров.
- Базовый CCP-1 протокол: ACK, оффлайн-доставка, Presence, CallStats, capability поля.
- Ротация Noise static ключей и админ-токена; аудит через Ledger.
- Авто-ротация ключей устройств (CSR API, CCP `KeyUpdate` уведомления).
- Диагностика: `/metrics`, `commucat-cli diagnose`.
- Roadmap на GitHub, документация (`README.md`, `PROTOCOL.md`).

### Всё ещё отсутствует / в процессе
- PQ-гибрид в основном туннеле.
- Адаптивная обфускация (REALITY/XRay/VLESS, domain fronting, стеганография).
- Pluggable transports, TOR/onion routing, AmnesiaWG.
- AV1/H264/GPU, FEC, SVC, мультипутной медиапайплайн.
- Полноценная федерация, auto-install (в один клик), клиенты.
- Блокчейн-интеграция, криптообмен, ZKP.

---

## 1. Октябрь 2025 — декабрь 2025 (CommuCat 1.2)

### 1.1 Пользовательский опыт
| Задача | Описание | Ответственные |
|--------|----------|---------------|
| One-line installer | Скрипт “set-up.sh/ps1” (Postgres, Redis, миграции, генерация ключей, запуск службы). | DevOps (команда) |
| Авто-ротация ключей устройств | ✅ Вершина закрыта (CSR API на сервере, `KeyUpdate` уведомления) | Done (Codex) |
| CLI onboarding | Команда `commucat-cli autopair` — bootstrap устройства без пароля. | Rust контрибьюторы (Codex в работе) |
| Документация Quick Start | Обновить `docs/quickstart.md` и пример конфигов. | Технический писатель/дизайнер |

### 1.2 Медиа и протокол
- Включить capability renegotiation: Opus/VP8 fallback vs RAW, запись в `CallSession`.
- Поддержка H.264 (libopenh264). Режим “software only”.
- Подготовить черновик CCP-2: форматы, capability negotiation, мультипут.

**Ресурсы**: нужен Rust-медиа разработчик.

---

## 2. Январь 2026 — Июнь 2026 (CommuCat 1.5)

### 2.1 Транспорт и цензура
- Реализовать pluggable transports: Reality, AmnesiaWG, Shadowsocks, VLESS, onion routing.
- Интеграция TOR proxy + автоматический fallback (Traffic analysis resistance).
- Прототип обфускации (AdaptiveObfuscator) с policy-файлом.

**Нужны**: сетевой инженер/специалист по обходу цензуры.

### 2.2 PQ + ZKP
- Полный PQ-гибрид (ML-KEM-768 + ML-DSA-65) в основном туннеле.
- Минимальный ZKP: доказательство владения приватным ключом устройства (экспериментальная ветка).

**Нужны**: криптограф (PQ), специалист по ZKP.

### 2.3 Федерация и Mesh
- API для обмена событиями между узлами (подпись + взаимная валидация).
- Gossip-based discovery, авто-регистрация узлов.
- Начало работы над mesh (QUIC + Multipath + NAT traversal).

**Нужны**: Rust-разработчик, сетевой инженер.

---

## 3. Q3 2026 — Q4 2026 (CommuCat 2.0 – CCP-2 Draft)

### 3.1 CCP-2
- Протокол событий (CBOR/Protobuf), capability handshake, device bootstrap.
- Встроенная обфускация, поддержка нескольких транспортов из коробки.
- Режим “covert chat”: имитация популярных протоколов, padding, jitter.

### 3.2 Медиа
- Полноценный транскодер c FEC и SVC; GPU-ускорение (NVENC/VAAPI/Metal).
- Мультипут аудио/видео (MultipathTunnel) + адаптивный битрейт.

### 3.3 Zero passwords
- Безпарольный UX: устройство ↔ профиль ↔ recovery через social recovery/SSS.
- Веб/desktop/mobile клиенты: Flutter, Swift, C# (Avalonia/MAUI/WPF).

**Нужны**: Flutter/Swift/C# разработчики.

### 3.4 Блокчейн, криптообмен
- Wallet API: хранение ключей (L2/ERC20/BTC/Ton TBD).
- Интеграция с чатом (tip, escrow, micropayments).
- Запись хэшей сообщений в блокчейн (опционально).

**Нужны**: специалист по блокчейну.

---

## 4. Beyond 2026 (Vision)
- Социальный сервис “все в одном” (XMPP/IRC/Discord/Telegram/Facebook).
- Mesh по Wi-Fi Direct/BLE, offline synchronization, edge nodes.
- Сравнительный анализ и bridge к Signal, Matrix, WireGuard.
- Полная автоматизация: Helm chart, Operators, Cloud marketplace.
- Трендовая экспертиза: traffic analysis resistance, steganography, AI-based detection avoidance.

---

## 5. Команда и поиск коллег
**Уже есть**: DevOps (команда). Еще нужен:
- Дизайнер UI/UX и технический писатель.
- Rust-разработчики (ядро, медиа, протоколы).
- Сетевой инженер / специалист по цензуроустойчивости.
- Криптограф (PQ, ZKP).
- Блокчейн-разработчик.
- Разработчики Flutter / Swift / C# (клиенты).

*Присоединяйтесь: issues/PR в GitHub или team@commucat.tech.*
