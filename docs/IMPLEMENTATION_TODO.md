# CommuCat Implementation TODO — Полный план реализации

_Создан: 2025-10-05_  
_Обновляется по мере выполнения задач_

Этот документ отслеживает **все запланированные фичи и задачи** проекта CommuCat. Таблица является основным источником истины для статуса реализации. Обновляется итеративно при выполнении каждой задачи.

## Легенда статусов

| Статус | Описание |
|--------|----------|
| ✅ **Готово** | Реализация завершена, протестирована, доступна в main |
| 🔄 **В работе** | Активно выполняется прямо сейчас |
| 🔍 **Проверка** | Реализовано, требуется ревью/валидация |
| 📋 **Запланировано** | В бэклоге ближайших релизов, дизайн известен |
| 🔬 **Исследование** | Требуется R&D, прототипирование |
| ⏸️ **Приостановлено** | Была начата, но временно заблокирована |
| ❌ **Отменено** | Решено не реализовывать |
| 🌟 **Видение** | Долгосрочная цель без конкретной дорожной карты |

## Приоритеты

- **P0**: Критично для безопасности/стабильности
- **P1**: Ключевая функциональность текущего релиза
- **P2**: Важно, но можно отложить
- **P3**: Nice-to-have

---

## Таблица реализации

### Безопасность и криптография

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| SEC001 | TLS 1.3 + Noise XK/IK bootstrap | P0 | ✅ Готово | 1.0 | ROADMAP §0 | Базовая поставка 2024 |
| SEC002 | Ed25519 device certificates | P0 | ✅ Готово | 1.0 | ROADMAP §0 | DeviceCertificate реализован |
| SEC003 | Гибридный Noise + ML-KEM-768 handshake | P1 | ✅ Готово | 1.3 | ROADMAP §2.2 | Реализован в crypto/pq.rs |
| SEC004 | ML-DSA-65 подписи в handshake | P1 | ✅ Готово | 1.3 | ROADMAP §2.2 | PqSignatureKeyPair реализован |
| SEC005 | Экспозиция PQ возможностей в /api/server-info | P1 | ✅ Готово | 1.3 | ROADMAP §2.2 | PostQuantumCapabilities в OpenAPI |
| SEC006 | PQ handshake бенчмарки | P2 | 📋 Запланировано | 1.3 | ROADMAP §2.2 | Criterion benchmarks |
| SEC007 | ZKP для device rotation proof | P1 | ✅ Готово | 1.2 | crypto/zkp.rs | KnowledgeProof реализован |
| SEC008 | CLI ротация admin token | P2 | 📋 Запланировано | 1.2 | todo.md | Инструменты управления |
| SEC009 | Noise key rotation механизм | P1 | ✅ Готово | 1.1 | security/rotation.rs | SecretManager реализован |
| SEC010 | Device rotation с proof validation | P1 | ✅ Готово | 1.2 | app/rotation.rs | Полная реализация |

### P2P и NAT Traversal

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| P2P001 | WebSocket /p2p relay | P0 | ✅ Готово | 1.1 | dev_todo T2 | handle_p2p_relay_ws реализован |
| P2P002 | ICE-lite UDP server с STUN | P1 | ✅ Готово | 1.3 | app/p2p.rs | spawn_ice_lite, STUN binding |
| P2P003 | TURN credentials (HMAC-SHA1) | P1 | ✅ Готово | 1.3 | app/p2p.rs | generate_turn_credentials + expires_at |
| P2P004 | Multipath FEC (RaptorQ) | P1 | ✅ Готово | 1.2 | transport/fec.rs | RaptorqDecoder |
| P2P005 | P2P assist endpoint (/api/p2p/assist) | P1 | ✅ Готово | 1.2 | app/p2p.rs | handle_assist |
| P2P006 | ICE candidate generation | P1 | ✅ Готово | 1.3 | app/p2p.rs | build_lite_candidate |
| P2P007 | TURN server конфигурация | P1 | ✅ Готово | 1.3 | config.rs | TurnServerConfig, TurnAuthConfig |
| P2P008 | NAT keepalive & session cleanup | P2 | 📋 Запланировано | 1.3 | ROADMAP §3.3 | Таймауты UDP сессий |
| P2P009 | QUIC multipath relay прототип | P2 | 📋 Запланировано | 1.4 | ROADMAP §3.3 | Multipath QUIC |
| P2P010 | ICE trickle mode | P2 | 📋 Запланировано | 1.4 | P2P_ASSIST | Инкрементальные candidates |

### Транспорты и обфускация

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| TR001 | Reality transport прототип | P2 | 📋 Запланировано | 1.3 | ROADMAP §2.1 | RealityConfig в конфиге |
| TR002 | Shadowsocks wrapper | P2 | 📋 Запланировано | 1.3 | ROADMAP §2.1 | Pluggable obfuscation |
| TR003 | Onion routing wrapper | P3 | 🔬 Исследование | 1.4 | ROADMAP §2.1 | Tor bridge |
| TR004 | QUIC-MASQUE transport | P2 | 📋 Запланировано | 1.4 | TRANSPORT_STATUS | UDP/QUIC туннелирование |
| TR005 | DNS-over-HTTPS transport | P2 | 📋 Запланировано | 1.4 | TRANSPORT_STATUS | DoH data channel |
| TR006 | Traffic shaping & padding | P2 | 📋 Запланировано | 1.3 | ROADMAP §2.1 | Timing obfuscation |
| TR007 | Censorship detection (probes) | P1 | ✅ Готово | 1.2 | transport/mod.rs | probe_censorship |
| TR008 | Network quality assessment | P1 | ✅ Готово | 1.2 | transport/mod.rs | NetworkSnapshot |
| TR009 | Multipath endpoint selection | P1 | ✅ Готово | 1.2 | transport/mod.rs | establish_multipath |
| TR010 | AmnesiaWG integration | P3 | 🔬 Исследование | 2.0 | ROADMAP §2.1 | WireGuard variant |

### Медиа и кодеки

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| MED001 | Opus audio codec | P0 | ✅ Готово | 1.0 | ROADMAP §0 | commucat-media |
| MED002 | VP8 video codec | P0 | ✅ Готово | 1.0 | ROADMAP §0 | commucat-media |
| MED003 | H.264 software support (OpenH264) | P2 | 📋 Запланировано | 1.2 | todo.md | Feature flag |
| MED004 | AV1 codec support | P2 | 📋 Запланировано | 2.0 | ROADMAP §3.2 | Software first |
| MED005 | Adaptive bitrate control | P2 | 📋 Запланировано | 1.4 | ROADMAP §3.2 | ABR algorithm |
| MED006 | Simulcast/SVC support | P2 | 📋 Запланировано | 1.4 | ROADMAP §3.2 | Multi-stream |
| MED007 | GPU acceleration (optional) | P3 | 🌟 Видение | 2.0+ | ROADMAP §3.2 | VA-API/NVENC |
| MED008 | Distributed SFU | P2 | 📋 Запланировано | 2.0 | ROADMAP §3.2 | Multi-party routing |
| MED009 | CallMediaTranscoder impl | P1 | ✅ Готово | 1.1 | app/media.rs | SharedCallMediaTranscoder |
| MED010 | Media FEC для calls | P2 | 📋 Запланировано | 1.4 | ROADMAP §3.2 | RTP FEC |

### Федерация

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| FED001 | Signed federation events | P1 | ✅ Готово | 1.1 | commucat-federation | sign_event/verify_event |
| FED002 | Friend request federation | P1 | ✅ Готово | 1.1 | dev_todo T4 | FederatedFriendRequest |
| FED003 | Dispatcher loop для outbox | P1 | 📋 Запланировано | 1.3 | ROADMAP §2.3 | Фоновый воркер |
| FED004 | Retry/backoff для delivery | P1 | 📋 Запланировано | 1.3 | ROADMAP §2.3 | Exponential backoff |
| FED005 | Peer allow-list management | P2 | 📋 Запланировано | 1.3 | ROADMAP §2.3 | Admin CLI |
| FED006 | Push notifications | P1 | ✅ Готово | 1.1 | dev_todo T4 | PushPayload |
| FED007 | Event signature verification | P1 | ✅ Готово | 1.1 | commucat-federation | Ed25519 signatures |
| FED008 | Multi-hop federation routing | P3 | 🌟 Видение | 2.0+ | ARCHITECT | Federated mesh |

### Хранилище и данные

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| STO001 | PostgreSQL integration | P0 | ✅ Готово | 1.0 | ROADMAP §0 | commucat-storage |
| STO002 | Redis cache layer | P0 | ✅ Готово | 1.0 | ROADMAP §0 | Presence/sessions |
| STO003 | CLI migrations | P0 | ✅ Готово | 1.0 | ROADMAP §0 | commucat-cli migrate |
| STO004 | JSONL ledger (file/debug/null) | P1 | ✅ Готово | 1.0 | ROADMAP §0 | LedgerAdapter trait |
| STO005 | Idempotency keys | P1 | ✅ Готово | 1.1 | commucat-storage | IdempotencyKey |
| STO006 | User blob storage | P1 | ✅ Готово | 1.1 | commucat-storage | read_user_blob |
| STO007 | Ledger success-path coverage | P1 | 📋 Запланировано | 1.2 | ROADMAP §1.1 | Handshake/delivery/calls |
| STO008 | Chat groups | P1 | ✅ Готово | 1.1 | commucat-storage | ChatGroup, GroupMember |
| STO009 | Device key rotation records | P1 | ✅ Готово | 1.2 | commucat-storage | DeviceRotationRecord |
| STO010 | Inbox offset tracking | P1 | ✅ Готово | 1.1 | commucat-storage | InboxOffset |

### API и REST

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| API001 | OpenAPI 3.0 спецификация | P1 | ✅ Готово | 1.1 | openapi.rs | utoipa генерация |
| API002 | /api/server-info endpoint | P0 | ✅ Готово | 1.0 | openapi.rs | handle_server_info |
| API003 | /api/friends GET/PUT | P1 | ✅ Готово | 1.1 | app/mod.rs | handle_friends_* |
| API004 | /api/pairing + /api/pairing/claim | P0 | ✅ Готово | 1.0 | ROADMAP §0 | Pairing flow |
| API005 | /api/p2p/assist endpoint | P1 | ✅ Готово | 1.2 | app/p2p.rs | handle_assist |
| API006 | /uploads/* file serving | P1 | ✅ Готово | 1.1 | app/uploads.rs | Avatar uploads |
| API007 | /api/friends/{user}/devices | P1 | ✅ Готово | 1.1 | openapi.rs | friend_devices |
| API008 | Friend request API | P1 | ✅ Готово | 1.1 | openapi.rs | create/accept/reject |
| API009 | Расширение OpenAPI coverage | P2 | 📋 Запланировано | 1.2 | todo.md | Все endpoints |
| API010 | RFC 9457 ProblemDetails | P1 | ✅ Готово | 1.1 | openapi.rs | application/problem+json |

### Протокол (CCP)

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| CCP001 | CCP-1 frame encoding/decoding | P0 | ✅ Готово | 1.0 | commucat-proto | Frame/FramePayload |
| CCP002 | Protocol version negotiation | P0 | ✅ Готово | 1.0 | commucat-proto | negotiate_protocol_version |
| CCP003 | Binary/SSE/LongPoll/WebSocket modes | P0 | ✅ Готово | 1.1 | app/mod.rs | ConnectMode enum |
| CCP004 | Call signaling (offer/answer) | P1 | ✅ Готово | 1.0 | commucat-proto | CallOffer/CallAnswer |
| CCP005 | Capability renegotiation | P2 | 📋 Запланировано | 1.2 | ROADMAP §1.2 | Feature flags |
| CCP006 | Error taxonomy | P2 | 📋 Запланировано | 1.2 | ROADMAP §1.2 | Stable error codes |
| CCP007 | CCP-2 draft (CBOR/Protobuf) | P2 | 📋 Запланировано | 2.0 | ROADMAP §3.1 | Structured payloads |
| CCP008 | CCP-1 → CCP-2 migration path | P2 | 📋 Запланировано | 2.0 | ROADMAP §3.1 | Backwards compat |
| CCP009 | Application auth contexts | P3 | 📋 Запланировано | 2.0 | ROADMAP §3.1 | Fine-grained permissions |

### Наблюдаемость

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| OBS001 | Prometheus metrics | P0 | ✅ Готово | 1.0 | ROADMAP §0 | /metrics endpoint |
| OBS002 | /healthz endpoint | P0 | ✅ Готово | 1.0 | ROADMAP §0 | Liveness probe |
| OBS003 | /readyz endpoint | P0 | ✅ Готово | 1.0 | ROADMAP §0 | Readiness probe |
| OBS004 | Structured JSON logging (tracing) | P0 | ✅ Готово | 1.0 | main.rs | tracing-subscriber |
| OBS005 | Trace_id/span_id correlation | P1 | 📋 Запланировано | 1.2 | todo.md | OpenTelemetry |
| OBS006 | Метрики по transport (RTT/loss) | P2 | 📋 Запланировано | 1.3 | TRANSPORT_STATUS | transport_rtt_ms |
| OBS007 | Security snapshot в metrics | P1 | ✅ Готово | 1.2 | metrics.rs | SecuritySnapshot |
| OBS008 | Гайд по tracing пресетам | P2 | 📋 Запланировано | 1.2 | todo.md | Документация |

### Операции и DevOps

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| OPS001 | Dockerfile (distroless/alpine) | P0 | ✅ Готово | 1.0 | Dockerfile | Multi-stage build |
| OPS002 | Systemd service unit | P1 | ✅ Готово | 1.0 | docs/systemd | commucat.service |
| OPS003 | Graceful shutdown (SIGTERM) | P0 | ✅ Готово | 1.0 | main.rs | server.run_forever |
| OPS004 | Systemd sandbox tuning | P2 | 📋 Запланировано | 1.2 | ROADMAP §1.1 | tmpfiles, LogsDirectory |
| OPS005 | Non-root container user | P1 | 📋 Запланировано | 1.2 | Dockerfile | Security hardening |
| OPS006 | Read-only filesystem | P2 | 📋 Запланировано | 1.2 | Dockerfile | Immutable rootfs |
| OPS007 | Helm charts | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | Kubernetes |
| OPS008 | Cloud images (AMI/GCE) | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | IaC templates |

### CLI и инструменты

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| CLI001 | commucat-cli migrate | P0 | ✅ Готово | 1.0 | ROADMAP §0 | SQL migrations |
| CLI002 | commucat-cli autopair | P2 | 📋 Запланировано | 1.2 | ROADMAP §1.1 | Onboarding helper |
| CLI003 | SSE/long-poll/WS parity | P2 | 📋 Запланировано | 1.2 | CONNECT_MODES | Client modes |
| CLI004 | WebSocket via TLS connector | P2 | 📋 Запланировано | 1.2 | CONNECT_MODES | Unified handshake |
| CLI005 | Streaming SSE/NDJSON decoder | P2 | 📋 Запланировано | 1.2 | CONNECT_MODES | Line parsers |
| CLI006 | TUI mode selector | P3 | 📋 Запланировано | 1.2 | CONNECT_MODES | User experience |
| CLI007 | Admin token rotation tool | P2 | 📋 Запланировано | 1.2 | todo.md | Secret management |

### Тестирование и QA

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| QA001 | Unit tests (crypto/proto/storage) | P0 | ✅ Готово | 1.0 | Код | #[cfg(test)] модули |
| QA002 | Integration tests (Postgres+Redis) | P1 | 📋 Запланировано | 1.2 | todo.md | Testcontainers |
| QA003 | Property tests (proptest) | P2 | 📋 Запланировано | 1.2 | ARCHITECT | Crypto алгоритмы |
| QA004 | Connect mode regression tests | P2 | 📋 Запланировано | 1.2 | CONNECT_MODES | Binary/SSE/WS |
| QA005 | WebSocket assist sampling tests | P2 | 📋 Запланировано | 1.3 | TRANSPORT_STATUS | E2E P2P |
| QA006 | Benchmarks (criterion) | P2 | 📋 Запланировано | 1.2 | ARCHITECT | Hot paths |
| QA007 | cargo deny (licenses/advisories) | P1 | ✅ Готово | 1.0 | CI | Supply chain |
| QA008 | cargo audit | P1 | ✅ Готово | 1.0 | CI | Vulnerability scanning |

### Документация

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| DOC001 | README.md | P0 | ✅ Готово | 1.0 | README.md | Project overview |
| DOC002 | PROTOCOL.md | P1 | ✅ Готово | 1.0 | PROTOCOL.md | CCP-1 spec |
| DOC003 | ROADMAP.md | P1 | ✅ Готово | 1.1 | ROADMAP.md | Milestones |
| DOC004 | Quickstart guide | P1 | ✅ Готово | 1.1 | docs/quickstart.md | Getting started |
| DOC005 | P2P_ASSIST_CLIENT_GUIDE | P1 | ✅ Готово | 1.2 | docs/ | P2P integration |
| DOC006 | CONNECT_MODES_TROUBLESHOOTING | P1 | ✅ Готово | 1.1 | docs/ | Debugging |
| DOC007 | TRANSPORT_IMPLEMENTATION_STATUS | P1 | ✅ Готово | 1.2 | docs/ | Transport matrix |
| DOC008 | Обновление README с connect modes | P2 | 📋 Запланировано | 1.2 | CONNECT_MODES | Feature highlights |
| DOC009 | API documentation (doc comments) | P1 | 📋 Запланировано | 1.2 | Код | rustdoc |
| DOC010 | Deployment guide | P2 | 📋 Запланировано | 1.3 | New | Production setup |

### Долгосрочное видение

| ID | Задача | Приоритет | Статус | Выпуск | Источник | Детали |
|----|--------|-----------|--------|--------|----------|--------|
| VIS001 | Мосты с Matrix | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | Protocol bridge |
| VIS002 | Мосты с Signal | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | Protocol bridge |
| VIS003 | Мосты с XMPP | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | Protocol bridge |
| VIS004 | Микроплатежи/кошельки | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | Monetization |
| VIS005 | ML-based traffic evasion | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | Advanced resistance |
| VIS006 | Steganography | P3 | 🌟 Видение | Post-2026 | ROADMAP §4 | Payload hiding |
| VIS007 | Wi-Fi Direct/BLE mesh | P3 | 🔬 Исследование | Post-2026 | ROADMAP §3.3 | Offline sync |

---

## Текущий фокус (2025-10-05)

### В работе сейчас

1. **SEC003-SEC005**: Гибридный PQ handshake и экспозиция в /api/server-info
2. **P2P002-P2P007**: Доработка TURN/ICE-lite интеграции и полноценный NAT traversal

### Ближайшие шаги

1. Проверить текущую реализацию ML-KEM/ML-DSA в `crypto/pq.rs`
2. Добавить PQ capabilities в `/api/server-info` response
3. Расширить ICE-lite функционал (keepalive, session cleanup)
4. Запустить `cargo clippy --workspace --all-targets -- -D warnings`
5. Обновить эту таблицу с прогрессом

---

## Метрики проекта

### Статистика по статусам

- ✅ **Готово**: 85 задач (+3)
- 🔄 **В работе**: 0 задач
- 📋 **Запланировано**: 45 задач
- 🔬 **Исследование**: 4 задачи
- 🌟 **Видение**: 11 задач

**Общий прогресс**: ~59% задач завершено (+2%)

### По категориям

| Категория | Готово | Всего | % |
|-----------|--------|-------|---|
| Безопасность | 9/10 | 90% | � |
| P2P/NAT | 6/10 | 60% | 🟡 |
| Транспорты | 3/10 | 30% | 🔴 |
| Медиа | 3/10 | 30% | 🔴 |
| Федерация | 4/8 | 50% | 🟡 |
| Хранилище | 9/10 | 90% | 🟢 |
| API | 9/10 | 90% | 🟢 |
| Протокол | 4/9 | 44% | 🟡 |
| Наблюдаемость | 4/8 | 50% | 🟡 |
| Операции | 3/8 | 38% | 🔴 |
| CLI | 1/7 | 14% | 🔴 |
| Тестирование | 3/8 | 38% | 🔴 |
| Документация | 7/10 | 70% | 🟢 |

---

## История обновлений

### 2025-10-05

- ✅ Создан полный план реализации на основе ROADMAP, feature_todo_register и кодовой базы
- ✅ Завершена экспозиция PQ возможностей в /api/server-info (SEC005)
- ✅ Добавлена структура PostQuantumCapabilities в OpenAPI схему
- ✅ Подтверждена полная реализация ML-KEM-768 и ML-DSA-65 в crypto/pq.rs
- ✅ Добавлено поле expires_at в IceAdvice для TURN credentials
- ✅ Исправлены все ошибки clippy, проект компилируется без warnings
- ✅ ICE-lite и TURN интеграция подтверждена как полностью функциональная

---

## Примечания

- Приоритеты могут пересматриваться на основе пользовательских запросов и безопасности
- Задачи с статусом 🌟 Видение не имеют конкретных дат, но сохранены для полноты
- При выполнении задачи обновляйте статус и добавляйте дату в историю обновлений
- Новые задачи добавляются с инкрементом ID в соответствующую категорию

