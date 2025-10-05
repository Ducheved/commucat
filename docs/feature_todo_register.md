# Реестр фич и задач CommuCat

Документ агрегирует все известные фичи и крупные задачи из `ROADMAP.md`, `docs/todo.md`, `docs/dev_todo_tracker.md`, транспортных/клиентских гайдов и архитектурных заметок. Таблица обновляется по ходу работы; при закрытии задачи переносите строку в состояние `Готово` (или отмечайте новую дату/итерацию). Статусы используются в следующем смысле:

- `Готово` — реализация доступна в main.
- `В работе` — задача выполняется прямо сейчас.
- `Проект` — оформлена идея/дизайн, ждет реализации.
- `Требует доработки` — обнаружены пробелы, нужна дополнительная работа.
- `Запланировано` — задача в бэклоге ближайших релизов.
- `Не начато` — подтвержденная цель, но без активной проработки.
- `Исследование` — требуется R&D.
- `Видение` — долгосрочная цель без дорожной карты.

| ID   | Категория      | Задача / фича                                                        | Выпуск                | Статус          | Источник                     |
|------|----------------|-----------------------------------------------------------------------|-----------------------|-----------------|------------------------------|
| F001 | Безопасность   | TLS 1.3 + Noise XK/IK bootstrap для `/connect`                       | 2024 базовая поставка | Готово          | ROADMAP §0                   |
| F002 | Хранилище      | PostgreSQL + Redis интеграция, миграции CLI                          | 2024 базовая поставка | Готово          | ROADMAP §0                   |
| F003 | Онбординг      | Pairing API (`/api/pairing`, `/api/pairing/claim`)                    | 2024 базовая поставка | Готово          | ROADMAP §0                   |
| F004 | Леджер         | JSONL ledger адаптеры (file/debug/null)                              | 2024 базовая поставка | Готово          | ROADMAP §0                   |
| F005 | Медиа          | Базовый Opus/VP8 медиа-пайплайн                                       | 2024 базовая поставка | Готово          | ROADMAP §0                   |
| F006 | Наблюдаемость  | Prometheus + `/healthz`, `/readyz`, `/metrics`                        | 2024 базовая поставка | Готово          | ROADMAP §0                   |
| F007 | Документация   | Обновление quickstart и протокольных документов                       | Q4 2025 (1.1)         | Готово          | ROADMAP §1.1                 |
| F008 | P2P            | Assist: живой подбор путей, FEC-сэмплинг, метрики                     | 2025                  | Готово          | dev_todo_tracker T1          |
| F009 | P2P            | WebSocket ретрансляция `/p2p`, NAT-таймауты, очистка сессий           | 2025                  | Готово          | dev_todo_tracker T2          |
| F058 | P2P            | Валидация `session_id` и формат `/p2p` WebSocket                       | 2025                  | Готово          | Текущая итерация (валидация) |
| F010 | Транспорты     | Оценка сети (RTT/пропускная), детекция цензуры Reality                | 2025                  | Готово          | dev_todo_tracker T3          |
| F011 | Федерация      | Подписи friend-request и push-уведомления                            | 2025                  | Готово          | dev_todo_tracker T4          |
| F012 | Техдолг        | Удаление `dead_code`, активация метрик                                | 2025                  | Готово          | dev_todo_tracker T5          |
| F013 | Документация   | Гайды по P2P/WebSocket/SSE                                            | 2025                  | Готово          | dev_todo_tracker T6          |
| F014 | Леджер         | Логирование success-пути handshake/delivery/call                     | Q4 2025 (1.2)         | В работе        | ROADMAP §1.1                 |
| F015 | CLI            | Команда `autopair`                                                    | Q4 2025 (1.2)         | Проект          | docs/todo.md                 |
| F016 | Операции       | Упаковка systemd (tmpfiles, LogsDirectory, sandbox)                   | Q4 2025 (1.2)         | Требует доработки | docs/todo.md               |
| F017 | Протокол       | Capability renegotiation (codec fallback, feature toggles)            | 1.2                   | Запланировано   | docs/todo.md                 |
| F018 | Протокол       | Таксономия ошибок для bootstrap                                       | 1.2                   | Запланировано   | docs/todo.md                 |
| F019 | API            | Расширение OpenAPI спецификации                                       | 1.2                   | Запланировано   | docs/todo.md                 |
| F020 | Медиа          | Фича-флаг software H.264 (OpenH264)                                   | 1.2                   | Запланировано   | docs/todo.md                 |
| F021 | Транспорты     | Reality / AmnesiaWG прототипы                                         | 1.3                   | Не начато       | ROADMAP §2.1 / docs/todo.md  |
| F022 | Транспорты     | Shadowsocks / Onion обёртки                                           | 1.3                   | Не начато       | ROADMAP §2.1 / docs/todo.md  |
| F023 | Транспорты     | Traffic-shaping и padding для `/connect`                              | 1.3                   | Не начато       | ROADMAP §2.1                 |
| F024 | PQ             | Гибридный Noise + ML-KEM/ML-DSA handshake                             | 1.3                   | Запланировано   | ROADMAP §2.2 / docs/todo.md  |
| F025 | PQ             | Экспозиция PQ возможностей в `/api/server-info`                       | 1.3                   | Запланировано   | ROADMAP §2.2                 |
| F026 | PQ             | Бенчмарки и анализ размера PQ                                         | 1.3                   | Запланировано   | ROADMAP §2.2                 |
| F027 | Федерация      | Dispatcher loop для `federation_outbox`                               | 1.3                   | Запланировано   | ROADMAP §2.3 / docs/todo.md  |
| F028 | Федерация      | Подтверждение подписей, ретраи и backoff                              | 1.3                   | Запланировано   | ROADMAP §2.3                 |
| F029 | Федерация      | Админ-инструменты для allow-list пиров                                | 1.3                   | Запланировано   | ROADMAP §2.3                 |
| F030 | Наблюдаемость  | Гайд по structured tracing и пресеты                                  | 1.2                   | Запланировано   | docs/todo.md                 |
| F031 | QA             | Интеграционный тестовый стенд (Postgres+Redis)                        | 1.2                   | Запланировано   | docs/todo.md                 |
| F032 | Security       | CLI для ротации админ-токена                                          | 1.2                   | Запланировано   | docs/todo.md                 |
| F033 | Медиа          | Адаптивный битрейт, simulcast/FEC                                     | 1.4                   | Запланировано   | docs/todo.md                 |
| F034 | Mesh           | QUIC/multipath relay прототип                                         | 1.4                   | Запланировано   | docs/todo.md                 |
| F035 | P2P            | TURN/ICE-lite интеграция, NAT traversal                               | 1.4                   | Готово          | ICE-lite UDP + HMAC TURN creds (см. T8) |
| F058 | Надёжность     | WebSocket Keep-Alive (Ping/Pong heartbeat)                            | 1.4                   | Готово          | Текущая итерация + resilience guide     |
| F059 | Надёжность     | Connection Health Monitoring (RTT/jitter/loss)                        | 1.4                   | Готово          | Текущая итерация + metrics              |
| F060 | Надёжность     | Automatic Reconnection с exponential backoff                          | 1.4                   | Готово          | Текущая итерация + client SDKs          |
| F061 | Безопасность   | Port Knocking для Reality transport (TCP/UDP)                         | 1.4                   | Готово          | Текущая итерация + server config        |
| F062 | P2P            | Multipath Failover (автоматическое переключение транспортов)          | 1.4                   | Готово          | Текущая итерация + degradation detect   |
| F036 | Mesh           | Offline синхронизация (Wi-Fi Direct/BLE)                              | 2.0                   | Исследование    | ROADMAP §3.3                 |
| F037 | Медиа          | AV1/H.264 поддержка (софт/GPU)                                        | 2.0                   | Запланировано   | ROADMAP §3.2                 |
| F038 | Медиа          | Распределённый SFU                                                    | 2.0                   | Запланировано   | ROADMAP §3.2                 |
| F039 | CCP-2          | Структурированные payloads (CBOR/Protobuf)                            | 2.0                   | Запланировано   | ROADMAP §3.1                 |
| F040 | CCP-2          | Переговоры capability set и auth контекстов                           | 2.0                   | Запланировано   | ROADMAP §3.1                 |
| F041 | CCP-2          | Путь миграции с CCP-1                                                 | 2.0                   | Запланировано   | ROADMAP §3.1                 |
| F042 | Интеграции     | Мосты с Matrix / Signal / XMPP                                        | Post-2026             | Видение         | ROADMAP §4                    |
| F043 | Монетизация    | Микроплатежи и кошельки                                               | Post-2026             | Видение         | ROADMAP §4                    |
| F044 | Операции       | Production tooling (Helm, образы, операторы)                          | Post-2026             | Видение         | ROADMAP §4                    |
| F045 | Безопасность   | Защита от traffic analysis (стеганография, ML)                        | Post-2026             | Видение         | ROADMAP §4                    |
| F046 | CLI            | Engine parity для SSE/long-poll/WebSocket                             | 1.2                   | Запланировано   | CONNECT_MODES TODO           |
| F047 | CLI            | WebSocket handshake через общий TLS коннектор                         | 1.2                   | Запланировано   | CONNECT_MODES TODO           |
| F048 | CLI            | Потоковые декодеры SSE/NDJSON                                         | 1.2                   | Запланировано   | CONNECT_MODES TODO           |
| F049 | UI             | Выбор режима в TUI, отображение активного канала                      | 1.2                   | Запланировано   | CONNECT_MODES TODO           |
| F050 | QA             | Регрессионные тесты для всех connect-mode                             | 1.2                   | Запланировано   | CONNECT_MODES TODO           |
| F051 | Документация   | Обновить README/quickstart с режимами подключения                     | 1.2                   | Запланировано   | CONNECT_MODES TODO           |
| F052 | Транспорты     | Полноценные data-path для Reality/Shadowsocks/QUIC/DNS                | 1.3                   | Запланировано   | TRANSPORT_STATUS Next steps  |
| F053 | Транспорты     | Расширенные сетевые пробы (HTTPS HEAD, джиттер)                       | 1.3                   | Готово          | TRANSPORT_STATUS Next steps  |
| F054 | Наблюдаемость  | Метрики `transport_rtt_ms`, `transport_loss_ratio`                    | 1.3                   | Готово          | TRANSPORT_STATUS Next steps  |
| F055 | QA             | Интеграционные тесты WebSocket assist sampling                        | 1.3                   | Запланировано   | TRANSPORT_STATUS Next steps  |
| F056 | Федерация      | Фоновый воркер retry + подпись очереди                                | 1.3                   | Запланировано   | dev_todo_tracker T7          |
| F057 | Надёжность     | Гранулярная обработка ошибок uploads/pairing/rate limiter             | 1.2                   | Запланировано   | ARCHITECT §7                 |
