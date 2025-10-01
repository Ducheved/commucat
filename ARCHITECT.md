# Архитектура CommuCat — детальный аудит

## Краткое резюме
- Проект позиционируется как защищённый маршрутизатор для звонков/сообщений с Noise, PQ-гибридом и антицензурой. На деле транспорт, обфускация и эксплуатационные аспекты остаются прототипами; «боевые» функции отсутствуют либо имитируются. Статусы задач синхронизированы с [`docs/todo.md`](docs/todo.md).
- Логика сосредоточена в монолите `crates/server/src/app/mod.rs` (>150 КБ). Отсутствует модульность, нет слоистой архитектуры, почти все ошибки обрабатываются через `expect`/строки.
- Операционный и безопасностный контуры не доведены: CLI печатает приватные ключи, нет zeroize, storage без пула подключений и подготовленных запросов, redis-операции блокируют mutex.
- Утверждения в README/PROTOCOL о мультипассе, DPI-resistance, федерации частично реализованы только на уровне типа/структур без фактической логики.

## Воркспейс и зависимости
- Workspace: `server`, `proto`, `crypto`, `storage`, `federation`, `ledger`, `cli`, `media-types`, `media`. Общие зависимости (tokio, tracing, snow, ml-kem/ml-dsa, pingora, audiopus, libvpx) закреплены в `[workspace.dependencies]`.
- `.cargo/config.toml` включает `--cfg getrandom_windows_legacy` для GNU target; rust-toolchain не зафиксирован.
- Внешние столпы: Pingora (TLS/HTTP/2), `snow` (Noise), `ml-kem/ml-dsa` (PQ), `raptorq` (FEC), `redis` + `tokio-postgres`, медиакодеки (`audiopus`, `libvpx`, `rav1e`, `openh264`).

## Смысл проекта и фактическое состояние
| Источник (док) | Заявлено | Что есть в коде | Разрыв |
| --- | --- | --- | --- |
| `README.md`, `PROTOCOL.md` | «Secure routing server», «stealth transports», «federated networking», «post-quantum hybrid», «system observability» | Noise-хэндшейк и выдача device certificate реализованы; федерация сведена к подписи/логированию; stealth-транспорты и multipath — в виде in-memory заглушек; наблюдаемость ограничена счётчиками | Нет реальных сетевых драйверов, нет интеграции с внешними федеративными узлами/протоколами, нет метрик уровня запросов, нет обработки отказов |
| `docs/systemd/commucat.service` | Production-unit: sandboxing, non-root, env config | Сервис действительно запускает бинарь под пользователем, но рабочая директория `/home/commucat` требует ручного деплоя; нет health-check, нет секретного стора, EnvironmentFile допускает утечки | Нужны tmpfs/StateDirectory, systemd sandboxing усилено, но без интеграции с секретами/логами |
| README (CLI) | «Operational CLI: migrations, key rotation, diagnostics» | Команды работают, но безопасностных практик нет (stdout с приватными ключами, `/dev/urandom`, строковые ошибки) | Для прод-использования неприемлемо, нет аутентификации, нет audit trail |

## Взаимодействия крейтов
- **`commucat-server`**: принимает HTTPS (Pingora) → REST эндпоинты + `/connect` Noise. Вызывает `storage` (Postgres/Redis) для пользователей, устройств, presence; `crypto` для Noise/сертификатов; `proto` для фреймов; `media` для транскодинга; `ledger` для логирования; `federation` для подписи событий; `transport` для выбора каналов (пока mock).
- **`commucat-cli`**: использует `storage`, `crypto`, `ledger`, `media` для админ-операций. Никакого RBAC/ACL; все операции доверенные.
- **`commucat-media`/`media-types`**: медиапайплайн, совместно используется `server` и `cli`.
- **`commucat-proto`**: кодек CCP-1, call DSL, obfuscation (Noise mimicry); единственный потребитель — `server`.
- **`commucat-storage`**: хендлинг Postgres/Redis без пулов; миграции через `include_str!`.

## Матрица модулей
| Модуль | Назначение | Основные зависимости | Реализовано | Несоответствия / проблемы | Что делать |
| --- | --- | --- | --- | --- | --- |
| `crates/server` (главный бинарь) | TLS-терминатор, REST/Noise, маршрутизация фреймов, orchestration | Pingora, tokio, tracing, storage, crypto, proto, media, ledger, federation | REST API (`/api/*`), handshake с ZKP и device cert, управление группами/звонками, ledger-хуки, мультипассовый планировщик | `app::mod.rs` — монолит >150 КБ, плотный stateful код, множество `expect`; транспортные «плагины» — фиктивные (in-memory duplex); нет rate limiting на каналах, нет backpressure, нет ретраев storage; ошибки HTTP строятся вручную, не по RFC 9457 | Разрезать на сервисные слои, ввести `Result`/`thiserror`, сделать реальные транспортные плагины, добавить лимиты/timeout/retry, использовать ProblemDetails, отделить websockets/noise обработчик |
| `server::app::media` | Компонент транскодинга внутри звонков | `commucat-media` | Кодирует PCM→Opus/VP8, строит пакеты с `MEDIA_PACKET_VERSION`, считает уровни | Отсутствует адаптация к сети, нет ограничения размера, нет версионирования протокола | Добавить BWE/RTT feedback, DPI ограничители, поля версии и capability negotiation |
| `server::app::p2p` | Генерация рекомендаций по обходу цензуры, multipath advice | transport, crypto, storage (метрики) | Конструирует `MultipathTunnel`, выдает Noise/PQ/ICE подсказки | Метрики сети заглушены, транспорт mock, нет кэширования или telemetry, не учитываются реальные peers | Подключить реальный сенсоринг (RTT/bandwidth), хранить результаты, интегрировать с federation/peer данными |
| `server::security::secrets` | Ротация Noise/static ключей и admin токенов | storage, crypto (derive), tracing | Синхронизирует `server_secret` таблицу, запускает фоновые тикеры | Нет сигналов остановки, тикер бесконечен, токены/ключи логируются, нет интеграции с внешними секрет-сторами, zeroize отсутствует | Добавить graceful shutdown, убрать логирование секретов, внедрить KMS/внешний стор, zeroize, audit |
| `server::transport` | Абстракция pluggable транспорта, FEC, multipath | raptorq, tokio | Подбор транспорта по score, FEC через RaptorQ, fallback chain | Все транспорты возвращают `DuplexStream`; censorship detection фиктивная; encode_frame нигде не применяется; нет metrics/backpressure | Реализовать реальные транспорты (QUIC, WebSocket, Reality), интегрировать с сетью, ввести health-check, telemetry, FEC в прод-путь |
| `crates/proto` | Кодек CCP-1, call DSL, фреймы, обфускация | serde, serde_json, blake3, rand (feature) | Varint-кодек, MAX	o 16 MiB, call структуры, obfuscation (JSON packet mimicry) | Нет схем валидации; MAX_FRAME_LEN без ограничений — DoS; нет версионности payload; обфускация — JSON сериализация, а не true wire mimicry | Добавить schema validation (schemars), enforce body size per тип, добавить версии фреймов, fuzz-тесты, переписать обфускацию на бинарный формат |
| `crates/crypto` | Noise XK/IK, device cert, PQ-хэндшейк, ZKP | snow, ed25519-dalek, ml-kem, ml-dsa, hkdf, blake3 | DeviceKeyPair, EventSigner, обёртки Noise, PQ ratchet, доказательства знания | `DeviceKeyPair::from_seed` детерминирован через BLAKE3 без salt/zeroize; нет secret wipe; PQ code без state persistence; ZKP не привязан к session TTL | Ввести HKDF, zeroize, хранить ключи в защищённой структуре, добавить state/persistence для PQ bundle |
| `crates/media` | Медиапримитивы: кодеки, pipeline, capture | audiopus, cpal, env_libvpx_sys, rav1e, openh264, tokio | Голос (Opus/raw), видео (VP8/VP9/AV1), capture через cpal, voice pipeline | Нет limit-check (payload size), нет адаптивных профилей, много `allow(clippy)`; FFI заключён напрямую без RAII | Обернуть FFI, добавить лимиты/обработку ошибок, вынести повторный hex-code, добавить тесты на переполнение |
| `crates/media-types` | DTO и capability-модель | serde | Перечисления кодеков, hardware, capabilities | Нет версионности/compat слоёв, hard-coded значения | Добавить `#[non_exhaustive]`, документировать mapping, рассмотреть feature flags |
| `crates/federation` | Подпись событий между доменами | commucat-crypto | Ed25519 подпись, digest BLAKE3, PeerDescriptor | Нет защиты от replay, нет retry/backoff, отсутствуют сетевые клиенты | Добавить nonce/expires, очередь повторной доставки, интеграция с transport |
| `crates/ledger` | Экспорт digest-логов | serde_json, tracing | Null/File/Debug адаптеры | File adapter записывает sync append без fsync; нет структурированных ошибок; hex helper дублирует код | Ввести async writers, configurable formatter, reuse hex utils |
| `crates/storage` | PostgreSQL/Redis DAL | tokio-postgres, redis, chrono, serde_json | SQL миграции, pairing, rotation, presence, relay queue | Нет пула подключений, нет prepared statements, Redis через Mutex (head-of-line blocking), возвращает `String` ошибки | Интегрировать `bb8`/`deadpool`, подготовленные запросы, дифференцировать чтение/запись, структурировать ошибки |
| `crates/cli` | Ops CLI | clap отсутствует, dotenvy, tokio runtime | Команды migrate/register-user/rotate-keys/diagnose/call-simulate | CLI читает `/dev/urandom`, печатает приватные ключи, ошибки `String`, нет флагов/подкоманд | Переписать на `clap`, скрыть секреты (stdout → файл с правами), внедрить подтверждения |
| Документация / сервисные файлы | README, PROTOCOL, systemd unit | Markdown | Обещают stealth, federation, наблюдаемость | Несовпадение с реализацией (см. Смысл vs факт) | Синхронизировать документацию с фактом, описать ограничения |

## Кросс-модульные зависимости и разрывы
- **Transport vs App**: `app` вызывает `transport` лишь для рекомендаций/handshake, но multipath не подключён к реальной отправке CCP-1 фреймов. Ledger логирует события, но transport не уведомляет о реальных ошибках.
- **Storage vs SecretManager**: ротация ключей и админ-токенов завязана на таблицу `server_secret`, но нет watcher’а на изменения (горячее переключение невозможно без рестарта). Админ токен генерируется и логируется в info → риск утечки.
- **Federation vs Inbox/Relay**: добавились `federation_outbox` и входящая точка `/federation/events`, но отсутствуют подтверждения, backoff и политика повторов для междоменной доставки.
- **Media vs Transport**: audio/video транскодер готов выдавать payload, но нет QoS/feedback — даже CallStats не влияют на pipeline.

## Потоки данных и процессы
### Noise / CCP-1 handshake
- Сервер проверяет ZKP (`commucat_crypto::zkp`) и device cert. При отсутствии устройства авто-регистрация с выдачей сертификата. Нет rate-limit на `Hello` → DoS возможно.
- В случае ошибки возвращается `FrameType::Error` без структурированного `ProblemDetails`; клиент сам интерпретирует.

### Маршрутизация каналов
- `channel_routes` хранит участников; при relay = true используется inbox/relay queue. Для оффлайн-узлов фрейм складывается в Postgres, но отсутствует TTL-контроль на уровне приложения (только поле expires_at).

### Звонки / медиа
- `CallSession` сохраняет участников/accepted/stats. Транскодер не использует CallStats, нет контроля нагрузки. Ledger логирует события, но не проверяет успешных доставок.

### Фоновые задачи
- `SecretManager::rotation_loop` — бесконечный тикер без cancel. `storage.invalidate_expired_pairings` запускается каждую минуту, но нет jitter/backoff и нет наблюдаемости.

## Безопасность и комплаенс
- **Ключи/секреты**: CLI печатает приватные ключи, `SecretManager` логирует freshly issued admin tokens. Нет zeroize, seed и приватные ключи держатся в обычных массивах.
- **Error handling**: множество `expect/unwrap` → crash on malformed input. Нет границы между пользовательскими и системными ошибками.
- **Валидация входа**: JSON payload не валидируются (CallOffer/Answer). Группы/друзья не проверяют длину/формат строк, есть риск injection.
- **DoS**: MAX_FRAME_LEN = 16 MiB, нет ограничений по количеству фреймов, inbox не purgeится по пользователю, presence TTL фиксирован.
- **Сетевые транспорты**: обещанная защита от DPI отсутствует; detect_censorship возвращает `Ok` всегда.

## Наблюдаемость и эксплуатация
- `metrics.rs` даёт агрегированные счётчики (connections, frames, rotations) + `/metrics` endpoint. Нет label’ов per endpoint/класс ошибок, нет tracing span id, нет `traceparent`.
- `/readyz` проверяет только storage.readiness. Нет `/livez`. Фоновые задачи (rotation, cleanup) не отчитываются.
- `docs/systemd/commucat.service`: базовый hardening (`NoNewPrivileges`, `ProtectSystem`), но нет `StateDirectory`, нет логирования через journald/otel, нет watchdog.

## Производительность и надёжность
- `Storage` без пула → каждое соединение — отдельный клиент; возможен перебор соединений или «stop the world» при ошибке.
- Redis через `Mutex<MultiplexedConnection>` → head-of-line blocking для presence, route, notifications.
- Транспорт/медиа не используют backpressure; отправка больших payload может выжечь память (`Vec::with_capacity`).
- Нет интеграционных тестов/benchmarks, кроме условных `#[tokio::test]` в storage (пропускаются без env).

## DX и тестирование
- Нет `justfile`/`Makefile`, нет инструкций по миграциям/seed. CLI не покрывает rollback’и или dry-run.
- Тесты разбросаны, в основном unit; интеграционные требуют внешних сервисов. Нет CI-конфигурации (не рассмотрено в этой ревизии).
- Документация не описывает реальные ограничения (например, требование TLS cert/key, необходимость вручную создать пользователя `commucat`).

## Ценность и потенциал
- **Реализованные сильные стороны**: продуманная модель handshake (ZKP + cert), наличие PQ-компонентов, медиа-пайплайн с кодеками, DAL для Postgres/Redis, структурированные данные (CallOffer/Profile).
- **Слабые**: отсутствие реальных транспортов/антицензуры, безопасность и эксплуатация на уровне прототипа, документация расходится с кодом.
- **Фактический статус**: технологический прототип/POC. Использовать в проде опасно без глубокой переработки транспорта, безопасности, наблюдаемости и эксплуатационных процессов.

## Рекомендации
### Немедленно (базовая гигиена)
1. Запретить вывод приватных ключей и логирование токенов; внедрить zeroize/HKDF для ключей.
2. Расщепить `app::mod.rs`, внедрить `thiserror`/`anyhow`, заменить `expect` → безопасные ошибки.
3. Ограничить размеры входных фреймов, валидировать JSON (schemars/validator), добавить rate limiting на `/connect`.
4. Ввести connection pooling (`bb8`/`deadpool`) для Postgres/Redis, подготовленные запросы.

### Среднесрочно
1. Реализовать реальные транспорты (QUIC/WebSocket/Reality) и подключить FEC/Multipath к отправке фреймов.
2. Ввести полноправную наблюдаемость: trace-id, структурированные логи, `/livez`, метрики по типам ошибок.
3. Провести security-hardening: RBAC для CLI/API, audit trail, ограничение выдачи секретов, защиту от replay.
4. Переписать CLI на `clap`, добавить подтверждения, журналирование, опции безопасного вывода.

### Долгосрочно
1. Пересмотреть архитектуру (server → сервисы/агрегаторы), выделить доменные модули (handshake, calls, federation, media) с явными интерфейсами.
2. Интегрировать федерацию (подпись + доставка) и антицензурный слой с реальными сетевыми клиентами.
3. Создать CI/CD pipeline с авто-тестами, fuzzing для протоколов, нагрузочным тестированием медиа/транспорта.
4. Синхронизировать документацию и протокол с реализацией, описать фичи/ограничения честно.

---
Доклад отражает фактическое состояние репозитория на момент аудита; информация из Markdown-документации проверена и сопоставлена с кодом. Предложенные шаги рассчитаны на постепенное движение прототипа к производственному уровню.
