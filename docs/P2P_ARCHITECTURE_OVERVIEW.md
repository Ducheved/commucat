# Архитектура P2P и вспомогательных каналов CommuCat

Документ описывает текущую реализацию peer-to-peer соединений, NAT-обхода через сервер и режимов `/connect` (Binary/SSE/Long-Poll/WebSocket). Материал основан на исходном коде `crates/server` и сопровождающих спецификациях (`PROTOCOL.md`, `P2P_ASSIST_CLIENT_GUIDE.md`, `docs/CONNECT_MODES_TROUBLESHOOTING.md`).

## 1. P2P Assist: что выдаёт сервер

Маршрут: `POST /api/p2p/assist` → `crates/server/src/app/p2p.rs::handle_assist`.

1. **Парсинг запроса** — сервер принимает `P2pAssistRequest` (путь, желаемое число каналов, FEC-профиль, флажки Reality). Если путей нет, строит дефолтную пару `primary/backup` на основе домена конфигурации (`default_paths`).
2. **FEC-профиль** — из `FecHint` формируется `FecProfile` (`mtu`, `repair_overhead`), иначе берётся `default_low_latency`.
3. **Выбор транспорта** — `TransportManager::establish_multipath` (см. §2) строит мультипатч-тоннель: сколько удалось поднять путей, какой приоритетный, какие сопротивление/производительность.
4. **FEC-проба** — `MultipathTunnel::encode_frame` кодирует случайный payload (используется RaptorQ). На лету собираются метрики: количество сегментов, доля repair-пакетов, успешность восстановления на приёмной стороне.
5. **Криптография** — генерируются временные ключи:
   - Noise: seed (32 байта), static public, prologue — через `DeviceKeyPair::from_seed` + `build_handshake` (XK, инициатор).
   - PQ: `PqxdhBundle::generate` выдаёт ML-KEM/ML-DSA связку (identity, signed prekey, KEM, подпись).
6. **ICE** — `build_ice_advice` формирует `username_fragment`, `password`, TTL и keepalive interval. Значения ограничены `pairing_ttl_seconds`/`connection_keepalive` из конфига.
7. **Obfuscation** — `build_obfuscation_advice` подсвечивает флаги Reality / domain fronting / Shadowsocks / Tor в зависимости от реальных путей.
8. **Security snapshot** — `Metrics::security_snapshot` в ответе отражает агрегированные показатели (handshake success, censorship и т.д.).

Результат: `P2pAssistResponse` содержит всё необходимое для установки клиентом мультипатч Noise-тоннеля и ICE-креды для NAT traversal.

## 2. Транспортный слой и мультипатч

Ключевые сущности: `TransportManager`, `PluggableTransport`, `MultipathTunnel` (`crates/server/src/transport/mod.rs`).

- **Оценка сети** — перед выбором транспорта вызывается `assess_network_conditions`: до трёх TCP-подключений с тайм-аутом 200 мс; собираются `rtt`, успехи/потери, оценка доступной полосы.
- **Оценка цензуры** — каждый транспорт реализует `detect_censorship`. Например, Reality проверяет blake3-хэш сертификата и делает два TCP-проба; при нулевом успехе возвращает `TransportError::Censorship`.
- **Скоринг** — `score_transport` учитывает устойчивость (ResistanceLevel), производительность (latency/throughput tiers), качество сети и флаг цензуры. Чем выше балл, тем раньше пробуем транспорт.
- **Fallback-chain** — после исчерпания основного списка задействуется цепочка `Reality → AmnesiaWG → QuicMasque → Shadowsocks → WebSocket → Dns → Onion` (без повторов текущего транспорта).
- **Multipath** — `establish_multipath` сортирует `MultipathEndpoint` по `priority`, пытается поднять соединения, пока не наберёт `min_paths`. Успешные пути заворачиваются в `MultipathTunnel` с единым FEC-профилем.
- **Известные ограничения**: большинство транспорта (`Reality`, `Shadowsocks`, `AmnesiaWg`, `QuicMasque`, `Dns`, `Onion`) пока возвращают in-memory `tokio::io::duplex` через `memory_stream()` ⇒ настоящий сетевой канал не подключён (см. TODO F052 в `feature_todo_register.md`). Реальный data-path реализован только для WebSocket. Это надо учитывать при планировании — assist выдаёт живые метрики только для WebSocket, остальные пути пока «фиктивны».

## 3. NAT traversal через сервер (`/p2p` WebSocket)

Маршрут: `GET /p2p` → `App::process_p2p_websocket` (`crates/server/src/app/mod.rs`).

1. **Upgrade** — используется тот же `ConnectChannel::upgrade_websocket`, что и для `/connect`. Требуется `GET`, `Upgrade: websocket`, `Connection: upgrade`, `Sec-WebSocket-Version: 13`.
2. **Регистрация сессии** — первая бинарная/текстовая рамка за 10 с должна содержать `session_id` (UTF-8). Пустой или просроченный ID отклоняется.
3. **Хранилище сессий** — `AppState::p2p_sessions` (`RwLock<HashMap<session_id, P2pSession>>`). Каждая запись хранит `peer_a`, `peer_b`, время создания. Перед использованием выполняется `retain` для очистки устаревших (>120 с).
4. **Согласование** — первый подключившийся клиент ждёт второго до 30 с (poll каждые 100 мс). Как только оба `mpsc::Sender` заполнены, обе стороны получают `OK` и запускается релей.
5. **Релей** — `relay_p2p_bidirectional`: `tokio::select!` слушает две стороны, таймаут на чтение 60 с, канал `mpsc` ёмкостью 100 сообщений. При разрыве любой стороны соединение закрывается, сессия удаляется.
6. **Безопасность & риски**:
   - Нет аутентикации кода сессии ⇒ любой клиент, знающий `session_id`, может перехватить соединение (важно генерировать криптографически стойкие ID на клиенте и экранировать в протоколе).
   - В отсутствие keepalive сервер полагается на таймауты `read_chunk`. Клиентам рекомендуется слать «пустые» кадры или ping WebSocket.
   - Удаление сессии происходит сразу после завершения релея; повторное подключение требует нового `session_id`.

## 4. Каналы `/connect`: Binary, SSE, Long-Poll, WebSocket

### 4.1 Маршрутизация режима

`detect_connect_mode` определяет режим в приоритетном порядке: `mode`/`transport` в query → `X-Connect-Mode` → `X-CommuCat-Connect-Mode` → стандартный WebSocket upgrade → `Accept: text/event-stream` → по умолчанию Binary.

### 4.2 HTTP-варианты (Binary / SSE / Long-Poll)

- Ответ формируется через `HttpChannel`. Заголовки: `Content-Type`, `Cache-Control: no-store`, `X-CommuCat-Connect-Mode`. Для SSE добавляется `Connection: keep-alive` и прокладывается префикс `:ready\n\n` (комментарий-команда).
- `write_payload`:
  - **Binary** — пишет байты кадра напрямую в тело HTTP/2.
  - **SSE** — кодирует payload в base64 (`event: frame`, `id`, `data`), разделяет двойным переводом строки.
  - **Long-Poll** — сериализует JSON `{channel, sequence, type, data}` + перевод строки (NDJSON).
- Недочёты: 
  - SSE-канал не отправляет периодические комментарии → на некоторых L7-проксах соединение может прерваться, если нет трафика (стоит добавить keepalive-комментарии).
  - Long-Poll режим реализован как «вечный» NDJSON-стрим (по сути Comet), но не ограничивает размер очереди: клиенты должны быстро читать поток.

### 4.3 WebSocket режим для `/connect`

- Использует `ConnectChannel::upgrade_websocket`. После апгрейда трафик проходит через `WebSocketChannel`, который поддерживает бинарные кадры и base64-текстовые (fallback). Ping → Pong обрабатывается.
- Проблемы: нет ограничений на размер кадра; полезно добавить лимиты + защиту от Slowloris.

## 5. Выявленные проблемы и риски

| Область | Наблюдение | Риск / влияние | Рекомендуемое действие |
|---------|------------|----------------|------------------------|
| Транспорты | `Reality`, `Shadowsocks`, `AmnesiaWg`, `QuicMasque`, `Dns`, `Onion` используют `memory_stream()` вместо реального соединения | Assist выдаёт фиктивные пути, клиенты не получают реального мультипата (один WebSocket) | Реализовать data-path (см. задачи F052–F055) либо помечать транспорты как экспериментальные в ответе |
| P2P relay | Отсутствует проверка подлинности `session_id`, нет MAC/подписи | Захват сессии при угадывании ID, особенно если клиент использует предсказуемые значения | Генерировать `session_id` только на сервере в привязке к аутентифицированному каналу или подписывать client-generated ID |
| P2P relay | Очистка сессий выполняется только по истечении 120 с или завершении релея; нет keepalive | Зависшие сессии могут удерживать память/слоты, при сетевых сбоях релей может не закрыться | Добавить heartbeat (WebSocket ping) и финальный GC-проход по расписанию |
| `/connect` SSE | Нет периодических комментариев/keepalive | Промежуточные прокси могут закрывать «тихие» SSE (idle timeout) | Ввести `:ping\n\n` каждые N секунд, параметризовать интервал |
| `/connect` WebSocket | Нет лимита размера кадра/скорости чтения | Возможность DoS большим бинарным кадром | Ввести ограничение через `tungstenite::protocol::frame::coding::CloseCode::Size` или кастомный `StreamExt::next` с проверками |
| `/connect` Long-Poll | Потоковый NDJSON без backpressure | Медленные клиенты накапливают буфер в Pingora | Добавить предел outstanding-кадров/разрыв соединения при превышении |

## 6. Ссылки по коду

- `crates/server/src/app/p2p.rs` — реализация `/api/p2p/assist`.
- `crates/server/src/app/mod.rs` — `/connect` режимы, `/p2p` релей.
- `crates/server/src/transport/mod.rs` — менеджер транспортов, FEC, WebSocket адаптер.
- `docs/feature_todo_register.md` — список задач с идентификаторами F0xx (используйте при обновлении статуса).
- `docs/CONNECT_MODES_TROUBLESHOOTING.md` — пользовательский гид по каналам и ожидаемым запросам.

## 7. Следующие шаги

1. **Реализовать реальные data-path для альтернативных транспортов** (F052) и повторно откалибровать оценку устойчивости.
2. **Укрепить безопасность релея**: подписанные `session_id`, интеграция с аутентификацией WebSocket клиента.
3. **Добавить keepalive и лимиты** для SSE/Long-Poll/WebSocket, чтобы исключить обрывы и DoS.
4. **Расширить тестовое покрытие** — интеграционные сценарии по задачам F050 и F055, чтобы ловить регрессии в каналах связи.
