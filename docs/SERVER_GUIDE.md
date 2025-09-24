# CommuCat Server Guide

Подробное руководство по устройству, настройке и эксплуатации CommuCat. Быстрый старт описан в `README.md`, здесь сосредоточены практические детали и расширенные объяснения.

## Архитектура

- **commucat-server**: процесс Pingora, завершающий TLS, выполняющий Noise-хэндшейк и маршрутизацию кадров CCP-1. Держит активные каналы, публикует presence в Redis, пишет агрегаты в ledger.
- **PostgreSQL**: долговременное хранилище. Основные таблицы: `app_user`, `user_device`, `session`, `relay_queue`, `device_key_event`, `chat_group`, `group_member`, `federation_peer`, `inbox_offset`.
- **Redis**: краткоживущие данные (`presence:{device}`, `route:{device}`) и лёгкие TTL-таблицы для прерывания соединений.
- **Ledger адаптер**: опциональная внешняя система аудита (file/debug/null) для фиксации сессий и изменений ключей.

Компоненты работают по принципу минимального доверия: сервер не видит содержимого кадров, но фиксирует метаданные и события для последующего расследования.

## Подготовка окружения

1. PostgreSQL ≥ 12 (рекомендовано 17), доступная запись. Создайте базу и роль, например:
   ```sql
   CREATE ROLE commucat WITH LOGIN PASSWORD 'secret';
   CREATE DATABASE commucat OWNER commucat;
   ```
2. Redis ≥ 6 для presence и маршрутов.
3. TLS-сертификат (самоподписанный или выданный CA).
4. Rust toolchain `stable` (минимум 1.75) и `pkg-config`/OpenSSL для сборки.

## Конфигурирование

Основной файл `commucat.toml`:

- `[server]`: bind, TLS файлы, домен, `auto_approve_devices`, `keepalive`.
- `[storage]`: строки подключения к PostgreSQL и Redis.
- `[crypto]`: Noise ключи, сид подписи федерации, prologue.
- `[federation]`: статические доверенные домены. Они объединяются с динамическими записями `federation_peer`.
- `[limits]`: `presence_ttl`, `relay_ttl`.
- `[admin]`: опциональный bearer-токен для `GET /metrics`.

Бинарь читает окружение `COMMUCAT_*`, которые переопределяют TOML (см. `.env.sample`). Для прогонов тестов добавлены `COMMUCAT_TEST_PG_DSN` и `COMMUCAT_TEST_REDIS_URL` — они позволяют запускать интеграционные тесты слоя хранилища.

## Группы и роли

- `GROUP_CREATE` регистрирует запись в `chat_group`, сохраняет владельца и всех перечисленных участников в `group_member`. Пример полезной нагрузки:
  ```json
  {
    "group_id": "grp-optional",
    "members": ["device-owner", "device-peer"],
    "roles": {"device-peer": "admin"},
    "relay": true
  }
  ```
- `GROUP_INVITE` добавляет участника. Допустимые роли: `member`, `admin`. Запросы на `owner` автоматически понижаются до `admin`, чтобы избежать расщепления полномочий.
- В `JOIN` клиент может указать `group_id`; сервер сверит его с БД и отклонит участника, отсутствующего в `group_member`.
- Удаление участника (`remove_group_member`) снимает запись и обновляет кэш маршрутов.

## Аудит ключей устройств

Каждая авто-активация или ротация ключа фиксируется в `device_key_event`. Событие содержит `event_id`, `device_id`, публичный ключ и время. Хэндшейк откажется, если вставка не удалась — это предотвращает появление «серых» устройств без следа в журнале.

CLI `commucat-cli rotate-keys` использует те же механизмы и автоматически создаёт запись в таблице. Для отчётности можно выгрузить историю по `device_id` и сверить её с ledger.

## Очереди и оффлайн-доставка

- `relay_queue` хранит зашифрованные кадры `payload` для устройств вне сети. Ключ — `inbox:{device_id}`.
- `inbox_offset` запоминает последний выданный `envelope_id` для пары `(entity_id, channel_id)`. Это помогает клиентам возобновить загрузку без дубликатов и служит аудитом.
- При подключении сервер удаляет из `relay_queue` до 128 конвертов, повторно кодирует их с новыми sequence, обновляет `inbox_offset`, отправляет кадры по активному каналу.

## Федерация

- `federation_peer` хранит домен, endpoint HTTPS, публичный ключ и статус (`active`, `pending`, `blocked`).
- Конфигурация `[federation]` задаёт жёстко доверенные домены; новые пэры могут появиться динамически — сервер поднимет статус с `pending` до `active`, как только зафиксирует необходимость отправки трафика.
- События федерации (`FederationEvent`) подписываются Ed25519-ключом `crypto.federation_seed`. Проверка на принимающей стороне должна валидировать digest и подпись.

## Нагрузочное тестирование

- Локальный smoke-тест: `cargo test`. Интеграция с настоящими Postgres/Redis включается, если выставлены `COMMUCAT_TEST_PG_DSN` и `COMMUCAT_TEST_REDIS_URL`.
- Простой сценарий нагрузки: сгенерируйте 1000 кадров (`FrameType::Msg`) — тест `encode_large_batch` в `commucat-proto` демонстрирует верхние границы кодека.
- Для прикладного теста маршрутизации поднимите два клиента, выполните `GROUP_CREATE`, отправьте 10k кадров в relay-режиме и убедитесь, что `relay_queue` и `inbox_offset` растут линейно и освобождаются при повторном подключении.

## Диагностика и мониторинг

- `GET /healthz` — базовая проверка жизнеспособности процесса.
- `GET /readyz` — проверяет Postgres/Redis (использует `Storage::readiness`).
- `GET /metrics` — Prometheus текст, требует `admin.token`, если задан.
- Журналы содержат события ротации ключей (`device_key_event`), доставки кадров (`delivered frame`), федерации (`federation event queued`).

## Troubleshooting

| Симптом | Проверка |
|---------|----------|
| `storage failure` | DSN, права роли, миграции (`commucat-cli migrate`). |
| `redis failure` | Доступность Redis, ACL, правильный DB index. |
| `group join rejected` | Убедитесь, что устройство числится в `group_member` и послало актуальный `GROUP_INVITE`. |
| `federation peer not allowed` | Добавьте запись в `[federation]` или предварительно занесите строку в `federation_peer` со статусом `active`. |

## Roadmap / TODO

- TTL/cleanup для `device_key_event` с архивированием в внешнем объектном хранилище.
- Расширенная модель ролей групп (владелец → совладельцы). 
- Push-репликация `inbox_offset` в федеративные домены.
- Аналитика отправленных кадров на основе `inbox_offset` и ledger.
