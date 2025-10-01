# CommuCat TODO

| Фича | Категория | Релиз по roadmap | Статус | Примечания |
|------|-----------|------------------|--------|------------|
| One-line installer (Postgres/Redis/ключи) | Операции | CommuCat 1.2 (2025 Q4) | Planned | Нужен удобный bootstrap-скрипт под Linux/Windows. |
| Авто-ротация ключей устройств (CSR + KeyUpdate) | Безопасность | CommuCat 1.2 (2025 Q4) | Done | Реализовано в `POST /api/device/csr`, уведомления через `FrameType::KeyUpdate`. |
| CLI onboarding (`commucat-cli autopair`) | DX | CommuCat 1.2 (2025 Q4) | Planned | Требуется автоматизировать bootstrap устройства без пароля. |
| Документация Quick Start | Документация | CommuCat 1.2 (2025 Q4) | Done (Codex 2026-Q1) | Описана в `docs/quickstart.md`. |
| Автовыдача устройств друзей (`/api/friends`) | DX | CommuCat 1.2 (2025 Q4) | Done (Codex 2026-Q1) | Ответы `GET/PUT` возвращают `devices`, добавлен `GET /api/friends/{id}/devices`. |
| Capability renegotiation для медиапрофилей | Медиа / Протокол | CommuCat 1.2 (2025 Q4) | Planned | Нужно динамически переключаться между RAW и Opus/VP8. |
| Серверный H.264 (software, openh264) | Медиа / Протокол | CommuCat 1.2 (2025 Q4) | Planned | Требуется feature `media-h264` и интеграция в пайплайн. |
| Черновик CCP-2 (форматы, multipath) | Протокол | CommuCat 1.2 (2025 Q4) | Planned | Подготовить спеку/POC второго протокола. |
| Pluggable transports (Reality/AmnesiaWG/Shadowsocks/VLESS/Onion) | Транспорт / Антицензура | CommuCat 1.5 (2026 H1) | Planned | Реализовать реальные драйверы вместо заглушек. |
| TOR proxy + автоматический fallback | Транспорт / Антицензура | CommuCat 1.5 (2026 H1) | Planned | Интеграция с TOR и fallback стратегия при блокировках. |
| AdaptiveObfuscator + policy-файл | Транспорт / Антицензура | CommuCat 1.5 (2026 H1) | Planned | Управление обфускацией на основе политик. |
| PQ-гибрид ML-KEM-768 + ML-DSA-65 в основном туннеле | Криптография | CommuCat 1.5 (2026 H1) | Planned | Смешанный ключевой материал для Noise-потока. |
| Минимальный ZKP для доказательства владения устройством | Криптография | CommuCat 1.5 (2026 H1) | Planned | Проверка владения приватным ключом устройства. |
| Federation event API (подпись + валидация) | Федерация | CommuCat 1.5 (2026 H1) | In progress (Codex 2026-Q1) | Включена очередь и HTTP `/federation/events`; остались ретраи и прод-мониторинг. |
| Gossip discovery и авто-регистрация узлов | Федерация | CommuCat 1.5 (2026 H1) | Planned | Распространение пиров и auto-join. |
| Mesh (QUIC + multipath + NAT traversal) | Федерация / Сеть | CommuCat 1.5 (2026 H1) | Planned | Построить mesh-топологию и обход NAT. |
| CCP-2: событийный протокол (CBOR/Protobuf) | Протокол | CommuCat 2.0 (2026 H2) | Planned | Новый формат событий и расширенный handshake. |
| CCP-2: встроенная обфускация и мульти-транспорт | Протокол | CommuCat 2.0 (2026 H2) | Planned | Обеспечить out-of-the-box stealth и выбор транспортов. |
| CCP-2: режим covert chat (mimicry/padding/jitter) | Протокол | CommuCat 2.0 (2026 H2) | Planned | Противодействие анализу трафика. |
| Полный медиатранскодер (FEC, SVC, GPU) | Медиа | CommuCat 2.0 (2026 H2) | Planned | Добавить защиту от потерь, масштабируемость и GPU-ускорение. |
| Мультипут аудио/видео + адаптивный битрейт | Медиа | CommuCat 2.0 (2026 H2) | Planned | Распределение потоков по нескольким каналам с BWE. |
| Паролесный UX (device ⇄ профиль ⇄ recovery) | Пользовательский опыт | CommuCat 2.0 (2026 H2) | Planned | Социальное восстановление, привязка устройств без пароля. |
| Клиенты: Flutter / Swift / C# | Клиенты | CommuCat 2.0 (2026 H2) | Planned | Нативные приложения под мобильные/desktop платформы. |
| Wallet API и хранение ключей (L2/ERC20/BTC/Ton) | Блокчейн | CommuCat 2.0 (2026 H2) | Planned | Управление кошельком и интеграция с сервисом. |
| Чат-фичи: tip/escrow/micropayments | Блокчейн | CommuCat 2.0 (2026 H2) | Planned | Расширение чата микроплатежами. |
| Запись хэшей сообщений в блокчейн | Блокчейн | CommuCat 2.0 (2026 H2) | Planned | Неизменяемые аудиторские следы. |
| Социальный сервис «всё в одном» (XMPP/IRC/Discord/Telegram/Facebook) | Vision | Beyond 2026 | Planned | Универсальные мосты и мульти-платформенная интеграция. |
| Mesh по Wi-Fi Direct/BLE и оффлайн синхронизация | Vision | Beyond 2026 | Planned | Edge-ноды и оффлайн режимы. |
| Bridge к Signal/Matrix/WireGuard | Vision | Beyond 2026 | Planned | Совместимость с популярными протоколами. |
| Полная автоматизация (Helm/Operators/Marketplaces) | Vision | Beyond 2026 | Planned | DevOps-автоматизация и дистрибуция. |
| Anti-DPI/steganography/AI avoidance исследования | Vision | Beyond 2026 | Planned | Исследования по сокрытию трафика и сопротивляемость. |
