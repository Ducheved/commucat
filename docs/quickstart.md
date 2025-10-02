# CommuCat Quick Start

Пошаговое руководство по запуску прототипа CommuCat в локальной среде. Документ покрывает сценарий разработки/тестирования и не является продакшен-гайдом.

---

## 1. Предварительные требования

| Компонент | Минимальная версия | Примечания |
|-----------|--------------------|------------|
| Rust toolchain | nightly 2024-02-01 или новее | Edition 2024 требует nightly (`rustup toolchain install nightly`). |
| PostgreSQL | 15+ (тестировалось с 15/16/17) | Необходима база `commucat`. Пользователь должен иметь права на создание таблиц. |
| Redis | 6+ | Используется для presence и маршрутизации. |
| OpenSSL / LibreSSL | для генерации ключей | Можно воспользоваться `openssl rand -hex`. |
| Git, C toolchain | стандартный набор для сборки Rust + зависимостей (libvpx, audiopus). |

Для Windows рекомендуется WSL2 или MSYS2: CLI читает случайность из `/dev/urandom`, а серверу требуется доступ к `libvpx` (собирается автоматически через `env-libvpx-sys`).

---

## 2. Клонирование и подготовка окружения

```bash
# клонируем репозиторий
git clone https://github.com/ducheved/commucat.git
cd commucat

# переключаемся на nightly
rustup override set nightly

# устанавливаем зависимости Rust
cargo fetch
```

Создайте файл окружения (по желанию) `commucat.env`:

```ini
COMMUCAT_PG_DSN=postgres://commucat:commucat@localhost/commucat
COMMUCAT_REDIS_URL=redis://127.0.0.1:6379
COMMUCAT_FEDERATION_SEED=$(openssl rand -hex 32)
COMMUCAT_TLS_CERT=certs/server.crt
COMMUCAT_TLS_KEY=certs/server.key
COMMUCAT_NOISE_PRIVATE=$(openssl rand -hex 32)
COMMUCAT_NOISE_PUBLIC=$(openssl rand -hex 32) # см. ниже для генерации
COMMUCAT_DOMAIN=commucat.local
```

> ⚠️ `COMMUCAT_NOISE_PUBLIC` должен соответствовать `COMMUCAT_NOISE_PRIVATE`. Сгенерируйте пару через `commucat-cli rotate-keys` или `commucat-server` helper (см. п. 3.2).

---

## 3. Настройка секретов и баз данных

### 3.1 PostgreSQL и Redis

```bash
# создаём базу данных (пример для PostgreSQL 16)
createdb commucat
createuser commucat
psql -d postgres -c "ALTER USER commucat WITH PASSWORD 'commucat';"
psql -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE commucat TO commucat;"

# Redis достаточно запустить с настройками по умолчанию (порт 6379)
redis-server
```

### 3.2 Генерация Noise ключей и сертификатов

1. Сгенерируйте Noise static ключ:
   ```bash
   # выводит приватный/публичный ключи для Noise
   cargo run -p commucat-cli -- rotate-keys --handle bootstrap --device noise-bootstrap \
     | rg 'public_key=' | cut -d '=' -f2
   ```
   Скопируйте `public_key` в конфиг (`COMMUCAT_NOISE_PUBLIC`). Приватный ключ используйте для `COMMUCAT_NOISE_PRIVATE`.

2. Создайте файл `commucat.toml` (можно взять `commucat.toml` в корне и заменить значения):
   ```toml
   [server]
   bind = "0.0.0.0:9443"
   domain = "commucat.local"
   tls_cert = "certs/server.crt"
   tls_key = "certs/server.key"
   auto_approve_devices = true
   max_auto_devices_per_user = 2

   [storage]
   postgres_dsn = "postgres://commucat:commucat@localhost/commucat"
   redis_url = "redis://127.0.0.1:6379"

   [crypto]
   noise_private = "<hex32>"
   noise_public  = "<hex32>"
   federation_seed = "<hex64>"
   prologue = "commucat"
   ```

3. Подготовьте самоподписанный TLS-сертификат (для локальных тестов):
   ```bash
   mkdir -p certs
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
     -days 365 -nodes -subj '/CN=commucat.local'
   ```

---

## 4. Применение миграций и базовая инициализация

```bash
# применяем SQL миграции
cargo run -p commucat-cli -- migrate

# создаём первого пользователя
cargo run -p commucat-cli -- register-user alice "Alice" "https://example.com/avatar.png"

# выдаём устройству сертификат (опционально)
cargo run -p commucat-cli -- rotate-keys --handle alice
```

Команда `rotate-keys` выводит приватный ключ, публичный ключ, сертификат и метаданные. Сохраните их в защищённом месте — это прототип.

---

## 5. Запуск сервера

```bash
# экспортируем переменные (если не используем commucat.env)
export COMMUCAT_CONFIG=$(pwd)/commucat.toml
export COMMUCAT_PG_DSN=postgres://commucat:commucat@localhost/commucat
export COMMUCAT_REDIS_URL=redis://127.0.0.1:6379
export COMMUCAT_FEDERATION_SEED=<hex>

# сборка и запуск
cargo run -p commucat-server --release
```

Сервер слушает `https://0.0.0.0:9443`. В логах (`tracing` JSON) появится сообщение `"commucat listening"`.

Проверка сервисов:

```bash
curl -k https://commucat.local:9443/healthz
curl -k https://commucat.local:9443/readyz
curl -k -H "Authorization: Bearer <session_id>" https://commucat.local:9443/metrics
```

Чтобы получить `session_id`, подключитесь клиентом CCP‑1 или используйте тестовую утилиту (не включена в репозиторий).

---

---

## 6. Работа с пользователями: user_id vs handle

CommuCat использует два типа идентификаторов пользователей:

| Идентификатор | Описание | Пример | Использование |
|---------------|----------|--------|---------------|
| **user_id** | Уникальный внутренний ID | `user-abc123` | Генерируется сервером, используется во внутренней логике |
| **handle** | Читаемое имя пользователя | `alice`, `duchesss` | Удобно для пользователей, уникально |

### API принимает оба формата

**Хорошая новость:** Большинство API-эндпоинтов, которые принимают параметр `{user_id}` в пути URL, могут работать **как с user_id, так и с handle**. Сервер автоматически определяет тип идентификатора.

**Примеры:**

```bash
# Отправить запрос в друзья по handle
POST /api/friends/requests/duchesss

# Или по user_id
POST /api/friends/requests/user-abc123

# Оба работают!
```

### Эндпоинты, поддерживающие оба формата:

- `POST /api/friends/requests/{user_id}` - отправить запрос в друзья
- `POST /api/friends/requests/{user_id}/accept` - принять запрос
- `POST /api/friends/requests/{user_id}/reject` - отклонить запрос
- `GET /api/friends/{user_id}/devices` - получить устройства друга
- `DELETE /api/friends/{user_id}` - удалить друга

### Как это работает?

1. Сервер сначала пытается найти пользователя по `user_id`
2. Если не находит, пробует найти по `handle`
3. Если не находит и там, возвращает `404 Not Found`

### Рекомендации:

- **В клиентских приложениях:** используйте `handle` для удобства пользователей
- **Во внутренней логике:** предпочитайте `user_id` для надёжности
- **При хранении ссылок:** сохраняйте `user_id`, так как `handle` может измениться

---

## 7. Полезные команды во время разработки

```bash
# симуляция медиапайплайна Opus
cargo run -p commucat-cli -- call-simulate 100

# форматирование и статический анализ
cargo fmt --all
cargo clippy --all-targets --all-features

# запуск модульных тестов конкретного крейта
cargo test -p commucat-proto
```

При необходимости поменяйте фичи медиакодеков, добавив флаги при сборке:

```bash
cargo build -p commucat-server --features media-h264
```

---

## 7. Очистка и остановка

- Остановите `commucat-server` (`Ctrl+C`).
- Для очистки данных:
  ```bash
  dropdb commucat
  redis-cli FLUSHALL
  ```
- Сбросите override toolchain: `rustup override unset`.

---

## 8. Что дальше

- Ознакомьтесь с [ROADMAP.md](../ROADMAP.md) и текущими задачами в [`docs/todo.md`](todo.md).
- Проверьте архитектурный отчёт [ARCHITECT.md](../ARCHITECT.md) перед тем как переносить прототип в прод.
- Отправьте обратную связь через issue/PR или team@commucat.tech.

Удачной охоты! 🐾
