use chrono::{DateTime, Utc};
use serde_json::Value;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls};

const INIT_SQL: &str = include_str!("../migrations/001_init.sql");

#[derive(Debug)]
pub enum StorageError {
    Postgres,
    Redis,
    Serialization,
    Missing,
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres => write!(f, "postgres failure"),
            Self::Redis => write!(f, "redis failure"),
            Self::Serialization => write!(f, "serialization failure"),
            Self::Missing => write!(f, "missing record"),
        }
    }
}

impl Error for StorageError {}

pub struct Storage {
    client: Client,
    _pg_task: JoinHandle<()>,
    redis: Arc<Mutex<redis::aio::MultiplexedConnection>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub session_id: String,
    pub device_id: String,
    pub tls_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEnvelope {
    pub envelope_id: String,
    pub channel_id: String,
    pub payload: Vec<u8>,
    pub deliver_after: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKey {
    pub key: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceSnapshot {
    pub entity: String,
    pub state: String,
    pub expires_at: DateTime<Utc>,
}

/// Establishes connectivity to PostgreSQL and Redis backends.
pub async fn connect(postgres_dsn: &str, redis_url: &str) -> Result<Storage, StorageError> {
    let (client, connection) = tokio_postgres::connect(postgres_dsn, NoTls)
        .await
        .map_err(|_| StorageError::Postgres)?;
    let task = tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::error!("postgres connection stopped: {}", error);
        }
    });
    let redis_client = redis::Client::open(redis_url).map_err(|_| StorageError::Redis)?;
    let redis_connection = redis_client
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| StorageError::Redis)?;
    Ok(Storage {
        client,
        _pg_task: task,
        redis: Arc::new(Mutex::new(redis_connection)),
    })
}

impl Storage {
    /// Applies bundled migrations to PostgreSQL.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        self.client
            .batch_execute(INIT_SQL)
            .await
            .map_err(|_| StorageError::Postgres)
    }

    /// Executes lightweight probes across PostgreSQL and Redis.
    pub async fn readiness(&self) -> Result<(), StorageError> {
        self.client
            .simple_query("SELECT 1")
            .await
            .map_err(|_| StorageError::Postgres)?;
        let mut conn = self.redis.lock().await;
        let _: String = redis::cmd("PING")
            .query_async::<_, String>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        Ok(())
    }

    /// Registers or rotates a device key.
    pub async fn upsert_device(&self, record: &DeviceRecord) -> Result<(), StorageError> {
        let query = "INSERT INTO user_device (opaque_id, pubkey, status, created_at) VALUES ($1, $2, $3, $4)
            ON CONFLICT (opaque_id) DO UPDATE SET pubkey = excluded.pubkey, status = excluded.status";
        self.client
            .execute(
                query,
                &[
                    &record.device_id,
                    &record.public_key,
                    &record.status,
                    &record.created_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Creates a session binding a device to a TLS fingerprint.
    pub async fn record_session(&self, session: &SessionRecord) -> Result<(), StorageError> {
        let query =
            "INSERT INTO session (opaque_id, device_id, tls_fingerprint, created_at, ttl_seconds)
            VALUES ($1, $2, $3, $4, $5)";
        self.client
            .execute(
                query,
                &[
                    &session.session_id,
                    &session.device_id,
                    &session.tls_fingerprint,
                    &session.created_at,
                    &session.ttl_seconds,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Fetches device metadata by identifier.
    pub async fn load_device(&self, device_id: &str) -> Result<DeviceRecord, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT opaque_id, pubkey, status, created_at FROM user_device WHERE opaque_id = $1",
                &[&device_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let row = row.ok_or(StorageError::Missing)?;
        Ok(DeviceRecord {
            device_id: row.get(0),
            public_key: row.get(1),
            status: row.get(2),
            created_at: row.get(3),
        })
    }

    /// Schedules an encrypted relay envelope for delivery.
    pub async fn enqueue_relay(&self, envelope: &RelayEnvelope) -> Result<(), StorageError> {
        let query =
            "INSERT INTO relay_queue (envelope_id, channel_id, payload, deliver_after, expires_at)
            VALUES ($1, $2, $3, $4, $5)";
        self.client
            .execute(
                query,
                &[
                    &envelope.envelope_id,
                    &envelope.channel_id,
                    &envelope.payload,
                    &envelope.deliver_after,
                    &envelope.expires_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Claims pending relay envelopes for a channel.
    pub async fn claim_envelopes(
        &self,
        channel_id: &str,
        limit: i64,
    ) -> Result<Vec<RelayEnvelope>, StorageError> {
        let query = "DELETE FROM relay_queue
            WHERE envelope_id IN (
                SELECT envelope_id FROM relay_queue
                WHERE channel_id = $1 AND deliver_after <= now()
                ORDER BY deliver_after ASC
                LIMIT $2
            )
            RETURNING envelope_id, channel_id, payload, deliver_after, expires_at";
        let rows = self
            .client
            .query(query, &[&channel_id, &limit])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| RelayEnvelope {
                envelope_id: row.get(0),
                channel_id: row.get(1),
                payload: row.get(2),
                deliver_after: row.get(3),
                expires_at: row.get(4),
            })
            .collect())
    }

    /// Records an idempotency key for deduplication.
    pub async fn store_idempotency(&self, key: &IdempotencyKey) -> Result<(), StorageError> {
        let query = "INSERT INTO idempotency (key, scope, created_at) VALUES ($1, $2, $3)
            ON CONFLICT (key, scope) DO NOTHING";
        self.client
            .execute(query, &[&key.key, &key.scope, &key.created_at])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Publishes local presence information into Redis.
    pub async fn publish_presence(&self, snapshot: &PresenceSnapshot) -> Result<(), StorageError> {
        let mut conn = self.redis.lock().await;
        let ttl = (snapshot.expires_at.timestamp() - Utc::now().timestamp()).max(1) as usize;
        let payload = serde_json::json!({
            "entity": snapshot.entity,
            "state": snapshot.state,
            "expires_at": snapshot.expires_at.to_rfc3339(),
        })
        .to_string();
        redis::cmd("SETEX")
            .arg(format!("presence:{}", snapshot.entity))
            .arg(ttl)
            .arg(payload)
            .query_async::<_, ()>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        Ok(())
    }

    /// Reads presence state from Redis.
    pub async fn read_presence(
        &self,
        entity: &str,
    ) -> Result<Option<PresenceSnapshot>, StorageError> {
        let mut conn = self.redis.lock().await;
        let value: Option<String> = redis::cmd("GET")
            .arg(format!("presence:{}", entity))
            .query_async::<_, Option<String>>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        if let Some(json) = value {
            let parsed: Value =
                serde_json::from_str(&json).map_err(|_| StorageError::Serialization)?;
            let state = parsed
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("online")
                .to_string();
            let expires = parsed
                .get("expires_at")
                .and_then(|v| v.as_str())
                .ok_or(StorageError::Serialization)?;
            let expires = DateTime::parse_from_rfc3339(expires)
                .map_err(|_| StorageError::Serialization)?
                .with_timezone(&Utc);
            Ok(Some(PresenceSnapshot {
                entity: entity.to_string(),
                state,
                expires_at: expires,
            }))
        } else {
            Ok(None)
        }
    }

    /// Registers a routing entry in Redis for direct message delivery.
    pub async fn register_route(
        &self,
        entity: &str,
        session_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), StorageError> {
        let mut conn = self.redis.lock().await;
        redis::cmd("SETEX")
            .arg(format!("route:{}", entity))
            .arg(ttl_seconds.max(1) as usize)
            .arg(session_id)
            .query_async::<_, ()>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        Ok(())
    }

    /// Removes a routing entry from Redis.
    pub async fn clear_route(&self, entity: &str) -> Result<(), StorageError> {
        let mut conn = self.redis.lock().await;
        let _: () = redis::cmd("DEL")
            .arg(format!("route:{}", entity))
            .query_async::<_, ()>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_sql_exists() {
        assert!(INIT_SQL.contains("CREATE TABLE"));
    }
}
