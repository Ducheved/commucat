use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use serde_json::Value;
use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls};

const INIT_SQL: &str = include_str!("../migrations/001_init.sql");
const PAIRING_SQL: &str = include_str!("../migrations/002_pairing.sql");
const USER_BLOB_SQL: &str = include_str!("../migrations/003_user_blob.sql");
const SERVER_SECRET_SQL: &str = include_str!("../migrations/004_server_secrets.sql");
const DEVICE_ROTATION_SQL: &str = include_str!("../migrations/005_device_rotation.sql");
const FEDERATION_OUTBOX_SQL: &str = include_str!("../migrations/006_federation_outbox.sql");
const FRIEND_REQUESTS_SQL: &str = include_str!("../migrations/007_friend_requests.sql");
const PAIRING_MAX_ATTEMPTS: i32 = 5;
const PAIRING_CODE_LENGTH: usize = 8;
const PAIRING_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

#[derive(Debug)]
pub enum StorageError {
    Postgres,
    Redis,
    Serialization,
    Missing,
    Invalid,
}

impl Display for StorageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postgres => write!(f, "postgres failure"),
            Self::Redis => write!(f, "redis failure"),
            Self::Serialization => write!(f, "serialization failure"),
            Self::Missing => write!(f, "missing record"),
            Self::Invalid => write!(f, "invalid state"),
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
pub struct NewUserProfile {
    pub user_id: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserProfile {
    pub user_id: String,
    pub handle: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub device_id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub session_id: String,
    pub user_id: String,
    pub device_id: String,
    pub tls_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSecretRecord {
    pub name: String,
    pub version: i64,
    pub secret: Vec<u8>,
    pub public: Option<Vec<u8>>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub valid_after: DateTime<Utc>,
    pub rotates_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
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

#[derive(Debug, Clone)]
pub struct FederationOutboxInsert<'a> {
    pub outbox_id: &'a str,
    pub destination: &'a str,
    pub endpoint: &'a str,
    pub payload: &'a serde_json::Value,
    pub public_key: &'a [u8; 32],
    pub next_attempt_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationOutboxMessage {
    pub outbox_id: String,
    pub destination: String,
    pub endpoint: String,
    pub payload: serde_json::Value,
    pub public_key: [u8; 32],
    pub attempts: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceSnapshot {
    pub entity: String,
    pub state: String,
    pub expires_at: DateTime<Utc>,
    pub user_id: Option<String>,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

fn presence_user_payload(snapshot: &PresenceSnapshot) -> Option<serde_json::Value> {
    snapshot.user_id.as_ref().map(|id| {
        let user_id = id.clone();
        serde_json::json!({
            "id": user_id.clone(),
            "user_id": user_id,
            "handle": snapshot.handle.clone(),
            "display_name": snapshot.display_name.clone(),
            "avatar_url": snapshot.avatar_url.clone(),
        })
    })
}

fn presence_user_fields(
    map: &serde_json::Map<String, serde_json::Value>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let user_id = map
        .get("user_id")
        .or_else(|| map.get("id"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let handle = map
        .get("handle")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let display_name = map
        .get("display_name")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let avatar_url = map
        .get("avatar_url")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    (user_id, handle, display_name, avatar_url)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyEvent {
    pub event_id: String,
    pub device_id: String,
    pub public_key: Vec<u8>,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendRequest {
    pub id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub status: String, // 'pending', 'accepted', 'rejected'
    pub message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRotationAudit {
    pub rotation_id: String,
    pub device_id: String,
    pub old_public_key: Vec<u8>,
    pub new_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
    pub proof_expires_at: DateTime<Utc>,
    pub applied_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DeviceRotationRecord<'a> {
    pub rotation_id: &'a str,
    pub device_id: &'a str,
    pub user_id: &'a str,
    pub old_public_key: &'a [u8],
    pub new_public_key: &'a [u8],
    pub signature: &'a [u8],
    pub nonce: Option<&'a [u8]>,
    pub proof_expires_at: DateTime<Utc>,
    pub applied_at: DateTime<Utc>,
    pub event_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTokenIssued {
    pub pair_code: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingClaimResult {
    pub user: UserProfile,
    pub issuer_device_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatGroup {
    pub group_id: String,
    pub owner_device: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
}

impl GroupRole {
    fn as_str(&self) -> &'static str {
        match self {
            GroupRole::Owner => "owner",
            GroupRole::Admin => "admin",
            GroupRole::Member => "member",
        }
    }
}

impl FromStr for GroupRole {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "owner" => Ok(GroupRole::Owner),
            "admin" => Ok(GroupRole::Admin),
            "member" => Ok(GroupRole::Member),
            _ => Err(StorageError::Serialization),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub group_id: String,
    pub device_id: String,
    pub role: GroupRole,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationPeerStatus {
    Active,
    Pending,
    Blocked,
}

impl FederationPeerStatus {
    fn as_str(&self) -> &'static str {
        match self {
            FederationPeerStatus::Active => "active",
            FederationPeerStatus::Pending => "pending",
            FederationPeerStatus::Blocked => "blocked",
        }
    }
}

impl FromStr for FederationPeerStatus {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(FederationPeerStatus::Active),
            "pending" => Ok(FederationPeerStatus::Pending),
            "blocked" => Ok(FederationPeerStatus::Blocked),
            _ => Err(StorageError::Serialization),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPeerRecord {
    pub domain: String,
    pub endpoint: String,
    pub public_key: [u8; 32],
    pub status: FederationPeerStatus,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxOffset {
    pub entity_id: String,
    pub channel_id: String,
    pub last_envelope_id: Option<String>,
    pub updated_at: DateTime<Utc>,
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
            .map_err(|_| StorageError::Postgres)?;
        self.client
            .batch_execute(PAIRING_SQL)
            .await
            .map_err(|_| StorageError::Postgres)?;
        self.client
            .batch_execute(USER_BLOB_SQL)
            .await
            .map_err(|_| StorageError::Postgres)?;
        self.client
            .batch_execute(SERVER_SECRET_SQL)
            .await
            .map_err(|_| StorageError::Postgres)?;
        self.client
            .batch_execute(DEVICE_ROTATION_SQL)
            .await
            .map_err(|_| StorageError::Postgres)?;
        self.client
            .batch_execute(FEDERATION_OUTBOX_SQL)
            .await
            .map_err(|_| StorageError::Postgres)?;
        self.client
            .batch_execute(FRIEND_REQUESTS_SQL)
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Executes lightweight probes across PostgreSQL and Redis.
    pub async fn readiness(&self) -> Result<(), StorageError> {
        self.client
            .simple_query("SELECT 1")
            .await
            .map_err(|_| StorageError::Postgres)?;
        let mut conn = self.redis.lock().await;
        let _: String = redis::cmd("PING")
            .query_async::<String>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        Ok(())
    }

    /// Reads a user-scoped blob entry.
    pub async fn read_user_blob(
        &self,
        user_id: &str,
        key: &str,
    ) -> Result<Option<String>, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT payload FROM user_blob WHERE user_id = $1 AND key = $2",
                &[&user_id, &key],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(row.map(|row| row.get(0)))
    }

    /// Upserts a user-scoped blob entry.
    pub async fn write_user_blob(
        &self,
        user_id: &str,
        key: &str,
        payload: &str,
    ) -> Result<(), StorageError> {
        let now = Utc::now();
        self.client
            .execute(
                "INSERT INTO user_blob (user_id, key, payload, updated_at) VALUES ($1, $2, $3, $4)
                ON CONFLICT (user_id, key) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at",
                &[&user_id, &key, &payload, &now],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Inserts a server-scoped secret version.
    pub async fn insert_server_secret(
        &self,
        record: &ServerSecretRecord,
    ) -> Result<(), StorageError> {
        let query = "INSERT INTO server_secret (name, version, secret, public, metadata, created_at, valid_after, rotates_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)";
        self.client
            .execute(
                query,
                &[
                    &record.name,
                    &record.version,
                    &record.secret,
                    &record.public,
                    &record.metadata,
                    &record.created_at,
                    &record.valid_after,
                    &record.rotates_at,
                    &record.expires_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Loads active secret material for a given name.
    pub async fn active_server_secrets(
        &self,
        name: &str,
        moment: DateTime<Utc>,
    ) -> Result<Vec<ServerSecretRecord>, StorageError> {
        let query = "SELECT name, version, secret, public, metadata, created_at, valid_after, rotates_at, expires_at
            FROM server_secret
            WHERE name = $1 AND valid_after <= $2 AND expires_at > $2
            ORDER BY version DESC";
        let rows = self
            .client
            .query(query, &[&name, &moment])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| ServerSecretRecord {
                name: row.get(0),
                version: row.get(1),
                secret: row.get(2),
                public: row.get(3),
                metadata: row.get(4),
                created_at: row.get(5),
                valid_after: row.get(6),
                rotates_at: row.get(7),
                expires_at: row.get(8),
            })
            .collect())
    }

    /// Returns the most recent version number for a secret name.
    pub async fn latest_server_secret_version(&self, name: &str) -> Result<i64, StorageError> {
        let row = self
            .client
            .query_one(
                "SELECT COALESCE(MAX(version), 0) FROM server_secret WHERE name = $1",
                &[&name],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(row.get(0))
    }

    /// Deletes expired secret versions.
    pub async fn delete_expired_server_secrets(
        &self,
        name: &str,
        threshold: DateTime<Utc>,
    ) -> Result<u64, StorageError> {
        let affected = self
            .client
            .execute(
                "DELETE FROM server_secret WHERE name = $1 AND expires_at <= $2",
                &[&name, &threshold],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(affected)
    }

    /// Creates a short-lived pairing code bound to an issuer device.
    pub async fn create_pairing_token(
        &self,
        user_id: &str,
        issuer_device_id: &str,
        ttl_seconds: i64,
    ) -> Result<PairingTokenIssued, StorageError> {
        let issuer = self.load_device(issuer_device_id).await?;
        if issuer.user_id != user_id || issuer.status != "active" {
            return Err(StorageError::Invalid);
        }
        let ttl = ttl_seconds.clamp(60, 3600);
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(ttl);
        for _ in 0..16 {
            let pair_code = generate_pair_code();
            let inserted = self
                .client
                .execute(
                    "INSERT INTO device_pairing (pair_code, user_id, issuer_device_id, issued_at, expires_at)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (pair_code) DO NOTHING",
                    &[&pair_code, &user_id, &issuer_device_id, &issued_at, &expires_at],
                )
                .await
                .map_err(|_| StorageError::Postgres)?;
            if inserted == 1 {
                return Ok(PairingTokenIssued {
                    pair_code,
                    issued_at,
                    expires_at,
                });
            }
        }
        Err(StorageError::Postgres)
    }

    /// Registers or rotates a device key.
    pub async fn upsert_device(&self, record: &DeviceRecord) -> Result<(), StorageError> {
        let query = "INSERT INTO user_device (opaque_id, user_id, pubkey, status, created_at) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (opaque_id) DO UPDATE SET pubkey = excluded.pubkey, status = excluded.status
            WHERE user_device.user_id = excluded.user_id";
        self.client
            .execute(
                query,
                &[
                    &record.device_id,
                    &record.user_id,
                    &record.public_key,
                    &record.status,
                    &record.created_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Persists an audit trail entry for device key material.
    pub async fn record_device_key_event(
        &self,
        event: &DeviceKeyEvent,
    ) -> Result<(), StorageError> {
        let query = "INSERT INTO device_key_event (event_id, device_id, public_key, recorded_at) VALUES ($1, $2, $3, $4)";
        self.client
            .execute(
                query,
                &[
                    &event.event_id,
                    &event.device_id,
                    &event.public_key,
                    &event.recorded_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Applies a device key rotation atomically.
    pub async fn apply_device_key_rotation(
        &self,
        rotation: &DeviceRotationRecord<'_>,
    ) -> Result<(), StorageError> {
        self.client
            .batch_execute("BEGIN")
            .await
            .map_err(|_| StorageError::Postgres)?;
        let update_result = self
            .client
            .execute(
                "UPDATE user_device SET pubkey = $1 WHERE opaque_id = $2 AND user_id = $3",
                &[
                    &rotation.new_public_key,
                    &rotation.device_id,
                    &rotation.user_id,
                ],
            )
            .await;
        let updated = match update_result {
            Ok(value) => value,
            Err(_) => {
                let _ = self.client.batch_execute("ROLLBACK").await;
                return Err(StorageError::Postgres);
            }
        };
        if updated != 1 {
            let _ = self.client.batch_execute("ROLLBACK").await;
            return Err(StorageError::Missing);
        }
        if self
            .client
            .execute(
                "INSERT INTO device_key_event (event_id, device_id, public_key, recorded_at) VALUES ($1, $2, $3, $4)",
                &[&rotation.event_id, &rotation.device_id, &rotation.new_public_key, &rotation.applied_at],
            )
            .await
            .is_err()
        {
            let _ = self.client.batch_execute("ROLLBACK").await;
            return Err(StorageError::Postgres);
        }
        if self
            .client
            .execute(
                "INSERT INTO device_rotation_audit (rotation_id, device_id, old_public_key, new_public_key, signature, nonce, proof_expires_at, applied_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &rotation.rotation_id,
                    &rotation.device_id,
                    &rotation.old_public_key,
                    &rotation.new_public_key,
                    &rotation.signature,
                    &rotation.nonce,
                    &rotation.proof_expires_at,
                    &rotation.applied_at,
                ],
            )
            .await
            .is_err()
        {
            let _ = self.client.batch_execute("ROLLBACK").await;
            return Err(StorageError::Postgres);
        }
        if self.client.batch_execute("COMMIT").await.is_err() {
            let _ = self.client.batch_execute("ROLLBACK").await;
            return Err(StorageError::Postgres);
        }
        Ok(())
    }

    /// Claims a pairing token and registers a new device for the associated user.
    pub async fn claim_pairing_token(
        &self,
        pair_code: &str,
        device_id: &str,
        public_key: &[u8],
    ) -> Result<PairingClaimResult, StorageError> {
        let recorded_at = Utc::now();
        let event_id = format!(
            "pair:{}:{}",
            device_id,
            recorded_at.timestamp_nanos_opt().unwrap_or_default()
        );
        let stmt = "WITH selected AS (
                SELECT user_id, issuer_device_id, expires_at, redeemed_at, attempts
                FROM device_pairing
                WHERE pair_code = $1
                FOR UPDATE
            ),
            validated AS (
                SELECT user_id, issuer_device_id
                FROM selected
                WHERE expires_at > now()
                  AND redeemed_at IS NULL
                  AND attempts < $6
            ),
            updated AS (
                UPDATE device_pairing
                SET redeemed_at = $5,
                    redeemed_device_id = $2,
                    public_key = $3,
                    attempts = LEAST(attempts + 1, $6)
                WHERE pair_code = $1
                  AND EXISTS (SELECT 1 FROM validated)
                RETURNING user_id, issuer_device_id
            ),
            inserted AS (
                INSERT INTO user_device (opaque_id, user_id, pubkey, status, created_at)
                SELECT $2, user_id, $3, 'active', $5 FROM validated
                RETURNING user_id
            ),
            events AS (
                INSERT INTO device_key_event (event_id, device_id, public_key, recorded_at)
                SELECT $4, $2, $3, $5 FROM inserted
            )
            SELECT user_id, issuer_device_id FROM updated";
        let result = self
            .client
            .query_opt(
                stmt,
                &[
                    &pair_code,
                    &device_id,
                    &public_key,
                    &event_id,
                    &recorded_at,
                    &PAIRING_MAX_ATTEMPTS,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let (user_id, issuer_device_id) = match result {
            Some(row) => {
                let user_id: String = row.get(0);
                let issuer_device_id: String = row.get(1);
                (user_id, issuer_device_id)
            }
            None => {
                let exists = self
                    .client
                    .query_opt(
                        "SELECT 1 FROM device_pairing WHERE pair_code = $1",
                        &[&pair_code],
                    )
                    .await
                    .map_err(|_| StorageError::Postgres)?;
                if exists.is_some() {
                    self
                        .client
                        .execute(
                            "UPDATE device_pairing SET attempts = LEAST(attempts + 1, $2) WHERE pair_code = $1",
                            &[&pair_code, &PAIRING_MAX_ATTEMPTS],
                        )
                        .await
                        .map_err(|_| StorageError::Postgres)?;
                    return Err(StorageError::Invalid);
                }
                return Err(StorageError::Missing);
            }
        };
        let profile = self.load_user(&user_id).await?;
        Ok(PairingClaimResult {
            user: profile,
            issuer_device_id,
        })
    }

    /// Removes expired or exhausted pairing tokens.
    pub async fn invalidate_expired_pairings(&self) -> Result<u64, StorageError> {
        let affected = self
            .client
            .execute(
                "DELETE FROM device_pairing WHERE expires_at <= now() OR attempts >= $1 OR (redeemed_at IS NOT NULL AND redeemed_at <= now() - interval '1 day')",
                &[&PAIRING_MAX_ATTEMPTS],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(affected)
    }

    /// Fetches the newest device key event for a device identifier.
    pub async fn latest_device_key_event(
        &self,
        device_id: &str,
    ) -> Result<Option<DeviceKeyEvent>, StorageError> {
        let query = "SELECT event_id, device_id, public_key, recorded_at
            FROM device_key_event WHERE device_id = $1 ORDER BY recorded_at DESC LIMIT 1";
        let row = self
            .client
            .query_opt(query, &[&device_id])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(row.map(|row| DeviceKeyEvent {
            event_id: row.get(0),
            device_id: row.get(1),
            public_key: row.get(2),
            recorded_at: row.get(3),
        }))
    }

    /// Creates a session binding a device to a TLS fingerprint.
    pub async fn record_session(&self, session: &SessionRecord) -> Result<(), StorageError> {
        let query =
            "INSERT INTO session (opaque_id, user_id, device_id, tls_fingerprint, created_at, ttl_seconds)
            VALUES ($1, $2, $3, $4, $5, $6)";
        self.client
            .execute(
                query,
                &[
                    &session.session_id,
                    &session.user_id,
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

    /// Loads a persisted session by identifier.
    pub async fn load_session(&self, session_id: &str) -> Result<SessionRecord, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT opaque_id, user_id, device_id, tls_fingerprint, created_at, ttl_seconds FROM session WHERE opaque_id = $1",
                &[&session_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let row = row.ok_or(StorageError::Missing)?;
        Ok(SessionRecord {
            session_id: row.get(0),
            user_id: row.get(1),
            device_id: row.get(2),
            tls_fingerprint: row.get(3),
            created_at: row.get(4),
            ttl_seconds: row.get(5),
        })
    }

    /// Fetches device metadata by identifier.
    pub async fn load_device(&self, device_id: &str) -> Result<DeviceRecord, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT opaque_id, user_id, pubkey, status, created_at FROM user_device WHERE opaque_id = $1",
                &[&device_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let row = row.ok_or(StorageError::Missing)?;
        Ok(DeviceRecord {
            device_id: row.get(0),
            user_id: row.get(1),
            public_key: row.get(2),
            status: row.get(3),
            created_at: row.get(4),
        })
    }

    /// Counts active devices registered for a user.
    pub async fn count_active_devices(&self, user_id: &str) -> Result<i64, StorageError> {
        let row = self
            .client
            .query_one(
                "SELECT COUNT(*) FROM user_device WHERE user_id = $1 AND status = 'active'",
                &[&user_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(row.get(0))
    }

    /// Lists devices associated with a user ordered by creation time.
    pub async fn list_devices_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<DeviceRecord>, StorageError> {
        let rows = self
            .client
            .query(
                "SELECT opaque_id, user_id, pubkey, status, created_at FROM user_device WHERE user_id = $1 ORDER BY created_at ASC",
                &[&user_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| DeviceRecord {
                device_id: row.get(0),
                user_id: row.get(1),
                public_key: row.get(2),
                status: row.get(3),
                created_at: row.get(4),
            })
            .collect())
    }

    /// Marks a device as active.
    pub async fn activate_device(&self, device_id: &str) -> Result<(), StorageError> {
        self.update_device_status(device_id, "active").await
    }

    /// Marks a device as revoked.
    pub async fn deactivate_device(&self, device_id: &str) -> Result<(), StorageError> {
        self.update_device_status(device_id, "revoked").await
    }

    async fn update_device_status(
        &self,
        device_id: &str,
        status: &str,
    ) -> Result<(), StorageError> {
        let affected = self
            .client
            .execute(
                "UPDATE user_device SET status = $2 WHERE opaque_id = $1",
                &[&device_id, &status],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        if affected == 0 {
            return Err(StorageError::Missing);
        }
        Ok(())
    }

    /// Creates a new user profile entry.
    pub async fn create_user(&self, profile: &NewUserProfile) -> Result<UserProfile, StorageError> {
        let now = Utc::now();
        let row = self
            .client
            .query_one(
                "INSERT INTO app_user (user_id, handle, display_name, avatar_url, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $5)
                RETURNING user_id, handle, display_name, avatar_url, created_at, updated_at",
                &[
                    &profile.user_id,
                    &profile.handle,
                    &profile.display_name,
                    &profile.avatar_url,
                    &now,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(UserProfile {
            user_id: row.get(0),
            handle: row.get(1),
            display_name: row.get(2),
            avatar_url: row.get(3),
            created_at: row.get(4),
            updated_at: row.get(5),
        })
    }

    /// Loads a user profile by identifier.
    pub async fn load_user(&self, user_id: &str) -> Result<UserProfile, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT user_id, handle, display_name, avatar_url, created_at, updated_at FROM app_user WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let row = row.ok_or(StorageError::Missing)?;
        Ok(UserProfile {
            user_id: row.get(0),
            handle: row.get(1),
            display_name: row.get(2),
            avatar_url: row.get(3),
            created_at: row.get(4),
            updated_at: row.get(5),
        })
    }

    /// Loads a user profile by handle.
    pub async fn load_user_by_handle(&self, handle: &str) -> Result<UserProfile, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT user_id, handle, display_name, avatar_url, created_at, updated_at FROM app_user WHERE handle = $1",
                &[&handle],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let row = row.ok_or(StorageError::Missing)?;
        Ok(UserProfile {
            user_id: row.get(0),
            handle: row.get(1),
            display_name: row.get(2),
            avatar_url: row.get(3),
            created_at: row.get(4),
            updated_at: row.get(5),
        })
    }

    /// Applies partial updates to user profile metadata.
    pub async fn update_user_profile(
        &self,
        user_id: &str,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
    ) -> Result<(), StorageError> {
        let now = Utc::now();
        let affected = self
            .client
            .execute(
                "UPDATE app_user SET display_name = COALESCE($2, display_name), avatar_url = COALESCE($3, avatar_url), updated_at = $4 WHERE user_id = $1",
                &[&user_id, &display_name, &avatar_url, &now],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        if affected == 0 {
            return Err(StorageError::Missing);
        }
        Ok(())
    }

    /// Updates user avatar URL
    pub async fn update_user_avatar(
        &self,
        user_id: &str,
        avatar_url: &str,
    ) -> Result<(), StorageError> {
        let now = Utc::now();
        let affected = self
            .client
            .execute(
                "UPDATE app_user SET avatar_url = $2, updated_at = $3 WHERE user_id = $1",
                &[&user_id, &avatar_url, &now],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        if affected == 0 {
            return Err(StorageError::Missing);
        }
        Ok(())
    }

    /// Creates a chat group entry and enrolls the owner as a member.
    pub async fn create_group(&self, group: &ChatGroup) -> Result<(), StorageError> {
        self.client
            .execute(
                "INSERT INTO chat_group (group_id, owner_device, created_at) VALUES ($1, $2, $3)
                ON CONFLICT (group_id) DO NOTHING",
                &[&group.group_id, &group.owner_device, &group.created_at],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        self.client
            .execute(
                "INSERT INTO group_member (group_id, device_id, role, joined_at) VALUES ($1, $2, $3, $4)
                ON CONFLICT (group_id, device_id) DO UPDATE SET role = excluded.role",
                &[
                    &group.group_id,
                    &group.owner_device,
                    &GroupRole::Owner.as_str(),
                    &group.created_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Adds or updates group membership information.
    pub async fn add_group_member(&self, member: &GroupMember) -> Result<(), StorageError> {
        let query = "INSERT INTO group_member (group_id, device_id, role, joined_at) VALUES ($1, $2, $3, $4)
            ON CONFLICT (group_id, device_id) DO UPDATE SET role = excluded.role, joined_at = excluded.joined_at";
        self.client
            .execute(
                query,
                &[
                    &member.group_id,
                    &member.device_id,
                    &member.role.as_str(),
                    &member.joined_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Removes a member from the given group.
    pub async fn remove_group_member(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Result<(), StorageError> {
        let affected = self
            .client
            .execute(
                "DELETE FROM group_member WHERE group_id = $1 AND device_id = $2",
                &[&group_id, &device_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        if affected == 0 {
            return Err(StorageError::Missing);
        }
        Ok(())
    }

    /// Lists all members of a group ordered by join time.
    pub async fn list_group_members(
        &self,
        group_id: &str,
    ) -> Result<Vec<GroupMember>, StorageError> {
        let rows = self
            .client
            .query(
                "SELECT group_id, device_id, role, joined_at FROM group_member WHERE group_id = $1 ORDER BY joined_at ASC",
                &[&group_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let mut members = Vec::with_capacity(rows.len());
        for row in rows {
            let role: String = row.get(2);
            let parsed = GroupRole::from_str(role.as_str())?;
            members.push(GroupMember {
                group_id: row.get(0),
                device_id: row.get(1),
                role: parsed,
                joined_at: row.get(3),
            });
        }
        Ok(members)
    }

    /// Loads group metadata by identifier.
    pub async fn load_group(&self, group_id: &str) -> Result<ChatGroup, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT group_id, owner_device, created_at FROM chat_group WHERE group_id = $1",
                &[&group_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let row = row.ok_or(StorageError::Missing)?;
        Ok(ChatGroup {
            group_id: row.get(0),
            owner_device: row.get(1),
            created_at: row.get(2),
        })
    }

    /// Lists groups that include the target device.
    pub async fn list_groups_for_device(
        &self,
        device_id: &str,
    ) -> Result<Vec<ChatGroup>, StorageError> {
        let rows = self
            .client
            .query(
                "SELECT g.group_id, g.owner_device, g.created_at FROM chat_group g
                INNER JOIN group_member m ON g.group_id = m.group_id
                WHERE m.device_id = $1 ORDER BY g.created_at ASC",
                &[&device_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(rows
            .into_iter()
            .map(|row| ChatGroup {
                group_id: row.get(0),
                owner_device: row.get(1),
                created_at: row.get(2),
            })
            .collect())
    }

    /// Upserts federation peer descriptors for S2S routing.
    pub async fn upsert_federation_peer(
        &self,
        peer: &FederationPeerRecord,
    ) -> Result<(), StorageError> {
        let query = "INSERT INTO federation_peer (domain, endpoint, public_key, status, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (domain) DO UPDATE SET endpoint = excluded.endpoint, public_key = excluded.public_key, status = excluded.status, updated_at = excluded.updated_at";
        self.client
            .execute(
                query,
                &[
                    &peer.domain,
                    &peer.endpoint,
                    &peer.public_key.as_slice(),
                    &peer.status.as_str(),
                    &peer.updated_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Loads a federation peer by domain.
    pub async fn load_federation_peer(
        &self,
        domain: &str,
    ) -> Result<FederationPeerRecord, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT domain, endpoint, public_key, status, updated_at FROM federation_peer WHERE domain = $1",
                &[&domain],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let row = row.ok_or(StorageError::Missing)?;
        let key: Vec<u8> = row.get(2);
        let status: String = row.get(3);
        let status = FederationPeerStatus::from_str(status.as_str())?;
        let public_key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::Serialization)?;
        Ok(FederationPeerRecord {
            domain: row.get(0),
            endpoint: row.get(1),
            public_key,
            status,
            updated_at: row.get(4),
        })
    }

    /// Enumerates all known federation peers.
    pub async fn list_federation_peers(&self) -> Result<Vec<FederationPeerRecord>, StorageError> {
        let rows = self
            .client
            .query(
                "SELECT domain, endpoint, public_key, status, updated_at FROM federation_peer",
                &[],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let mut peers = Vec::with_capacity(rows.len());
        for row in rows {
            let key: Vec<u8> = row.get(2);
            let status: String = row.get(3);
            let status = FederationPeerStatus::from_str(status.as_str())?;
            let public_key: [u8; 32] = key
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::Serialization)?;
            peers.push(FederationPeerRecord {
                domain: row.get(0),
                endpoint: row.get(1),
                public_key,
                status,
                updated_at: row.get(4),
            });
        }
        Ok(peers)
    }

    /// Sets the peer status and refresh timestamp.
    pub async fn set_federation_peer_status(
        &self,
        domain: &str,
        status: FederationPeerStatus,
    ) -> Result<(), StorageError> {
        let now = Utc::now();
        let affected = self
            .client
            .execute(
                "UPDATE federation_peer SET status = $2, updated_at = $3 WHERE domain = $1",
                &[&domain, &status.as_str(), &now],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        if affected == 0 {
            return Err(StorageError::Missing);
        }
        Ok(())
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

    /// Registers a federation event for outbound delivery.
    pub async fn enqueue_federation_outbox(
        &self,
        record: &FederationOutboxInsert<'_>,
    ) -> Result<(), StorageError> {
        self.client
            .execute(
                "INSERT INTO federation_outbox (outbox_id, destination_domain, endpoint, payload, public_key, next_attempt_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (outbox_id) DO NOTHING",
                &[
                    &record.outbox_id,
                    &record.destination,
                    &record.endpoint,
                    &record.payload,
                    &&record.public_key[..],
                    &record.next_attempt_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Claims due federation events and leases them for processing.
    pub async fn claim_federation_outbox(
        &self,
        limit: i64,
        lease: Duration,
        now: DateTime<Utc>,
    ) -> Result<Vec<FederationOutboxMessage>, StorageError> {
        let lease_deadline = now + lease;
        let query = "WITH due AS (
                SELECT outbox_id
                FROM federation_outbox
                WHERE next_attempt_at <= $1
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            ),
            updated AS (
                UPDATE federation_outbox f
                SET next_attempt_at = $3,
                    attempts = f.attempts + 1,
                    last_error = NULL
                FROM due
                WHERE f.outbox_id = due.outbox_id
                RETURNING f.outbox_id, f.destination_domain, f.endpoint, f.payload, f.public_key, f.attempts, f.next_attempt_at, f.last_error
            )
            SELECT * FROM updated";
        let rows = self
            .client
            .query(query, &[&now, &limit, &lease_deadline])
            .await
            .map_err(|_| StorageError::Postgres)?;
        rows.into_iter()
            .map(|row| {
                let key: Vec<u8> = row.get(4);
                let public_key: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::Serialization)?;
                Ok(FederationOutboxMessage {
                    outbox_id: row.get(0),
                    destination: row.get(1),
                    endpoint: row.get(2),
                    payload: row.get(3),
                    public_key,
                    attempts: row.get(5),
                    next_attempt_at: row.get(6),
                    last_error: row.get(7),
                })
            })
            .collect()
    }

    /// Removes a federation outbox entry once delivery succeeds.
    pub async fn delete_federation_outbox(&self, outbox_id: &str) -> Result<(), StorageError> {
        let affected = self
            .client
            .execute(
                "DELETE FROM federation_outbox WHERE outbox_id = $1",
                &[&outbox_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        if affected == 0 {
            return Err(StorageError::Missing);
        }
        Ok(())
    }

    /// Reschedules a federation outbox entry after a failed attempt.
    pub async fn reschedule_federation_outbox(
        &self,
        outbox_id: &str,
        delay: Duration,
        now: DateTime<Utc>,
        error: Option<&str>,
    ) -> Result<(), StorageError> {
        let next_attempt = now + delay;
        let affected = self
            .client
            .execute(
                "UPDATE federation_outbox SET next_attempt_at = $2, last_error = $3 WHERE outbox_id = $1",
                &[&outbox_id, &next_attempt, &error],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        if affected == 0 {
            return Err(StorageError::Missing);
        }
        Ok(())
    }

    /// Stores the last delivered envelope reference for an entity/channel pair.
    pub async fn store_inbox_offset(&self, offset: &InboxOffset) -> Result<(), StorageError> {
        let query = "INSERT INTO inbox_offset (entity_id, channel_id, last_envelope_id, updated_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (entity_id, channel_id) DO UPDATE SET last_envelope_id = excluded.last_envelope_id, updated_at = excluded.updated_at";
        self.client
            .execute(
                query,
                &[
                    &offset.entity_id,
                    &offset.channel_id,
                    &offset.last_envelope_id,
                    &offset.updated_at,
                ],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Reads the stored inbox offset if present.
    pub async fn read_inbox_offset(
        &self,
        entity_id: &str,
        channel_id: &str,
    ) -> Result<Option<InboxOffset>, StorageError> {
        let row = self
            .client
            .query_opt(
                "SELECT entity_id, channel_id, last_envelope_id, updated_at FROM inbox_offset WHERE entity_id = $1 AND channel_id = $2",
                &[&entity_id, &channel_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(row.map(|row| InboxOffset {
            entity_id: row.get(0),
            channel_id: row.get(1),
            last_envelope_id: row.get(2),
            updated_at: row.get(3),
        }))
    }

    /// Records an idempotency key for deduplication.
    pub async fn store_idempotency(&self, key: &IdempotencyKey) -> Result<bool, StorageError> {
        let query = "INSERT INTO idempotency (key, scope, created_at) VALUES ($1, $2, $3)
            ON CONFLICT (key, scope) DO NOTHING RETURNING 1";
        let row = self
            .client
            .query_opt(query, &[&key.key, &key.scope, &key.created_at])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(row.is_some())
    }

    /// Creates a friend request
    pub async fn create_friend_request(
        &self,
        id: &str,
        from_user_id: &str,
        to_user_id: &str,
        message: Option<&str>,
    ) -> Result<FriendRequest, StorageError> {
        let query = "INSERT INTO friend_requests (id, from_user_id, to_user_id, message, created_at, updated_at)
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            ON CONFLICT (from_user_id, to_user_id) DO UPDATE
            SET status = 'pending', message = EXCLUDED.message, updated_at = NOW()
            RETURNING id, from_user_id, to_user_id, status, message, created_at, updated_at";
        let row = self
            .client
            .query_one(query, &[&id, &from_user_id, &to_user_id, &message])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(FriendRequest {
            id: row.get(0),
            from_user_id: row.get(1),
            to_user_id: row.get(2),
            status: row.get(3),
            message: row.get(4),
            created_at: row.get(5),
            updated_at: row.get(6),
        })
    }

    /// Gets a friend request by ID
    pub async fn get_friend_request(&self, id: &str) -> Result<FriendRequest, StorageError> {
        let query = "SELECT id, from_user_id, to_user_id, status, message, created_at, updated_at
            FROM friend_requests WHERE id = $1";
        let row = self
            .client
            .query_opt(query, &[&id])
            .await
            .map_err(|_| StorageError::Postgres)?
            .ok_or(StorageError::Missing)?;
        Ok(FriendRequest {
            id: row.get(0),
            from_user_id: row.get(1),
            to_user_id: row.get(2),
            status: row.get(3),
            message: row.get(4),
            created_at: row.get(5),
            updated_at: row.get(6),
        })
    }

    /// Lists incoming friend requests for a user
    pub async fn list_incoming_friend_requests(
        &self,
        user_id: &str,
    ) -> Result<Vec<FriendRequest>, StorageError> {
        let query = "SELECT id, from_user_id, to_user_id, status, message, created_at, updated_at
            FROM friend_requests
            WHERE to_user_id = $1 AND status = 'pending'
            ORDER BY created_at DESC";
        let rows = self
            .client
            .query(query, &[&user_id])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(rows
            .iter()
            .map(|row| FriendRequest {
                id: row.get(0),
                from_user_id: row.get(1),
                to_user_id: row.get(2),
                status: row.get(3),
                message: row.get(4),
                created_at: row.get(5),
                updated_at: row.get(6),
            })
            .collect())
    }

    /// Lists outgoing friend requests from a user
    pub async fn list_outgoing_friend_requests(
        &self,
        user_id: &str,
    ) -> Result<Vec<FriendRequest>, StorageError> {
        let query = "SELECT id, from_user_id, to_user_id, status, message, created_at, updated_at
            FROM friend_requests
            WHERE from_user_id = $1
            ORDER BY created_at DESC";
        let rows = self
            .client
            .query(query, &[&user_id])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(rows
            .iter()
            .map(|row| FriendRequest {
                id: row.get(0),
                from_user_id: row.get(1),
                to_user_id: row.get(2),
                status: row.get(3),
                message: row.get(4),
                created_at: row.get(5),
                updated_at: row.get(6),
            })
            .collect())
    }

    /// Accepts a friend request
    pub async fn accept_friend_request(&self, id: &str) -> Result<FriendRequest, StorageError> {
        let query = "UPDATE friend_requests
            SET status = 'accepted', updated_at = NOW()
            WHERE id = $1 AND status = 'pending'
            RETURNING id, from_user_id, to_user_id, status, message, created_at, updated_at";
        let row = self
            .client
            .query_opt(query, &[&id])
            .await
            .map_err(|_| StorageError::Postgres)?
            .ok_or(StorageError::Missing)?;
        Ok(FriendRequest {
            id: row.get(0),
            from_user_id: row.get(1),
            to_user_id: row.get(2),
            status: row.get(3),
            message: row.get(4),
            created_at: row.get(5),
            updated_at: row.get(6),
        })
    }

    /// Rejects a friend request
    pub async fn reject_friend_request(&self, id: &str) -> Result<FriendRequest, StorageError> {
        let query = "UPDATE friend_requests
            SET status = 'rejected', updated_at = NOW()
            WHERE id = $1 AND status = 'pending'
            RETURNING id, from_user_id, to_user_id, status, message, created_at, updated_at";
        let row = self
            .client
            .query_opt(query, &[&id])
            .await
            .map_err(|_| StorageError::Postgres)?
            .ok_or(StorageError::Missing)?;
        Ok(FriendRequest {
            id: row.get(0),
            from_user_id: row.get(1),
            to_user_id: row.get(2),
            status: row.get(3),
            message: row.get(4),
            created_at: row.get(5),
            updated_at: row.get(6),
        })
    }

    /// Deletes a friend request
    pub async fn delete_friend_request(&self, id: &str) -> Result<(), StorageError> {
        let query = "DELETE FROM friend_requests WHERE id = $1";
        self.client
            .execute(query, &[&id])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(())
    }

    /// Checks if a friend request exists between two users
    pub async fn friend_request_exists(
        &self,
        from_user_id: &str,
        to_user_id: &str,
    ) -> Result<Option<FriendRequest>, StorageError> {
        let query = "SELECT id, from_user_id, to_user_id, status, message, created_at, updated_at
            FROM friend_requests
            WHERE from_user_id = $1 AND to_user_id = $2";
        let row = self
            .client
            .query_opt(query, &[&from_user_id, &to_user_id])
            .await
            .map_err(|_| StorageError::Postgres)?;
        Ok(row.map(|row| FriendRequest {
            id: row.get(0),
            from_user_id: row.get(1),
            to_user_id: row.get(2),
            status: row.get(3),
            message: row.get(4),
            created_at: row.get(5),
            updated_at: row.get(6),
        }))
    }

    /// Publishes local presence information into Redis.
    pub async fn publish_presence(&self, snapshot: &PresenceSnapshot) -> Result<(), StorageError> {
        let mut conn = self.redis.lock().await;
        let ttl = (snapshot.expires_at.timestamp() - Utc::now().timestamp()).max(1) as usize;
        let payload = serde_json::json!({
            "entity": snapshot.entity.clone(),
            "state": snapshot.state.clone(),
            "expires_at": snapshot.expires_at.to_rfc3339(),
            "user": presence_user_payload(snapshot),
        })
        .to_string();
        redis::cmd("SETEX")
            .arg(format!("presence:{}", snapshot.entity))
            .arg(ttl)
            .arg(payload)
            .query_async::<()>(&mut *conn)
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
            .query_async::<Option<String>>(&mut *conn)
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
            let user_obj = parsed.get("user").and_then(|v| v.as_object());
            let (user_id, handle, display_name, avatar_url) = if let Some(map) = user_obj {
                presence_user_fields(map)
            } else {
                (None, None, None, None)
            };
            Ok(Some(PresenceSnapshot {
                entity: entity.to_string(),
                state,
                expires_at: expires,
                user_id,
                handle,
                display_name,
                avatar_url,
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
            .query_async::<()>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        Ok(())
    }

    /// Removes a routing entry from Redis.
    pub async fn clear_route(&self, entity: &str) -> Result<(), StorageError> {
        let mut conn = self.redis.lock().await;
        let _: () = redis::cmd("DEL")
            .arg(format!("route:{}", entity))
            .query_async::<()>(&mut *conn)
            .await
            .map_err(|_| StorageError::Redis)?;
        Ok(())
    }
}

fn generate_pair_code() -> String {
    let mut seed = [0u8; PAIRING_CODE_LENGTH];
    OsRng.fill_bytes(&mut seed);
    let mut output = String::with_capacity(PAIRING_CODE_LENGTH + 1);
    for (index, byte) in seed.iter().enumerate() {
        let symbol = PAIRING_ALPHABET[(*byte as usize) % PAIRING_ALPHABET.len()] as char;
        output.push(symbol);
        if index == (PAIRING_CODE_LENGTH / 2) - 1 {
            output.push('-');
        }
    }
    if output.ends_with('-') {
        output.pop();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn init_sql_exists() {
        assert!(INIT_SQL.contains("CREATE TABLE"));
    }

    #[test]
    fn pairing_code_format() {
        let code = generate_pair_code();
        assert_eq!(code.len(), PAIRING_CODE_LENGTH + 1);
        assert!(code.contains('-'));
    }

    #[test]
    fn init_sql_declares_new_relations() {
        assert!(INIT_SQL.contains("device_key_event"));
        assert!(INIT_SQL.contains("chat_group"));
        assert!(INIT_SQL.contains("group_member"));
        assert!(INIT_SQL.contains("federation_peer"));
        assert!(INIT_SQL.contains("inbox_offset"));
    }

    #[test]
    fn pairing_sql_declares_pairing_table() {
        assert!(PAIRING_SQL.contains("device_pairing"));
    }

    #[test]
    fn group_role_roundtrip() {
        assert_eq!(GroupRole::Owner.as_str(), "owner");
        assert_eq!(GroupRole::from_str("admin").unwrap(), GroupRole::Admin);
        assert!(GroupRole::from_str("unknown").is_err());
    }

    #[test]
    fn federation_status_roundtrip() {
        assert_eq!(FederationPeerStatus::Active.as_str(), "active");
        assert_eq!(
            FederationPeerStatus::from_str("pending").unwrap(),
            FederationPeerStatus::Pending
        );
        assert!(FederationPeerStatus::from_str("offline").is_err());
    }

    #[test]
    fn presence_user_payload_emits_aliases() {
        let now = Utc::now();
        let snapshot = PresenceSnapshot {
            entity: "dev-1".to_string(),
            state: "online".to_string(),
            expires_at: now + Duration::seconds(30),
            user_id: Some("user-1".to_string()),
            handle: Some("alice".to_string()),
            display_name: Some("Alice".to_string()),
            avatar_url: None,
        };
        let payload = presence_user_payload(&snapshot).expect("payload");
        assert_eq!(payload["id"], serde_json::json!("user-1"));
        assert_eq!(payload["user_id"], serde_json::json!("user-1"));
        assert_eq!(payload["handle"], serde_json::json!("alice"));
    }

    #[test]
    fn presence_user_fields_accepts_user_id_alias() {
        let mut map = serde_json::Map::new();
        map.insert("user_id".to_string(), serde_json::json!("user-99"));
        map.insert("handle".to_string(), serde_json::json!("eve"));
        let (user_id, handle, display_name, avatar_url) = presence_user_fields(&map);
        assert_eq!(user_id.as_deref(), Some("user-99"));
        assert_eq!(handle.as_deref(), Some("eve"));
        assert!(display_name.is_none());
        assert!(avatar_url.is_none());
    }

    #[tokio::test]
    async fn storage_integration_flow() -> Result<(), Box<dyn std::error::Error>> {
        let pg = match std::env::var("COMMUCAT_TEST_PG_DSN") {
            Ok(value) => value,
            Err(_) => {
                eprintln!("skipping storage_integration_flow: COMMUCAT_TEST_PG_DSN not set");
                return Ok(());
            }
        };
        let redis = match std::env::var("COMMUCAT_TEST_REDIS_URL") {
            Ok(value) => value,
            Err(_) => {
                eprintln!("skipping storage_integration_flow: COMMUCAT_TEST_REDIS_URL not set");
                return Ok(());
            }
        };
        let storage = connect(&pg, &redis).await?;
        storage.migrate().await?;
        let suffix = Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let user_profile = NewUserProfile {
            user_id: format!("test-user-{}", suffix),
            handle: format!("tester{}", suffix),
            display_name: Some("Tester".to_string()),
            avatar_url: None,
        };
        let created = storage.create_user(&user_profile).await?;
        let device_id = format!("test-device-{}", suffix);
        let device_record = DeviceRecord {
            device_id: device_id.clone(),
            user_id: created.user_id.clone(),
            public_key: vec![1; 32],
            status: "active".to_string(),
            created_at: Utc::now(),
        };
        storage.upsert_device(&device_record).await?;
        let key_event = DeviceKeyEvent {
            event_id: format!("evt-{}", suffix),
            device_id: device_id.clone(),
            public_key: device_record.public_key.clone(),
            recorded_at: Utc::now(),
        };
        storage.record_device_key_event(&key_event).await?;
        let latest = storage
            .latest_device_key_event(&device_id)
            .await?
            .expect("expected key event");
        assert_eq!(latest.public_key.len(), 32);

        let new_key = vec![2u8; 32];
        let rotation_id = format!("rot-{}", suffix);
        let rotation_event_id = format!("evt-rot-{}", suffix);
        let signature = vec![3u8; 64];
        let nonce = vec![4u8; 16];
        let applied_at = Utc::now();
        let proof_expires_at = applied_at + Duration::seconds(120);
        let rotation_record = DeviceRotationRecord {
            rotation_id: &rotation_id,
            device_id: &device_id,
            user_id: &created.user_id,
            old_public_key: device_record.public_key.as_slice(),
            new_public_key: new_key.as_slice(),
            signature: signature.as_slice(),
            nonce: Some(nonce.as_slice()),
            proof_expires_at,
            applied_at,
            event_id: &rotation_event_id,
        };
        storage.apply_device_key_rotation(&rotation_record).await?;
        let rotated = storage
            .latest_device_key_event(&device_id)
            .await?
            .expect("expected rotation event");
        assert_eq!(rotated.event_id, rotation_event_id);
        assert_eq!(rotated.public_key, new_key);
        let audit_row = storage
            .client
            .query_one(
                "SELECT old_public_key, new_public_key, proof_expires_at FROM device_rotation_audit WHERE rotation_id = $1",
                &[&rotation_id],
            )
            .await?;
        let stored_old: Vec<u8> = audit_row.get(0);
        let stored_new: Vec<u8> = audit_row.get(1);
        let stored_expiry: DateTime<Utc> = audit_row.get(2);
        assert_eq!(stored_old, device_record.public_key);
        assert_eq!(stored_new, new_key);
        assert_eq!(stored_expiry, proof_expires_at);

        let group = ChatGroup {
            group_id: format!("group-{}", suffix),
            owner_device: device_id.clone(),
            created_at: Utc::now(),
        };
        storage.create_group(&group).await?;
        let member = GroupMember {
            group_id: group.group_id.clone(),
            device_id: format!("peer-device-{}", suffix),
            role: GroupRole::Member,
            joined_at: Utc::now(),
        };
        storage.add_group_member(&member).await?;
        let members = storage.list_group_members(&group.group_id).await?;
        assert!(members.iter().any(|m| m.device_id == device_id));
        assert!(members.iter().any(|m| m.device_id == member.device_id));
        let memberships = storage.list_groups_for_device(&member.device_id).await?;
        assert_eq!(memberships.len(), 1);
        storage
            .remove_group_member(&group.group_id, &member.device_id)
            .await?;

        let peer = FederationPeerRecord {
            domain: format!("peer{}.example", suffix),
            endpoint: "https://peer.example/federation".to_string(),
            public_key: [5u8; 32],
            status: FederationPeerStatus::Active,
            updated_at: Utc::now(),
        };
        storage.upsert_federation_peer(&peer).await?;
        let fetched = storage.load_federation_peer(&peer.domain).await?;
        assert_eq!(fetched.endpoint, peer.endpoint);

        let event_json = serde_json::json!({
            "event": {
                "event_id": format!("fed-{}", suffix),
                "origin": "remote.example",
                "created_at": Utc::now().to_rfc3339(),
                "payload": serde_json::json!({"channel": 1, "payload": "00"}),
                "scope": "relay",
            },
            "signature": vec![0u8; 64],
            "digest": vec![0u8; 32],
        });
        let outbox_id = format!("outbox-{}", suffix);
        let outbox_insert = FederationOutboxInsert {
            outbox_id: &outbox_id,
            destination: &peer.domain,
            endpoint: &peer.endpoint,
            payload: &event_json,
            public_key: &peer.public_key,
            next_attempt_at: Utc::now(),
        };
        storage.enqueue_federation_outbox(&outbox_insert).await?;
        let claimed = storage
            .claim_federation_outbox(8, Duration::seconds(30), Utc::now())
            .await?;
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].outbox_id, outbox_id);
        storage
            .reschedule_federation_outbox(
                &outbox_id,
                Duration::seconds(5),
                Utc::now(),
                Some("boom"),
            )
            .await?;
        let after_delay = storage
            .claim_federation_outbox(8, Duration::seconds(30), Utc::now() + Duration::seconds(6))
            .await?;
        assert_eq!(after_delay.len(), 1);
        assert_eq!(after_delay[0].outbox_id, outbox_id);
        storage.delete_federation_outbox(&outbox_id).await?;

        let offset = InboxOffset {
            entity_id: device_id.clone(),
            channel_id: format!("inbox:{}", device_id),
            last_envelope_id: Some(format!("env-{}", suffix)),
            updated_at: Utc::now(),
        };
        storage.store_inbox_offset(&offset).await?;
        let loaded = storage
            .read_inbox_offset(&offset.entity_id, &offset.channel_id)
            .await?
            .expect("offset present");
        assert_eq!(loaded.last_envelope_id, offset.last_envelope_id);

        let ticket = storage
            .create_pairing_token(&created.user_id, &device_id, 300)
            .await?;
        assert_eq!(ticket.pair_code.len(), 9);
        let paired_device = format!("paired-device-{}", suffix);
        let claim = storage
            .claim_pairing_token(&ticket.pair_code, &paired_device, &[7u8; 32])
            .await?;
        assert_eq!(claim.user.user_id, created.user_id);
        assert_eq!(claim.issuer_device_id, device_id);
        storage
            .client
            .execute(
                "INSERT INTO device_pairing (pair_code, user_id, issuer_device_id, issued_at, expires_at, attempts) VALUES ($1, $2, $3, now(), now() - interval '10 minutes', 0)",
                &[&format!("expired-{}", suffix), &created.user_id, &device_id],
            )
            .await
            .map_err(|_| StorageError::Postgres)?;
        let purged = storage.invalidate_expired_pairings().await?;
        assert!(purged >= 1);
        storage
            .write_user_blob(&created.user_id, "friends", "[]")
            .await?;
        let blob = storage.read_user_blob(&created.user_id, "friends").await?;
        assert_eq!(blob.as_deref(), Some("[]"));

        let secret_name = format!("noise-static-{}", suffix);
        let now = Utc::now();
        let secret_record = ServerSecretRecord {
            name: secret_name.clone(),
            version: 1,
            secret: vec![9u8; 32],
            public: Some(vec![8u8; 32]),
            metadata: json!({"purpose": "test"}),
            created_at: now,
            valid_after: now,
            rotates_at: now + Duration::hours(1),
            expires_at: now + Duration::hours(2),
        };
        storage.insert_server_secret(&secret_record).await?;
        let latest = storage.latest_server_secret_version(&secret_name).await?;
        assert_eq!(latest, 1);
        let active = storage
            .active_server_secrets(&secret_name, now + Duration::minutes(30))
            .await?;
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].public.as_ref().map(|v| v.len()), Some(32));
        assert_eq!(active[0].metadata["purpose"], json!("test"));
        let removed = storage
            .delete_expired_server_secrets(&secret_name, now + Duration::hours(3))
            .await?;
        assert_eq!(removed, 1);

        let idempotency_key = IdempotencyKey {
            key: format!("key-{}", suffix),
            scope: "federation-test".to_string(),
            created_at: Utc::now(),
        };
        assert!(storage.store_idempotency(&idempotency_key).await?);
        assert!(!storage.store_idempotency(&idempotency_key).await?);

        Ok(())
    }
}
