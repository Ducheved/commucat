use crate::config::SecretRotationConfig;
use crate::metrics::Metrics;
use crate::util::encode_hex;
use blake3::Hasher;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use commucat_crypto::{derive_noise_public_key, generate_noise_static_keypair};
use commucat_storage::{ServerSecretRecord, Storage, StorageError};
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tokio::time::{self, Duration as TokioDuration, MissedTickBehavior};
use tracing::{info, warn};

const SECRET_NOISE_STATIC: &str = "noise-static";
const SECRET_ADMIN_TOKEN: &str = "admin-token";
const ADMIN_SALT_LENGTH: usize = 16;
const ROTATION_TICK_SECONDS: u64 = 60;

#[derive(Clone)]
pub struct NoiseKey {
    pub version: i64,
    pub private: [u8; 32],
    pub public: [u8; 32],
    pub valid_after: DateTime<Utc>,
    pub rotates_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct AdminToken {
    version: i64,
    hash: [u8; 32],
    salt: [u8; ADMIN_SALT_LENGTH],
    valid_after: DateTime<Utc>,
    rotates_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    source: AdminTokenSource,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdminTokenSource {
    Static,
    Rotated,
}

pub struct SecretManager {
    storage: Arc<Storage>,
    metrics: Arc<Metrics>,
    rotation: SecretRotationConfig,
    noise_keys: RwLock<Vec<NoiseKey>>,
    admin_tokens: RwLock<Vec<AdminToken>>,
    admin_rotation_enabled: bool,
}

impl SecretManager {
    pub async fn bootstrap(
        storage: Arc<Storage>,
        metrics: Arc<Metrics>,
        rotation: SecretRotationConfig,
        initial_noise_private: [u8; 32],
        initial_noise_public: [u8; 32],
        initial_admin_token: Option<String>,
    ) -> Result<Arc<Self>, StorageError> {
        let manager = Arc::new(SecretManager {
            storage,
            metrics,
            rotation,
            noise_keys: RwLock::new(Vec::new()),
            admin_tokens: RwLock::new(Vec::new()),
            admin_rotation_enabled: rotation.admin.enabled,
        });
        manager
            .initialize_noise(initial_noise_private, initial_noise_public)
            .await?;
        manager
            .initialize_admin(initial_admin_token)
            .await?;
        Ok(manager)
    }

    pub fn spawn(self: &Arc<Self>) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            manager.rotation_loop().await;
        });
    }

    pub async fn active_noise_keys(&self) -> Vec<NoiseKey> {
        let guard = self.noise_keys.read().await;
        guard.clone()
    }

    pub async fn noise_catalog(&self) -> Vec<NoiseKey> {
        self.active_noise_keys().await
    }

    pub async fn verify_admin_token(&self, token: &str) -> bool {
        let tokens = self.admin_tokens.read().await;
        if tokens.is_empty() && !self.admin_rotation_enabled {
            return true;
        }
        if tokens.is_empty() {
            return false;
        }
        let now = Utc::now();
        let candidate = token.as_bytes();
        for record in tokens.iter() {
            if now < record.valid_after || now >= record.expires_at {
                continue;
            }
            let digest = hash_admin_token(candidate, &record.salt);
            if digest.ct_eq(&record.hash).into() {
                return true;
            }
        }
        false
    }

    pub async fn admin_token_required(&self) -> bool {
        if self.admin_rotation_enabled {
            return true;
        }
        let tokens = self.admin_tokens.read().await;
        !tokens.is_empty()
    }

    pub async fn current_noise_key(&self) -> Option<NoiseKey> {
        let guard = self.noise_keys.read().await;
        guard.first().cloned()
    }

    async fn rotation_loop(self: Arc<Self>) {
        let mut ticker = time::interval(TokioDuration::from_secs(ROTATION_TICK_SECONDS));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(err) = self.tick_once().await {
                warn!("secret rotation tick failed: {}", err);
            }
        }
    }

    async fn tick_once(&self) -> Result<(), StorageError> {
        let now = Utc::now();
        self.rotate_noise_if_needed(now).await?;
        if self.admin_rotation_enabled {
            self.rotate_admin_if_needed(now).await?;
        }
        self.prune_noise(now).await?;
        if self.admin_rotation_enabled {
            self.prune_admin(now).await?;
        }
        Ok(())
    }

    async fn initialize_noise(
        self: &Arc<Self>,
        private_key: [u8; 32],
        public_key: [u8; 32],
    ) -> Result<(), StorageError> {
        let now = Utc::now();
        let mut records = self
            .storage
            .active_server_secrets(SECRET_NOISE_STATIC, now)
            .await?;
        if records.is_empty() {
            self.ensure_consistent_public(&private_key, &public_key)?;
            let version = self
                .storage
                .latest_server_secret_version(SECRET_NOISE_STATIC)
                .await?
                + 1;
            let record = self.make_noise_record(version, private_key, public_key, now)?;
            self.storage.insert_server_secret(&record).await?;
            records.push(record);
            info!(version, "initialized noise static key material");
        }
        let keys = records
            .iter()
            .filter_map(|record| match noise_from_record(record) {
                Ok(key) => Some(key),
                Err(_) => None,
            })
            .collect::<Vec<_>>();
        let mut guard = self.noise_keys.write().await;
        *guard = keys;
        guard.sort_by(|a, b| b.version.cmp(&a.version));
        guard.truncate(self.rotation.noise.max_versions);
        Ok(())
    }

    async fn initialize_admin(
        self: &Arc<Self>,
        initial_token: Option<String>,
    ) -> Result<(), StorageError> {
        let now = Utc::now();
        let mut records = self
            .storage
            .active_server_secrets(SECRET_ADMIN_TOKEN, now)
            .await?;
        if records.is_empty() {
            if let Some(token) = initial_token.clone() {
                let version = self
                    .storage
                    .latest_server_secret_version(SECRET_ADMIN_TOKEN)
                    .await?
                    + 1;
                let record = self.make_admin_record(version, &token, now)?;
                self.storage.insert_server_secret(&record).await?;
                records.push(record);
            } else if self.rotation.admin.enabled {
                let (token, record) = self.generate_fresh_admin_record(now).await?;
                let version = record.version;
                self.storage.insert_server_secret(&record).await?;
                records.push(record);
                info!(version, token = %token, "issued new administrative token");
            }
        }
        let tokens = records
            .iter()
            .filter_map(|record| admin_from_record(record))
            .collect::<Vec<_>>();
        let mut guard = self.admin_tokens.write().await;
        *guard = tokens;
        guard.sort_by(|a, b| b.version.cmp(&a.version));
        if !self.rotation.admin.enabled {
            if let Some(token) = initial_token {
                if guard.is_empty() {
                    let salt = random_salt();
                    let hash = hash_admin_token(token.as_bytes(), &salt);
                    let sentinel = AdminToken {
                        version: 0,
                        hash,
                        salt,
                        valid_after: now,
                        rotates_at: now,
                        expires_at: far_future(now),
                        source: AdminTokenSource::Static,
                    };
                    guard.push(sentinel);
                }
            }
        } else if guard.is_empty() {
            let (token, record) = self.generate_fresh_admin_record(now).await?;
            let version = record.version;
            self.storage.insert_server_secret(&record).await?;
            guard.push(admin_from_record(&record).expect("admin record"));
            info!(version, token = %token, "issued new administrative token");
        }
        Ok(())
    }

    async fn rotate_noise_if_needed(&self, now: DateTime<Utc>) -> Result<(), StorageError> {
        let due = {
            let guard = self.noise_keys.read().await;
            match guard.first() {
                Some(current) => now >= current.rotates_at,
                None => true,
            }
        };
        if !due {
            return Ok(());
        }
        let version = self
            .storage
            .latest_server_secret_version(SECRET_NOISE_STATIC)
            .await?
            + 1;
        let (private, public) = generate_noise_static_keypair();
        let record = self.make_noise_record(version, private, public, now)?;
        self.storage.insert_server_secret(&record).await?;
        let mut guard = self.noise_keys.write().await;
        guard.insert(0, noise_from_record(&record)?);
        guard.sort_by(|a, b| b.version.cmp(&a.version));
        guard.truncate(self.rotation.noise.max_versions);
        self.metrics.mark_noise_rotation();
        info!(version, expires_at = %record.expires_at.to_rfc3339(), "rotated noise static key");
        Ok(())
    }

    async fn rotate_admin_if_needed(&self, now: DateTime<Utc>) -> Result<(), StorageError> {
        let due = {
            let guard = self.admin_tokens.read().await;
            match guard.first() {
                Some(current) => now >= current.rotates_at,
                None => true,
            }
        };
        if !due {
            return Ok(());
        }
        let (token, record) = self.generate_fresh_admin_record(now).await?;
        let version = record.version;
        self.storage.insert_server_secret(&record).await?;
        let mut guard = self.admin_tokens.write().await;
        guard.insert(0, admin_from_record(&record)?);
        guard.sort_by(|a, b| b.version.cmp(&a.version));
        guard.truncate(self.rotation.admin.max_versions);
        self.metrics.mark_admin_rotation();
        info!(version, token = %token, "rotated administrative token");
        Ok(())
    }

    async fn prune_noise(&self, now: DateTime<Utc>) -> Result<(), StorageError> {
        let removed = self
            .storage
            .delete_expired_server_secrets(SECRET_NOISE_STATIC, now)
            .await?;
        if removed > 0 {
            let mut guard = self.noise_keys.write().await;
            guard.retain(|key| key.expires_at > now);
        }
        Ok(())
    }

    async fn prune_admin(&self, now: DateTime<Utc>) -> Result<(), StorageError> {
        let removed = self
            .storage
            .delete_expired_server_secrets(SECRET_ADMIN_TOKEN, now)
            .await?;
        if removed > 0 {
            let mut guard = self.admin_tokens.write().await;
            guard.retain(|token| token.expires_at > now);
        }
        Ok(())
    }

    fn ensure_consistent_public(
        &self,
        private_key: &[u8; 32],
        public_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        let derived = derive_noise_public_key(private_key);
        if &derived != public_key {
            return Err(StorageError::Invalid);
        }
        Ok(())
    }

    fn make_noise_record(
        &self,
        version: i64,
        private: [u8; 32],
        public: [u8; 32],
        now: DateTime<Utc>,
    ) -> Result<ServerSecretRecord, StorageError> {
        let interval = chrono_from_std(self.rotation.noise.interval)?;
        let grace = chrono_from_std(self.rotation.noise.grace)?;
        let rotates_at = now + interval;
        let expires_at = rotates_at + grace;
        Ok(ServerSecretRecord {
            name: SECRET_NOISE_STATIC.to_string(),
            version,
            secret: private.to_vec(),
            public: Some(public.to_vec()),
            metadata: serde_json::Value::Null,
            created_at: now,
            valid_after: now,
            rotates_at,
            expires_at,
        })
    }

    fn make_admin_record(
        &self,
        version: i64,
        token: &str,
        now: DateTime<Utc>,
    ) -> Result<ServerSecretRecord, StorageError> {
        let interval = chrono_from_std(self.rotation.admin.interval)?;
        let grace = chrono_from_std(self.rotation.admin.grace)?;
        let rotates_at = if self.rotation.admin.enabled {
            now + interval
        } else {
            now + ChronoDuration::weeks(5200)
        };
        let expires_at = if self.rotation.admin.enabled {
            rotates_at + grace
        } else {
            far_future(now)
        };
        let salt = random_salt();
        let hash = hash_admin_token(token.as_bytes(), &salt);
        Ok(ServerSecretRecord {
            name: SECRET_ADMIN_TOKEN.to_string(),
            version,
            secret: hash.to_vec(),
            public: Some(salt.to_vec()),
            metadata: serde_json::Value::Null,
            created_at: now,
            valid_after: now,
            rotates_at,
            expires_at,
        })
    }

    async fn generate_fresh_admin_record(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(String, ServerSecretRecord), StorageError> {
        let version = self
            .storage
            .latest_server_secret_version(SECRET_ADMIN_TOKEN)
            .await?
            + 1;
        let token = generate_admin_token();
        let record = self.make_admin_record(version, &token, now)?;
        Ok((token, record))
    }
}

fn noise_from_record(record: &ServerSecretRecord) -> Result<NoiseKey, StorageError> {
    let private_vec = &record.secret;
    if private_vec.len() != 32 {
        return Err(StorageError::Invalid);
    }
    let mut private = [0u8; 32];
    private.copy_from_slice(private_vec);
    let public_vec = record
        .public
        .as_ref()
        .ok_or(StorageError::Invalid)?;
    if public_vec.len() != 32 {
        return Err(StorageError::Invalid);
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(public_vec);
    Ok(NoiseKey {
        version: record.version,
        private,
        public,
        valid_after: record.valid_after,
        rotates_at: record.rotates_at,
        expires_at: record.expires_at,
    })
}

fn admin_from_record(record: &ServerSecretRecord) -> Option<AdminToken> {
    let secret = &record.secret;
    if secret.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(secret);
    let salt_vec = record.public.as_ref()?;
    if salt_vec.len() != ADMIN_SALT_LENGTH {
        return None;
    }
    let mut salt = [0u8; ADMIN_SALT_LENGTH];
    salt.copy_from_slice(salt_vec);
    Some(AdminToken {
        version: record.version,
        hash,
        salt,
        valid_after: record.valid_after,
        rotates_at: record.rotates_at,
        expires_at: record.expires_at,
        source: AdminTokenSource::Rotated,
    })
}

fn hash_admin_token(token: &[u8], salt: &[u8; ADMIN_SALT_LENGTH]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(salt);
    hasher.update(token);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(digest.as_bytes());
    output
}

fn random_salt() -> [u8; ADMIN_SALT_LENGTH] {
    let mut rng = OsRng;
    let mut salt = [0u8; ADMIN_SALT_LENGTH];
    rng.fill_bytes(&mut salt);
    salt
}

fn generate_admin_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

fn chrono_from_std(value: StdDuration) -> Result<ChronoDuration, StorageError> {
    ChronoDuration::from_std(value).map_err(|_| StorageError::Invalid)
}

fn far_future(now: DateTime<Utc>) -> DateTime<Utc> {
    now + ChronoDuration::days(365 * 100)
}
