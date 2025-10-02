mod federation;
mod media;
mod p2p;
mod rotation;
mod uploads;

use self::federation::spawn_dispatcher;
use self::media::{CallMediaTranscoder, SharedCallMediaTranscoder};
use self::rotation::{
    DecodedRotationRequest, DeviceRotationRequest, RotationNotification, RotationRequestError,
    rotation_proof_message,
};
use self::uploads::{
    UploadError, generate_filename, mime_type_from_filename, read_file, save_file, validate_avatar,
};
use crate::config::{LedgerAdapter, PeerConfig, ServerConfig};
use crate::metrics::Metrics;
use crate::openapi;
use crate::security::limiter::{RateLimiter, RateScope};
use crate::security::secrets::{NoiseKey, SecretManager};
use crate::transport::{Endpoint, RealityConfig, TransportManager, default_manager};
use crate::util::{decode_hex, decode_hex32, encode_hex, generate_id};
use blake3::hash as blake3_hash;
use chrono::{Duration, Utc};
use commucat_crypto::zkp::{self, KnowledgeProof};
use commucat_crypto::{
    CryptoError, DeviceCertificate, DeviceCertificateData, DeviceKeyPair, EventSigner,
    EventVerifier, HandshakePattern, NoiseConfig, NoiseHandshake, NoiseTransport, build_handshake,
};
use commucat_federation::{
    FederationError, FederationEvent, SignedEvent, sign_event, verify_event,
};
use commucat_ledger::{
    DebugLedgerAdapter, FileLedgerAdapter, LedgerAdapter as LedgerAdapterTrait, LedgerError,
    LedgerRecord, NullLedger,
};
use commucat_proto::{
    ControlEnvelope, Frame, FramePayload, FrameType, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
    call::{
        CallAnswer as ProtoCallAnswer, CallEnd as ProtoCallEnd, CallEndReason, CallMediaDirection,
        CallMediaProfile, CallMode, CallOffer as ProtoCallOffer, CallRejectReason,
        CallStats as ProtoCallStats, CallTransport, CallTransportUpdate, TransportUpdatePayload,
    },
    is_supported_protocol_version, negotiate_protocol_version,
};
use commucat_storage::{
    ChatGroup, DeviceKeyEvent, DeviceRecord, DeviceRotationRecord, FederationOutboxInsert,
    FederationPeerStatus, GroupMember, GroupRole, IdempotencyKey, InboxOffset, NewUserProfile,
    PresenceSnapshot, RelayEnvelope, SessionRecord, Storage, StorageError, UserProfile, connect,
};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream};
use pingora::http::ResponseHeader;
use pingora::protocols::http::ServerSession;
use pingora::protocols::http::v2::server::H2Options;
use pingora::server::ShutdownWatch;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration as StdDuration;
use tokio::select;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

const LANDING_PAGE: &str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\" />\n<title>CommuCat</title>\n<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0b1120;color:#f9fafb;margin:0;display:flex;align-items:center;justify-content:center;height:100vh;}main{max-width:480px;text-align:center;padding:2rem;background:rgba(15,23,42,0.85);border-radius:20px;box-shadow:0 10px 30px rgba(15,23,42,0.4);}h1{font-size:2.25rem;margin-bottom:0.5rem;}p{margin:0.75rem 0;color:#cbd5f5;}a{color:#38bdf8;text-decoration:none;}a:hover{text-decoration:underline;}</style>\n</head>\n<body>\n<main>\n<h1>CommuCat Server</h1>\n<p>Secure Noise + TLS relay for CCP-1 chats.</p>\n<p><a href=\"https://github.com/ducheved/commucat\">Project documentation</a></p>\n<p><a href=\"/healthz\">Health</a> · <a href=\"/readyz\">Readiness</a></p>\n</main>\n</body>\n</html>\n";
const FRIENDS_BLOB_KEY: &str = "friends";
const DEVICE_CERT_MAX_SKEW: i64 = 300;
const DEVICE_CERT_VALIDITY_SECS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug)]
pub enum ServerError {
    Storage,
    Ledger,
    Crypto,
    Codec,
    Federation,
    Invalid,
    Io,
    PairingRequired,
    ProtocolNegotiation(String),
}

impl Display for ServerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage => write!(f, "storage failure"),
            Self::Ledger => write!(f, "ledger failure"),
            Self::Crypto => write!(f, "crypto failure"),
            Self::Codec => write!(f, "codec failure"),
            Self::Federation => write!(f, "federation failure"),
            Self::Invalid => write!(f, "invalid request"),
            Self::Io => write!(f, "io failure"),
            Self::PairingRequired => write!(f, "pairing required"),
            Self::ProtocolNegotiation(reason) => {
                write!(f, "protocol negotiation failed: {}", reason)
            }
        }
    }
}

fn encode_varint_usize(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 0x80 {
        bytes.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}

fn decode_varint_prefix(buffer: &[u8]) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0usize;
    for (index, byte) in buffer.iter().copied().enumerate() {
        let value = (byte & 0x7f) as usize;
        result |= value << shift;
        if byte & 0x80 == 0 {
            return Some((result, index + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_route_retains_group_metadata() {
        let mut members = HashSet::new();
        members.insert("dev-1".to_string());
        let route = ChannelRoute {
            members: members.clone(),
            relay: true,
            group_id: Some("grp-1".to_string()),
        };
        let cloned = route.clone();
        assert!(cloned.members.contains("dev-1"));
        assert_eq!(cloned.group_id.as_deref(), Some("grp-1"));
        assert!(route.relay);
    }

    #[test]
    fn cipher_varint_roundtrip() {
        let values = [0usize, 1, 127, 128, 16_384, (u32::MAX as usize)];
        for value in values {
            let encoded = encode_varint_usize(value);
            let (decoded, consumed) = decode_varint_prefix(&encoded).expect("decode varint");
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn user_snapshot_includes_alias() {
        let now = Utc::now();
        let profile = UserProfile {
            user_id: "user-123".to_string(),
            handle: "alice".to_string(),
            display_name: Some("Alice".to_string()),
            avatar_url: None,
            created_at: now,
            updated_at: now,
        };
        let payload = user_snapshot(&profile);
        assert_eq!(payload["id"], json!("user-123"));
        assert_eq!(payload["user_id"], json!("user-123"));
        assert_eq!(payload["handle"], json!("alice"));
    }

    #[test]
    fn friends_request_accepts_user_id_only() {
        let payload = json!({
            "friends": [
                {
                    "user_id": " user-42 ",
                    "alias": "  Pal  "
                }
            ]
        });
        let entries = parse_friends_request(&payload).expect("valid friends payload");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].user_id, "user-42");
        assert_eq!(entries[0].alias.as_deref(), Some("Pal"));
    }

    #[test]
    fn friends_request_rejects_handle_field() {
        let payload = json!({
            "friends": [
                {
                    "user_id": "user-1",
                    "handle": "alice"
                }
            ]
        });
        match parse_friends_request(&payload) {
            Err(ApiError::BadRequest(message)) => assert!(message.contains("handle")),
            Err(_) => panic!("unexpected error variant"),
            Ok(_) => panic!("handle field must be rejected"),
        }
    }

    #[test]
    fn friends_request_rejects_duplicate_ids() {
        let payload = json!({
            "friends": [
                { "user_id": "user-1" },
                { "user_id": "user-1" }
            ]
        });
        match parse_friends_request(&payload) {
            Err(ApiError::BadRequest(message)) => assert!(message.contains("duplicate")),
            Err(_) => panic!("unexpected error variant"),
            Ok(_) => panic!("duplicate friend user_id must be rejected"),
        }
    }

    #[test]
    fn friend_user_id_percent_decoding() {
        let decoded = decode_friend_user_id("alice%2Fbob").expect("percent decoding succeeds");
        assert_eq!(decoded, "alice/bob");
        let plain = decode_friend_user_id("user-123").expect("plain id is unchanged");
        assert_eq!(plain, "user-123");
    }

    #[test]
    fn friend_user_id_rejects_invalid_percent_sequences() {
        let err = decode_friend_user_id("bad%2").expect_err("truncated escape rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));
        let err = decode_friend_user_id("%zz").expect_err("non-hex escape rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));
        let err = decode_friend_user_id("%ff").expect_err("invalid utf-8 rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn friends_blob_accepts_legacy_entries() {
        let raw = r#"[{"user_id": "user-1", "handle": "alice", "alias": "  Pal  "}]"#;
        let entries = parse_friends_blob(raw).expect("legacy friends blob");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].user_id, "user-1");
        assert_eq!(entries[0].alias.as_deref(), Some("Pal"));
    }
}

impl Error for ServerError {}

impl From<StorageError> for ServerError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::Invalid | StorageError::Missing => ServerError::Invalid,
            _ => ServerError::Storage,
        }
    }
}

impl From<LedgerError> for ServerError {
    fn from(_: LedgerError) -> Self {
        ServerError::Ledger
    }
}

impl From<CryptoError> for ServerError {
    fn from(_: CryptoError) -> Self {
        ServerError::Crypto
    }
}

impl From<commucat_proto::CodecError> for ServerError {
    fn from(_: commucat_proto::CodecError) -> Self {
        ServerError::Codec
    }
}

impl From<FederationError> for ServerError {
    fn from(_: FederationError) -> Self {
        ServerError::Federation
    }
}

fn user_snapshot(profile: &UserProfile) -> serde_json::Value {
    let user_id = profile.user_id.clone();
    json!({
        "id": user_id.clone(),
        "user_id": user_id,
        "handle": profile.handle.clone(),
        "display_name": profile.display_name.clone(),
        "avatar_url": profile.avatar_url.clone(),
    })
}

pub struct AppState {
    pub config: ServerConfig,
    pub storage: Arc<Storage>,
    pub ledger: Box<dyn LedgerAdapterTrait + Send + Sync>,
    pub metrics: Arc<Metrics>,
    pub connections: RwLock<HashMap<String, ConnectionEntry>>,
    pub channel_routes: RwLock<HashMap<u64, ChannelRoute>>,
    pub call_sessions: RwLock<HashMap<String, CallSession>>,
    pub media_transcoders: RwLock<HashMap<String, SharedCallMediaTranscoder>>,
    pub peer_sessions: RwLock<HashMap<String, PeerPresence>>,
    pub allowed_peers: HashMap<String, PeerConfig>,
    pub dynamic_peers: RwLock<HashMap<String, PeerConfig>>,
    pub federation_signer: EventSigner,
    pub device_ca_public: [u8; 32],
    pub presence_ttl: i64,
    pub relay_ttl: i64,
    pub secrets: Arc<SecretManager>,
    pub rate_limits: Arc<RateLimiter>,
    pub transports: RwLock<TransportManager>,
}

pub struct ConnectionEntry {
    pub sender: mpsc::Sender<Frame>,
    pub session_id: String,
    pub user_id: String,
    next_sequence: AtomicU64,
}

impl ConnectionEntry {
    pub fn new(sender: mpsc::Sender<Frame>, session_id: String, user_id: String) -> Self {
        ConnectionEntry {
            sender,
            session_id,
            user_id,
            next_sequence: AtomicU64::new(1),
        }
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence.fetch_add(1, Ordering::SeqCst)
    }
}

#[derive(Clone)]
pub struct ChannelRoute {
    pub members: HashSet<String>,
    pub relay: bool,
    pub group_id: Option<String>,
}

#[derive(Clone)]
pub struct CallSession {
    pub call_id: String,
    pub channel_id: u64,
    pub initiator: String,
    pub started_at: chrono::DateTime<Utc>,
    pub last_update: chrono::DateTime<Utc>,
    pub media: CallMediaProfile,
    pub accepted: HashSet<String>,
    pub participants: HashSet<String>,
    pub stats: HashMap<String, ProtoCallStats>,
    pub transport: Option<CallTransport>,
    pub transport_updates: HashMap<String, CallTransportUpdate>,
}

pub struct PeerPresence {
    pub address: Option<String>,
    pub last_seen: chrono::DateTime<Utc>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct FriendEntryPayload {
    user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
struct FriendDeviceSnapshot {
    device_id: String,
    public_key: String,
    status: String,
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_rotated_at: Option<String>,
}

#[derive(Deserialize)]
struct PairCreateRequest {
    ttl: Option<i64>,
}

#[derive(Deserialize)]
struct PairClaimRequest {
    pair_code: String,
    device_name: Option<String>,
}

#[derive(Deserialize)]
struct DeviceRevokeRequest {
    device_id: String,
}

#[derive(Deserialize)]
struct FederationRelayPayload {
    #[serde(rename = "channel", default)]
    _channel: Option<u64>,
    payload: String,
    #[serde(rename = "sender", default)]
    _sender: Option<String>,
    target: String,
    #[serde(default)]
    _sequence: Option<u64>,
}

#[derive(Debug)]
struct SessionContext {
    user: UserProfile,
    device: DeviceRecord,
}

#[derive(Debug)]
enum ApiError {
    Unauthorized(Option<String>),
    Forbidden,
    BadRequest(String),
    NotFound,
    Conflict(String),
    Internal,
}

impl ApiError {
    fn status(&self) -> u16 {
        match self {
            Self::Unauthorized(_) => 401,
            Self::Forbidden => 403,
            Self::BadRequest(_) => 400,
            Self::NotFound => 404,
            Self::Conflict(_) => 409,
            Self::Internal => 500,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::BadRequest(_) => "BadRequest",
            Self::NotFound => "NotFound",
            Self::Conflict(_) => "Conflict",
            Self::Internal => "InternalError",
        }
    }
}

impl FriendEntryPayload {
    fn from_storage_value(value: &Value) -> Result<Self, ApiError> {
        let map = value.as_object().ok_or(ApiError::Internal)?;
        let user_id = map
            .get("user_id")
            .or_else(|| map.get("id"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(ApiError::Internal)?;
        let alias = match map.get("alias") {
            Some(Value::Null) | None => None,
            Some(Value::String(value)) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            Some(_) => return Err(ApiError::Internal),
        };
        Ok(Self {
            user_id: user_id.to_string(),
            alias,
        })
    }

    fn from_request_value(value: &Value) -> Result<Self, ApiError> {
        let map = value.as_object().ok_or_else(|| {
            ApiError::BadRequest("friend entry must be a JSON object".to_string())
        })?;
        if map.contains_key("handle") {
            return Err(ApiError::BadRequest(
                "friend entry must specify user_id; handle is not supported".to_string(),
            ));
        }
        for key in map.keys() {
            if key != "user_id" && key != "alias" {
                return Err(ApiError::BadRequest(format!(
                    "unexpected field in friend entry: {}",
                    key
                )));
            }
        }
        let user_id_raw = map
            .get("user_id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| ApiError::BadRequest("friend.user_id is required".to_string()))?;
        let user_id = user_id_raw.trim();
        if user_id.is_empty() {
            return Err(ApiError::BadRequest(
                "friend.user_id must be a non-empty string".to_string(),
            ));
        }
        let alias = match map.get("alias") {
            Some(Value::Null) | None => None,
            Some(Value::String(value)) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            Some(_) => {
                return Err(ApiError::BadRequest(
                    "friend.alias must be a string if present".to_string(),
                ));
            }
        };
        Ok(Self {
            user_id: user_id.to_string(),
            alias,
        })
    }
}

enum HandshakeStage {
    Hello,
    AwaitClient,
    Established,
}

struct HandshakeContext {
    stage: HandshakeStage,
    device_id: String,
    device_public: [u8; 32],
    session_id: String,
    user_id: String,
    user_profile: Option<UserProfile>,
    handshake: Option<NoiseHandshake>,
    protocol_version: u16,
    certificate: Option<DeviceCertificate>,
    noise_key: Option<NoiseKey>,
    transport: Option<Arc<Mutex<NoiseTransport>>>,
}

pub struct CommuCatApp {
    pub state: Arc<AppState>,
}

impl CommuCatApp {
    pub fn new(state: Arc<AppState>) -> Self {
        CommuCatApp { state }
    }

    pub async fn init(config: ServerConfig) -> Result<Arc<AppState>, ServerError> {
        let storage = Arc::new(connect(&config.postgres_dsn, &config.redis_url).await?);
        let ledger: Box<dyn LedgerAdapterTrait + Send + Sync> = match config.ledger.adapter {
            LedgerAdapter::Null => Box::new(NullLedger),
            LedgerAdapter::Debug => Box::new(DebugLedgerAdapter),
            LedgerAdapter::File => {
                let target = config.ledger.target.as_ref().ok_or(ServerError::Invalid)?;
                let adapter = FileLedgerAdapter::new(std::path::PathBuf::from(target))
                    .map_err(|_| ServerError::Ledger)?;
                Box::new(adapter)
            }
        };
        let metrics = Arc::new(Metrics::new());
        let rate_limits = Arc::new(RateLimiter::new(&config.rate_limit));
        let secrets = SecretManager::bootstrap(
            Arc::clone(&storage),
            Arc::clone(&metrics),
            config.rotation.clone(),
            config.noise_private,
            config.noise_public,
            config.admin_token.clone(),
        )
        .await?;
        let allowed_peers = config
            .peers
            .iter()
            .cloned()
            .map(|peer| (peer.domain.to_ascii_lowercase(), peer))
            .collect::<HashMap<String, PeerConfig>>();
        storage.migrate().await?;
        let stored_peers = storage
            .list_federation_peers()
            .await?
            .into_iter()
            .filter(|peer| {
                matches!(
                    peer.status,
                    FederationPeerStatus::Active | FederationPeerStatus::Pending
                )
            })
            .map(|peer| {
                let route = PeerConfig {
                    domain: peer.domain.clone(),
                    endpoint: peer.endpoint.clone(),
                    public_key: peer.public_key,
                };
                (peer.domain.to_ascii_lowercase(), route)
            })
            .collect::<HashMap<String, PeerConfig>>();
        let mut dynamic_seed = HashMap::new();
        for (domain, peer) in stored_peers.into_iter() {
            if !allowed_peers.contains_key(&domain) {
                dynamic_seed.insert(domain, peer);
            }
        }
        let signer = EventSigner::new(&config.federation_seed);
        let device_ca_public = signer.public_key();
        let reality_cfg = config
            .transport
            .reality
            .as_ref()
            .map(|settings| RealityConfig {
                certificate_pem: Arc::new(settings.certificate_pem.clone()),
                fingerprint: settings.fingerprint,
            });
        let transports = default_manager(reality_cfg);
        let state = Arc::new(AppState {
            storage: Arc::clone(&storage),
            ledger,
            metrics: Arc::clone(&metrics),
            connections: RwLock::new(HashMap::new()),
            channel_routes: RwLock::new(HashMap::new()),
            call_sessions: RwLock::new(HashMap::new()),
            media_transcoders: RwLock::new(HashMap::new()),
            peer_sessions: RwLock::new(HashMap::new()),
            allowed_peers,
            dynamic_peers: RwLock::new(dynamic_seed),
            federation_signer: signer,
            device_ca_public,
            presence_ttl: config.presence_ttl_seconds,
            relay_ttl: config.relay_ttl_seconds,
            secrets: Arc::clone(&secrets),
            rate_limits: Arc::clone(&rate_limits),
            transports: RwLock::new(transports),
            config,
        });
        secrets.spawn();
        let transport_state = Arc::clone(&state);
        tokio::spawn(async move {
            let cfg = &transport_state.config;
            let (address, port) = cfg
                .bind
                .rsplit_once(':')
                .and_then(|(host, port)| port.parse::<u16>().ok().map(|p| (host.to_string(), p)))
                .unwrap_or_else(|| (cfg.bind.clone(), 443));
            let reality = cfg
                .transport
                .reality
                .as_ref()
                .map(|settings| RealityConfig {
                    certificate_pem: Arc::new(settings.certificate_pem.clone()),
                    fingerprint: settings.fingerprint,
                });
            let endpoint = Endpoint {
                address,
                port,
                server_name: Some(cfg.domain.clone()),
                reality,
            };
            let mut manager = transport_state.transports.write().await;
            let available = manager.list_transports();
            info!(transports = ?available, "transport candidates prepared");
            match manager.establish_connection(&endpoint).await {
                Ok(session) => {
                    info!(transport = ?session.transport, "transport bootstrap established");
                }
                Err(err) => {
                    warn!(error = %err, "transport bootstrap failed");
                }
            }
        });
        let cleanup_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut ticker = interval(StdDuration::from_secs(60));
            loop {
                ticker.tick().await;
                match cleanup_state.storage.invalidate_expired_pairings().await {
                    Ok(purged) => {
                        if purged > 0 {
                            info!(tokens = purged, "expired pairing tokens purged");
                        }
                    }
                    Err(err) => warn!("pairing cleanup failed: {}", err),
                }
            }
        });
        spawn_dispatcher(Arc::clone(&state));
        Ok(state)
    }
}

impl HttpServerApp for CommuCatApp {
    fn process_new_http<'life0, 'life1, 'async_trait>(
        self: &'life0 Arc<Self>,
        session: ServerSession,
        shutdown: &'life1 ShutdownWatch,
    ) -> Pin<Box<dyn Future<Output = Option<ReusedHttpStream>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.handle_session(session, shutdown).await })
    }

    fn h2_options(&self) -> Option<H2Options> {
        None
    }

    fn server_options(&self) -> Option<&HttpServerOptions> {
        None
    }
}

fn parse_friends_blob(blob: &str) -> Result<Vec<FriendEntryPayload>, ApiError> {
    if blob.trim().is_empty() {
        return Ok(Vec::new());
    }
    let raw = serde_json::from_str::<Vec<Value>>(blob).map_err(|_| ApiError::Internal)?;
    let mut entries = Vec::with_capacity(raw.len());
    for value in raw.iter() {
        entries.push(FriendEntryPayload::from_storage_value(value)?);
    }
    Ok(entries)
}

fn parse_friends_request(root: &Value) -> Result<Vec<FriendEntryPayload>, ApiError> {
    let map = root
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("payload must be a JSON object".to_string()))?;
    let friends_value = map
        .get("friends")
        .ok_or_else(|| ApiError::BadRequest("\"friends\" field is required".to_string()))?;
    let friends_array = friends_value
        .as_array()
        .ok_or_else(|| ApiError::BadRequest("\"friends\" must be an array".to_string()))?;
    let mut entries = Vec::with_capacity(friends_array.len());
    let mut seen = HashSet::new();
    for value in friends_array {
        let entry = FriendEntryPayload::from_request_value(value)?;
        if !seen.insert(entry.user_id.clone()) {
            return Err(ApiError::BadRequest(format!(
                "duplicate friend user_id: {}",
                entry.user_id
            )));
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn decode_friend_user_id(segment: &str) -> Result<String, ApiError> {
    if segment.is_empty() {
        return Err(ApiError::BadRequest("missing friend user id".to_string()));
    }
    if !segment.contains('%') {
        return Ok(segment.to_string());
    }
    let mut buffer = Vec::with_capacity(segment.len());
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(ApiError::BadRequest(
                        "invalid percent-encoding in friend user id".to_string(),
                    ));
                }
                let hex = &segment[index + 1..index + 3];
                let decoded = decode_hex(hex).map_err(|_| {
                    ApiError::BadRequest("invalid percent-encoding in friend user id".to_string())
                })?;
                if decoded.is_empty() {
                    return Err(ApiError::BadRequest(
                        "invalid percent-encoding in friend user id".to_string(),
                    ));
                }
                buffer.extend_from_slice(&decoded);
                index += 3;
            }
            byte => {
                buffer.push(byte);
                index += 1;
            }
        }
    }
    if buffer.is_empty() {
        return Err(ApiError::BadRequest(
            "friend user id must not be empty".to_string(),
        ));
    }
    String::from_utf8(buffer)
        .map_err(|_| ApiError::BadRequest("friend user id must be valid UTF-8".to_string()))
}

impl CommuCatApp {
    async fn handle_session(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        match session.read_request().await {
            Ok(true) => {}
            Ok(false) => return None,
            Err(err) => {
                error!("failed to read request: {}", err);
                return None;
            }
        }
        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.to_string();
        if path != "/connect"
            && let Some(retry_after) = self.check_rate_limit(&session, RateScope::Http).await
        {
            self.state.metrics.mark_http_rate_limited();
            if let Err(err) = self.respond_rate_limited(session, retry_after).await {
                error!("rate limit response failed: {}", err);
            }
            return None;
        }
        match path.as_str() {
            "/" | "/index.html" => {
                self.state.metrics.mark_ingress();
                let mut response = ResponseHeader::build_no_case(200, None).ok()?;
                response
                    .append_header("content-type", "text/html; charset=utf-8")
                    .ok()?;
                session
                    .write_response_header(Box::new(response))
                    .await
                    .ok()?;
                session
                    .write_response_body(Vec::from(LANDING_PAGE.as_bytes()).into(), true)
                    .await
                    .ok()?;
                session.finish().await.ok()?;
                return None;
            }
            "/healthz" => {
                self.state.metrics.mark_ingress();
                let mut response = ResponseHeader::build_no_case(200, None).ok()?;
                response.append_header("content-type", "text/plain").ok()?;
                session
                    .write_response_header(Box::new(response))
                    .await
                    .ok()?;
                session
                    .write_response_body(Vec::from("ok".as_bytes()).into(), true)
                    .await
                    .ok()?;
                session.finish().await.ok()?;
                return None;
            }
            "/readyz" => {
                if self.state.storage.readiness().await.is_ok() {
                    let mut response = ResponseHeader::build_no_case(200, None).ok()?;
                    response.append_header("content-type", "text/plain").ok()?;
                    session
                        .write_response_header(Box::new(response))
                        .await
                        .ok()?;
                    session
                        .write_response_body(Vec::from("ready".as_bytes()).into(), true)
                        .await
                        .ok()?;
                } else {
                    let mut response = ResponseHeader::build_no_case(503, None).ok()?;
                    response.append_header("content-type", "text/plain").ok()?;
                    session
                        .write_response_header(Box::new(response))
                        .await
                        .ok()?;
                    session
                        .write_response_body(Vec::from("degraded".as_bytes()).into(), true)
                        .await
                        .ok()?;
                }
                session.finish().await.ok()?;
                return None;
            }
            "/metrics" => {
                if !self.authorize_admin(&session).await {
                    let mut response = ResponseHeader::build_no_case(401, None).ok()?;
                    response
                        .append_header("content-type", "application/problem+json")
                        .ok()?;
                    let body = json!({
                        "type": "about:blank",
                        "title": "Unauthorized",
                        "status": 401,
                    })
                    .to_string();
                    session
                        .write_response_header(Box::new(response))
                        .await
                        .ok()?;
                    session
                        .write_response_body(body.into_bytes().into(), true)
                        .await
                        .ok()?;
                    session.finish().await.ok()?;
                    return None;
                }
                let payload = self.state.metrics.encode_prometheus();
                let mut response = ResponseHeader::build_no_case(200, None).ok()?;
                response
                    .append_header("content-type", "text/plain; version=0.0.4")
                    .ok()?;
                session
                    .write_response_header(Box::new(response))
                    .await
                    .ok()?;
                session
                    .write_response_body(payload.into_bytes().into(), true)
                    .await
                    .ok()?;
                session.finish().await.ok()?;
                return None;
            }
            _ => {}
        }
        if path == "/openapi.json" && method == "GET" {
            self.state.metrics.mark_ingress();
            if let Err(err) = self.handle_openapi_spec(&mut session).await {
                error!("openapi spec response failed: {}", err);
            }
            return None;
        }
        if path == "/api/server-info" && method == "GET" {
            self.state.metrics.mark_ingress();
            if let Err(err) = self.handle_server_info(&mut session).await {
                error!("server info response failed: {}", err);
            }
            return None;
        }

        // GET /uploads/{filename} - отдача загруженных файлов
        if let Some(filename) = path.strip_prefix("/uploads/")
            && method == "GET"
        {
            self.state.metrics.mark_ingress();
            if let Err(err) = self.handle_uploads_get(&mut session, filename).await {
                error!("uploads get failed: {}", err);
            }
            return None;
        }

        if path == "/api/friends" && method == "GET" {
            self.state.metrics.mark_ingress();
            match self.handle_friends_get(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/api/friends" && method == "PUT" {
            self.state.metrics.mark_ingress();
            match self.handle_friends_put(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if let Some(rest) = path.strip_prefix("/api/friends/")
            && method == "GET"
            && rest.ends_with("/devices")
            && let Some(friend_id) = rest.strip_suffix("/devices")
        {
            let friend_user_id_raw = friend_id.trim_end_matches('/');
            if friend_user_id_raw.is_empty() {
                let _ = self
                    .respond_api_error(
                        &mut session,
                        ApiError::BadRequest("missing friend user id".to_string()),
                    )
                    .await;
                return None;
            }
            let friend_user_id = match decode_friend_user_id(friend_user_id_raw) {
                Ok(value) => value,
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                    return None;
                }
            };
            self.state.metrics.mark_ingress();
            match self
                .handle_friend_devices_get(&mut session, &friend_user_id)
                .await
            {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }

        // POST /api/users/me/avatar - загрузка аватарки
        if path == "/api/users/me/avatar" && method == "POST" {
            self.state.metrics.mark_ingress();
            match self.handle_avatar_upload(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }

        // GET /api/friends/requests - список запросов в друзья
        if path == "/api/friends/requests" && method == "GET" {
            self.state.metrics.mark_ingress();
            match self.handle_friend_requests_list(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        // POST /api/friends/requests/{user_id} - создать запрос в друзья
        // POST /api/friends/requests/{user_id}/accept - принять запрос
        // POST /api/friends/requests/{user_id}/reject - отклонить запрос
        if let Some(rest) = path.strip_prefix("/api/friends/requests/")
            && method == "POST"
        {
            let parts: Vec<&str> = rest.trim_end_matches('/').split('/').collect();
            if parts.is_empty() || parts[0].is_empty() {
                let _ = self
                    .respond_api_error(
                        &mut session,
                        ApiError::BadRequest("missing user id".to_string()),
                    )
                    .await;
                return None;
            }

            let user_id_raw = parts[0];
            let user_id = match decode_friend_user_id(user_id_raw) {
                Ok(value) => value,
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                    return None;
                }
            };

            self.state.metrics.mark_ingress();

            if parts.len() == 1 {
                // POST /api/friends/requests/{user_id} - создать запрос
                match self
                    .handle_friend_request_create(&mut session, &user_id)
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        let _ = self.respond_api_error(&mut session, err).await;
                    }
                }
            } else if parts.len() == 2 && parts[1] == "accept" {
                // POST /api/friends/requests/{user_id}/accept
                match self
                    .handle_friend_request_accept(&mut session, &user_id)
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        let _ = self.respond_api_error(&mut session, err).await;
                    }
                }
            } else if parts.len() == 2 && parts[1] == "reject" {
                // POST /api/friends/requests/{user_id}/reject
                match self
                    .handle_friend_request_reject(&mut session, &user_id)
                    .await
                {
                    Ok(()) => {}
                    Err(err) => {
                        let _ = self.respond_api_error(&mut session, err).await;
                    }
                }
            } else {
                let _ = self
                    .respond_api_error(&mut session, ApiError::NotFound)
                    .await;
            }
            return None;
        }
        // DELETE /api/friends/{user_id} - удалить друга
        if let Some(rest) = path.strip_prefix("/api/friends/")
            && method == "DELETE"
            && !rest.contains('/')
        {
            let friend_user_id_raw = rest.trim_end_matches('/');
            if friend_user_id_raw.is_empty() {
                let _ = self
                    .respond_api_error(
                        &mut session,
                        ApiError::BadRequest("missing friend user id".to_string()),
                    )
                    .await;
                return None;
            }
            let friend_user_id = match decode_friend_user_id(friend_user_id_raw) {
                Ok(value) => value,
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                    return None;
                }
            };
            self.state.metrics.mark_ingress();
            match self
                .handle_friend_delete(&mut session, &friend_user_id)
                .await
            {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/api/pair" && method == "POST" {
            self.state.metrics.mark_ingress();
            match self.handle_pair_create(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/api/pair/claim" && method == "POST" {
            if let Some(retry_after) = self
                .check_rate_limit(&session, RateScope::PairingClaim)
                .await
            {
                self.state.metrics.mark_http_rate_limited();
                if let Err(err) = self.respond_rate_limited(session, retry_after).await {
                    error!("pairing claim rate limit response failed: {}", err);
                }
                return None;
            }
            self.state.metrics.mark_ingress();
            match self.handle_pair_claim(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/api/p2p/assist" && method == "POST" {
            self.state.metrics.mark_ingress();
            let body = match Self::read_body(&mut session).await {
                Ok(payload) => payload,
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                    return None;
                }
            };
            let request = if body.is_empty() {
                p2p::P2pAssistRequest {
                    peer_hint: None,
                    paths: Vec::new(),
                    prefer_reality: true,
                    fec: None,
                    min_paths: None,
                }
            } else {
                match serde_json::from_slice::<p2p::P2pAssistRequest>(&body) {
                    Ok(req) => req,
                    Err(_) => {
                        let _ = self
                            .respond_api_error(
                                &mut session,
                                ApiError::BadRequest("invalid JSON payload".to_string()),
                            )
                            .await;
                        return None;
                    }
                }
            };
            match p2p::handle_assist(&self.state, request).await {
                Ok(response) => match serde_json::to_value(response) {
                    Ok(payload) => {
                        if let Err(err) = self
                            .respond_json(&mut session, 200, payload, "application/json")
                            .await
                        {
                            error!("p2p assistance response failed: {}", err);
                        }
                    }
                    Err(_) => {
                        let _ = self
                            .respond_api_error(&mut session, ApiError::Internal)
                            .await;
                    }
                },
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/api/security-stats" && method == "GET" {
            self.state.metrics.mark_ingress();
            let snapshot = self.state.metrics.security_snapshot();
            match serde_json::to_value(snapshot) {
                Ok(payload) => {
                    if let Err(err) = self
                        .respond_json(&mut session, 200, payload, "application/json")
                        .await
                    {
                        error!("security stats response failed: {}", err);
                    }
                }
                Err(_) => {
                    let _ = self
                        .respond_api_error(&mut session, ApiError::Internal)
                        .await;
                }
            }
            return None;
        }
        if path == "/api/device/csr" && method == "POST" {
            self.state.metrics.mark_ingress();
            match self.handle_device_csr(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/api/devices" && method == "GET" {
            self.state.metrics.mark_ingress();
            match self.handle_devices_list(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/api/devices/revoke" && method == "POST" {
            self.state.metrics.mark_ingress();
            match self.handle_device_revoke(&mut session).await {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.respond_api_error(&mut session, err).await;
                }
            }
            return None;
        }
        if path == "/federation/events" && method == "POST" {
            match self.handle_federation_event(&mut session).await {
                Ok(()) => {}
                Err(err) => warn!(error = %err, "federation event processing failed"),
            }
            return None;
        }
        if path == "/connect" && method == "POST" {
            return self.process_connect(session, shutdown).await;
        }
        let mut response = ResponseHeader::build_no_case(404, None).ok()?;
        response
            .append_header("content-type", "application/problem+json")
            .ok()?;
        let body = json!({
            "type": "about:blank",
            "title": "Not Found",
            "status": 404,
        })
        .to_string();
        session
            .write_response_header(Box::new(response))
            .await
            .ok()?;
        session
            .write_response_body(body.into_bytes().into(), true)
            .await
            .ok()?;
        session.finish().await.ok()?;
        None
    }

    async fn handle_openapi_spec(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ServerError> {
        let spec = openapi::openapi_json();
        let mut response =
            ResponseHeader::build_no_case(200, None).map_err(|_| ServerError::Invalid)?;
        response
            .append_header("content-type", "application/json")
            .map_err(|_| ServerError::Invalid)?;
        response
            .append_header("cache-control", "no-store")
            .map_err(|_| ServerError::Invalid)?;
        session
            .write_response_header(Box::new(response))
            .await
            .map_err(|_| ServerError::Io)?;
        session
            .write_response_body(spec.as_bytes().to_vec().into(), true)
            .await
            .map_err(|_| ServerError::Io)?;
        self.state.metrics.mark_egress();
        Ok(())
    }

    async fn handle_server_info(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ServerError> {
        let noise_catalog = self.state.secrets.noise_catalog().await;
        let current_noise_hex = if let Some(first) = noise_catalog.first() {
            encode_hex(&first.public)
        } else {
            encode_hex(&self.state.config.noise_public)
        };
        let noise_keys = noise_catalog
            .iter()
            .map(|key| {
                json!({
                    "version": key.version,
                    "public": encode_hex(&key.public),
                    "valid_after": key.valid_after.to_rfc3339(),
                    "rotates_at": key.rotates_at.to_rfc3339(),
                    "expires_at": key.expires_at.to_rfc3339(),
                })
            })
            .collect::<Vec<_>>();
        let payload = json!({
            "domain": self.state.config.domain,
            "noise_public": current_noise_hex,
            "noise_keys": noise_keys,
            "device_ca_public": encode_hex(&self.state.device_ca_public),
            "supported_patterns": ["XK", "IK"],
            "supported_versions": SUPPORTED_PROTOCOL_VERSIONS,
            "session": {
                "ttl_seconds": self.state.config.connection_keepalive,
                "keepalive_interval": self.state.config.connection_keepalive / 2,
            },
            "presence": {
                "ttl_seconds": self.state.config.presence_ttl_seconds,
            },
            "device_rotation": {
                "enabled": self.state.config.device_rotation.enabled,
                "min_interval_seconds": self.state.config.device_rotation.min_interval.as_secs(),
                "proof_ttl_seconds": self.state.config.device_rotation.proof_ttl.as_secs(),
            },
            "pairing": {
                "auto_approve": self.state.config.auto_approve_devices,
                "pairing_ttl": self.state.config.pairing_ttl_seconds,
                "max_auto_devices": self.state.config.max_auto_devices_per_user,
            }
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
    }

    async fn handle_friends_get(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;
        let blob = self
            .state
            .storage
            .read_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY)
            .await
            .map_err(|_| ApiError::Internal)?;
        let friends = match blob {
            Some(data) => parse_friends_blob(&data)?,
            None => Vec::new(),
        };
        let friend_ids = friends
            .iter()
            .map(|entry| entry.user_id.clone())
            .collect::<Vec<_>>();
        let device_snapshots = self
            .collect_friend_device_snapshots(&friend_ids)
            .await
            .map_err(|_| ApiError::Internal)?;
        let devices_value = self
            .build_friend_devices_value(&friends, device_snapshots)
            .map_err(|_| ApiError::Internal)?;
        let payload = json!({
            "friends": friends,
            "devices": devices_value,
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_friends_put(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;
        let body = Self::read_body(session).await?;
        let root = serde_json::from_slice::<Value>(&body)
            .map_err(|_| ApiError::BadRequest("invalid JSON payload".to_string()))?;
        let friends = parse_friends_request(&root)?;
        if friends.len() > 512 {
            return Err(ApiError::BadRequest("too many friends".to_string()));
        }
        let serialized = serde_json::to_string(&friends).map_err(|_| ApiError::Internal)?;
        self.state
            .storage
            .write_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY, &serialized)
            .await
            .map_err(|_| ApiError::Internal)?;
        let friend_ids = friends
            .iter()
            .map(|entry| entry.user_id.clone())
            .collect::<Vec<_>>();
        let device_snapshots = self
            .collect_friend_device_snapshots(&friend_ids)
            .await
            .map_err(|_| ApiError::Internal)?;
        let devices_value = self
            .build_friend_devices_value(&friends, device_snapshots)
            .map_err(|_| ApiError::Internal)?;
        let payload = json!({
            "friends": friends,
            "devices": devices_value,
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_friend_devices_get(
        self: &Arc<Self>,
        session: &mut ServerSession,
        friend_user_id: &str,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;

        // Преобразуем friend_user_id (может быть handle или user_id) в актуальный user_id
        let actual_friend_user_id = match self.state.storage.load_user(friend_user_id).await {
            Ok(user) => user.user_id,
            Err(_) => {
                // Если не найден по user_id, пробуем по handle
                self.state
                    .storage
                    .load_user_by_handle(friend_user_id)
                    .await
                    .map_err(|err| match err {
                        StorageError::Missing => ApiError::NotFound,
                        _ => ApiError::Internal,
                    })?
                    .user_id
            }
        };

        let blob = self
            .state
            .storage
            .read_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY)
            .await
            .map_err(|_| ApiError::Internal)?;
        let friends = match blob {
            Some(data) => parse_friends_blob(&data)?,
            None => Vec::new(),
        };
        if !friends
            .iter()
            .any(|entry| entry.user_id == actual_friend_user_id)
        {
            return Err(ApiError::NotFound);
        }
        let friend_ids = vec![actual_friend_user_id.clone()];
        let device_snapshots = self
            .collect_friend_device_snapshots(&friend_ids)
            .await
            .map_err(|_| ApiError::Internal)?;
        let snapshots = device_snapshots
            .get(&actual_friend_user_id)
            .cloned()
            .unwrap_or_default();
        let payload = json!({
            "friend": actual_friend_user_id,
            "devices": snapshots,
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_friend_request_create(
        self: &Arc<Self>,
        session: &mut ServerSession,
        to_user_id: &str,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;

        // Нельзя отправить запрос самому себе
        if context.user.user_id == to_user_id {
            return Err(ApiError::BadRequest(
                "cannot send friend request to yourself".to_string(),
            ));
        }

        // Проверяем существование целевого пользователя (может быть user_id или handle)
        let to_user = match self.state.storage.load_user(to_user_id).await {
            Ok(user) => user,
            Err(_) => {
                // Если не найден по user_id, пробуем по handle
                self.state
                    .storage
                    .load_user_by_handle(to_user_id)
                    .await
                    .map_err(|err| match err {
                        StorageError::Missing => ApiError::NotFound,
                        _ => ApiError::Internal,
                    })?
            }
        };

        // Используем фактический user_id из профиля
        let actual_to_user_id = &to_user.user_id;

        // Проверяем, не существует ли уже запрос
        let existing = self
            .state
            .storage
            .friend_request_exists(&context.user.user_id, actual_to_user_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        if let Some(req) = existing
            && req.status == "pending"
        {
            return Err(ApiError::Conflict(
                "friend request already exists".to_string(),
            ));
        }

        let body = Self::read_body(session).await?;
        let message = if body.is_empty() {
            None
        } else {
            let req: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|_| ApiError::BadRequest("invalid JSON payload".to_string()))?;
            req.get("message")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };

        let request_id = generate_id("friend-request");
        let friend_request = self
            .state
            .storage
            .create_friend_request(
                &request_id,
                &context.user.user_id,
                actual_to_user_id,
                message.as_deref(),
            )
            .await
            .map_err(|_| ApiError::Internal)?;

        let payload = json!({
            "request": {
                "id": friend_request.id,
                "from_user_id": friend_request.from_user_id,
                "to_user_id": friend_request.to_user_id,
                "status": friend_request.status,
                "message": friend_request.message,
                "created_at": friend_request.created_at.to_rfc3339(),
                "updated_at": friend_request.updated_at.to_rfc3339(),
            },
            "to_user": {
                "user_id": to_user.user_id,
                "handle": to_user.handle,
                "display_name": to_user.display_name,
                "avatar_url": to_user.avatar_url,
            }
        });
        self.respond_json(session, 201, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_friend_requests_list(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;

        let incoming = self
            .state
            .storage
            .list_incoming_friend_requests(&context.user.user_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        let outgoing = self
            .state
            .storage
            .list_outgoing_friend_requests(&context.user.user_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        let incoming_json: Vec<_> = incoming
            .iter()
            .map(|req| {
                json!({
                    "id": req.id,
                    "from_user_id": req.from_user_id,
                    "to_user_id": req.to_user_id,
                    "status": req.status,
                    "message": req.message,
                    "created_at": req.created_at.to_rfc3339(),
                    "updated_at": req.updated_at.to_rfc3339(),
                })
            })
            .collect();

        let outgoing_json: Vec<_> = outgoing
            .iter()
            .map(|req| {
                json!({
                    "id": req.id,
                    "from_user_id": req.from_user_id,
                    "to_user_id": req.to_user_id,
                    "status": req.status,
                    "message": req.message,
                    "created_at": req.created_at.to_rfc3339(),
                    "updated_at": req.updated_at.to_rfc3339(),
                })
            })
            .collect();

        let payload = json!({
            "incoming": incoming_json,
            "outgoing": outgoing_json,
        });

        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_friend_request_accept(
        self: &Arc<Self>,
        session: &mut ServerSession,
        from_user_id: &str,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;

        // Преобразуем from_user_id (может быть handle или user_id) в актуальный user_id
        let from_user = match self.state.storage.load_user(from_user_id).await {
            Ok(user) => user,
            Err(_) => {
                // Если не найден по user_id, пробуем по handle
                self.state
                    .storage
                    .load_user_by_handle(from_user_id)
                    .await
                    .map_err(|err| match err {
                        StorageError::Missing => ApiError::NotFound,
                        _ => ApiError::Internal,
                    })?
            }
        };
        let actual_from_user_id = &from_user.user_id;

        // Находим запрос от from_user_id к текущему пользователю
        let existing = self
            .state
            .storage
            .friend_request_exists(actual_from_user_id, &context.user.user_id)
            .await
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::NotFound)?;

        if existing.status != "pending" {
            return Err(ApiError::BadRequest("request is not pending".to_string()));
        }

        // Принимаем запрос
        let accepted = self
            .state
            .storage
            .accept_friend_request(&existing.id)
            .await
            .map_err(|_| ApiError::Internal)?;

        // Автоматически добавляем друг друга в списки друзей
        // Загружаем текущие списки обоих пользователей
        let requester_blob = self
            .state
            .storage
            .read_user_blob(actual_from_user_id, FRIENDS_BLOB_KEY)
            .await
            .map_err(|_| ApiError::Internal)?;

        let accepter_blob = self
            .state
            .storage
            .read_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY)
            .await
            .map_err(|_| ApiError::Internal)?;

        let mut requester_friends = match requester_blob {
            Some(data) => parse_friends_blob(&data)?,
            None => Vec::new(),
        };

        let mut accepter_friends = match accepter_blob {
            Some(data) => parse_friends_blob(&data)?,
            None => Vec::new(),
        };

        // Добавляем друг друга, если ещё нет
        if !requester_friends
            .iter()
            .any(|f| f.user_id == context.user.user_id)
        {
            requester_friends.push(FriendEntryPayload {
                user_id: context.user.user_id.clone(),
                alias: None,
            });
        }

        if !accepter_friends
            .iter()
            .any(|f| f.user_id == *actual_from_user_id)
        {
            accepter_friends.push(FriendEntryPayload {
                user_id: actual_from_user_id.clone(),
                alias: None,
            });
        }

        // Сохраняем обновлённые списки
        let requester_json =
            serde_json::to_string(&requester_friends).map_err(|_| ApiError::Internal)?;
        self.state
            .storage
            .write_user_blob(actual_from_user_id, FRIENDS_BLOB_KEY, &requester_json)
            .await
            .map_err(|_| ApiError::Internal)?;

        let accepter_json =
            serde_json::to_string(&accepter_friends).map_err(|_| ApiError::Internal)?;
        self.state
            .storage
            .write_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY, &accepter_json)
            .await
            .map_err(|_| ApiError::Internal)?;

        let payload = json!({
            "request": {
                "id": accepted.id,
                "from_user_id": accepted.from_user_id,
                "to_user_id": accepted.to_user_id,
                "status": accepted.status,
                "message": accepted.message,
                "created_at": accepted.created_at.to_rfc3339(),
                "updated_at": accepted.updated_at.to_rfc3339(),
            },
            "from_user": {
                "user_id": from_user.user_id,
                "handle": from_user.handle,
                "display_name": from_user.display_name,
                "avatar_url": from_user.avatar_url,
            }
        });

        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_friend_request_reject(
        self: &Arc<Self>,
        session: &mut ServerSession,
        from_user_id: &str,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;

        // Преобразуем from_user_id (может быть handle или user_id) в актуальный user_id
        let actual_from_user_id = match self.state.storage.load_user(from_user_id).await {
            Ok(user) => user.user_id,
            Err(_) => {
                // Если не найден по user_id, пробуем по handle
                self.state
                    .storage
                    .load_user_by_handle(from_user_id)
                    .await
                    .map_err(|err| match err {
                        StorageError::Missing => ApiError::NotFound,
                        _ => ApiError::Internal,
                    })?
                    .user_id
            }
        };

        // Находим запрос от from_user_id к текущему пользователю
        let existing = self
            .state
            .storage
            .friend_request_exists(&actual_from_user_id, &context.user.user_id)
            .await
            .map_err(|_| ApiError::Internal)?
            .ok_or(ApiError::NotFound)?;

        if existing.status != "pending" {
            return Err(ApiError::BadRequest("request is not pending".to_string()));
        }

        let rejected = self
            .state
            .storage
            .reject_friend_request(&existing.id)
            .await
            .map_err(|_| ApiError::Internal)?;

        // Загружаем информацию о пользователе, который отправил запрос
        let from_user = self
            .state
            .storage
            .load_user(&actual_from_user_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        let payload = json!({
            "request": {
                "id": rejected.id,
                "from_user_id": rejected.from_user_id,
                "to_user_id": rejected.to_user_id,
                "status": rejected.status,
                "message": rejected.message,
                "created_at": rejected.created_at.to_rfc3339(),
                "updated_at": rejected.updated_at.to_rfc3339(),
            },
            "from_user": {
                "user_id": from_user.user_id,
                "handle": from_user.handle,
                "display_name": from_user.display_name,
                "avatar_url": from_user.avatar_url,
            }
        });

        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_friend_delete(
        self: &Arc<Self>,
        session: &mut ServerSession,
        friend_user_id: &str,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;

        // Преобразуем friend_user_id (может быть handle или user_id) в актуальный user_id
        let actual_friend_user_id = match self.state.storage.load_user(friend_user_id).await {
            Ok(user) => user.user_id,
            Err(_) => {
                // Если не найден по user_id, пробуем по handle
                self.state
                    .storage
                    .load_user_by_handle(friend_user_id)
                    .await
                    .map_err(|err| match err {
                        StorageError::Missing => ApiError::NotFound,
                        _ => ApiError::Internal,
                    })?
                    .user_id
            }
        };

        let blob = self
            .state
            .storage
            .read_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY)
            .await
            .map_err(|_| ApiError::Internal)?;

        let mut friends = match blob {
            Some(data) => parse_friends_blob(&data)?,
            None => Vec::new(),
        };

        let original_len = friends.len();
        friends.retain(|f| f.user_id != actual_friend_user_id);

        if friends.len() == original_len {
            return Err(ApiError::NotFound);
        }

        let serialized = serde_json::to_string(&friends).map_err(|_| ApiError::Internal)?;
        self.state
            .storage
            .write_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY, &serialized)
            .await
            .map_err(|_| ApiError::Internal)?;

        // Возвращаем 204 No Content
        let mut response =
            ResponseHeader::build_no_case(204, None).map_err(|_| ApiError::Internal)?;
        response
            .append_header("cache-control", "no-store")
            .map_err(|_| ApiError::Internal)?;
        session
            .write_response_header(Box::new(response))
            .await
            .map_err(|_| ApiError::Internal)?;
        Ok(())
    }

    async fn handle_avatar_upload(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;
        let body = Self::read_body(session).await?;

        // Простой парсинг multipart (ищем boundary)
        let content_type = session
            .req_header()
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Для простоты, если Content-Type: image/*, то сохраняем напрямую
        let mime_type = if content_type.starts_with("image/") {
            content_type
        } else {
            "image/jpeg" // default
        };

        // Валидация
        validate_avatar(&body, mime_type).map_err(|err| match err {
            UploadError::TooLarge => {
                ApiError::BadRequest("avatar file too large (max 5 MB)".to_string())
            }
            UploadError::InvalidMimeType => ApiError::BadRequest(
                "invalid image type (allowed: jpeg, png, webp, gif)".to_string(),
            ),
            UploadError::Io(_) => ApiError::Internal,
        })?;

        // Генерируем уникальное имя файла
        let filename = generate_filename(&body, mime_type);

        // Сохраняем файл
        save_file(&self.state.config.uploads_dir, &filename, &body)
            .await
            .map_err(|_| ApiError::Internal)?;

        // Генерируем URL
        let avatar_url = format!("{}/{}", self.state.config.uploads_base_url, filename);

        // Обновляем профиль пользователя
        self.state
            .storage
            .update_user_avatar(&context.user.user_id, &avatar_url)
            .await
            .map_err(|_| ApiError::Internal)?;

        // Возвращаем ответ
        let payload = json!({
            "avatar_url": avatar_url,
            "filename": filename,
        });

        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_uploads_get(
        self: &Arc<Self>,
        session: &mut ServerSession,
        filename: &str,
    ) -> Result<(), ServerError> {
        // Security: validate filename (no path traversal)
        if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
            let mut response =
                ResponseHeader::build_no_case(403, None).map_err(|_| ServerError::Invalid)?;
            response
                .append_header("content-type", "text/plain")
                .map_err(|_| ServerError::Invalid)?;
            session
                .write_response_header(Box::new(response))
                .await
                .map_err(|_| ServerError::Io)?;
            session
                .write_response_body(b"forbidden".to_vec().into(), true)
                .await
                .map_err(|_| ServerError::Io)?;
            return Ok(());
        }

        // Читаем файл
        let data = match read_file(&self.state.config.uploads_dir, filename).await {
            Ok(data) => data,
            Err(_) => {
                let mut response =
                    ResponseHeader::build_no_case(404, None).map_err(|_| ServerError::Invalid)?;
                response
                    .append_header("content-type", "text/plain")
                    .map_err(|_| ServerError::Invalid)?;
                session
                    .write_response_header(Box::new(response))
                    .await
                    .map_err(|_| ServerError::Io)?;
                session
                    .write_response_body(b"not found".to_vec().into(), true)
                    .await
                    .map_err(|_| ServerError::Io)?;
                return Ok(());
            }
        };

        // Определяем MIME type
        let mime_type = mime_type_from_filename(filename);

        // Отдаём файл
        let mut response =
            ResponseHeader::build_no_case(200, None).map_err(|_| ServerError::Invalid)?;
        response
            .append_header("content-type", mime_type)
            .map_err(|_| ServerError::Invalid)?;
        response
            .append_header("cache-control", "public, max-age=31536000, immutable")
            .map_err(|_| ServerError::Invalid)?;
        response
            .append_header("content-length", data.len().to_string())
            .map_err(|_| ServerError::Invalid)?;
        session
            .write_response_header(Box::new(response))
            .await
            .map_err(|_| ServerError::Io)?;
        session
            .write_response_body(data.into(), true)
            .await
            .map_err(|_| ServerError::Io)?;
        self.state.metrics.mark_egress();
        Ok(())
    }

    async fn handle_pair_create(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;
        let body = Self::read_body(session).await?;
        let request = if body.is_empty() {
            PairCreateRequest { ttl: None }
        } else {
            serde_json::from_slice::<PairCreateRequest>(&body)
                .map_err(|_| ApiError::BadRequest("invalid JSON payload".to_string()))?
        };
        let mut ttl = request.ttl.unwrap_or(self.state.config.pairing_ttl_seconds);
        if ttl <= 0 {
            return Err(ApiError::BadRequest("ttl must be positive".to_string()));
        }
        ttl = ttl.min(self.state.config.pairing_ttl_seconds);
        let issued = self
            .state
            .storage
            .create_pairing_token(&context.user.user_id, &context.device.device_id, ttl)
            .await
            .map_err(|err| match err {
                StorageError::Invalid | StorageError::Missing => ApiError::Forbidden,
                _ => ApiError::Internal,
            })?;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let ttl_secs = issued
            .expires_at
            .signed_duration_since(issued.issued_at)
            .num_seconds();
        let payload = json!({
            "pair_code": issued.pair_code,
            "issued_at": issued.issued_at.to_rfc3339(),
            "expires_at": issued.expires_at.to_rfc3339(),
            "ttl": ttl_secs,
            "device_seed": encode_hex(&seed[..]),
            "issuer_device_id": context.device.device_id,
            "device_ca_public": encode_hex(&self.state.device_ca_public),
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_pair_claim(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let body = Self::read_body(session).await?;
        let request = serde_json::from_slice::<PairClaimRequest>(&body)
            .map_err(|_| ApiError::BadRequest("invalid JSON payload".to_string()))?;
        let code = request.pair_code.trim();
        if code.is_empty() {
            return Err(ApiError::BadRequest("pair_code is required".to_string()));
        }
        let normalized_code = code.to_uppercase();
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let keys = DeviceKeyPair::from_seed(&seed).map_err(|_| ApiError::Internal)?;
        let device_id = generate_id(&format!(
            "device:{}:{}",
            normalized_code,
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let claim = self
            .state
            .storage
            .claim_pairing_token(&normalized_code, &device_id, &keys.public[..])
            .await
            .map_err(|err| match err {
                StorageError::Missing => ApiError::NotFound,
                StorageError::Invalid => {
                    ApiError::BadRequest("pairing code invalid or expired".to_string())
                }
                _ => ApiError::Internal,
            })?;
        let certificate = self
            .issue_device_certificate(&claim.user.user_id, &device_id, &keys.public)
            .map_err(|_| ApiError::Internal)?;
        let recorded_at = Utc::now();
        let event = DeviceKeyEvent {
            event_id: generate_id(&format!(
                "dke:{}:{}",
                device_id,
                recorded_at.timestamp_nanos_opt().unwrap_or_default()
            )),
            device_id: device_id.clone(),
            public_key: keys.public.to_vec(),
            recorded_at,
        };
        self.state
            .storage
            .record_device_key_event(&event)
            .await
            .map_err(|_| ApiError::Internal)?;
        let ledger_entry = LedgerRecord {
            digest: keys.public,
            recorded_at,
            metadata: json!({
                "device": device_id,
                "user": claim.user.user_id,
                "action": "certificate",
                "source": "pair-claim",
                "certificate_serial": certificate.data.serial,
                "certificate_issued_at": certificate.data.issued_at,
                "certificate_expires_at": certificate.data.expires_at,
            }),
        };
        if let Err(err) = self.state.ledger.submit(&ledger_entry) {
            warn!("ledger submission failed: {}", err);
        }
        let mut response = json!({
            "device_id": device_id,
            "private_key": encode_hex(&keys.private[..]),
            "public_key": encode_hex(&keys.public[..]),
            "seed": encode_hex(&seed[..]),
            "issuer_device_id": claim.issuer_device_id.clone(),
            "user_id": claim.user.user_id.clone(),
            "user": user_snapshot(&claim.user),
        });
        if let Some(obj) = response.as_object_mut() {
            obj.insert(
                "device_certificate".to_string(),
                serde_json::to_value(&certificate).map_err(|_| ApiError::Internal)?,
            );
            obj.insert(
                "device_ca_public".to_string(),
                json!(encode_hex(&self.state.device_ca_public)),
            );
        }
        if let Some(name) = request.device_name
            && let Some(obj) = response.as_object_mut()
        {
            obj.insert("device_name".to_string(), json!(name));
        }
        self.respond_json(session, 200, response, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_devices_list(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;
        let devices = self
            .state
            .storage
            .list_devices_for_user(&context.user.user_id)
            .await
            .map_err(|_| ApiError::Internal)?;
        let entries = devices
            .into_iter()
            .map(|device| {
                json!({
                    "device_id": device.device_id,
                    "status": device.status,
                    "created_at": device.created_at.to_rfc3339(),
                    "public_key": encode_hex(device.public_key.as_slice()),
                    "current": device.device_id == context.device.device_id,
                })
            })
            .collect::<Vec<_>>();
        let payload = json!({
            "devices": entries,
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_device_csr(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        if !self.state.config.device_rotation.enabled {
            return Err(ApiError::NotFound);
        }
        let context = self.authenticate_session(session).await?;
        let body = Self::read_body(session).await?;
        if body.is_empty() {
            return Err(ApiError::BadRequest("request body required".to_string()));
        }
        let request = serde_json::from_slice::<DeviceRotationRequest>(&body)
            .map_err(|_| ApiError::BadRequest("invalid JSON payload".to_string()))?;
        let now = Utc::now();
        let decoded = match request.decode(now, self.state.config.device_rotation.proof_ttl) {
            Ok(decoded) => decoded,
            Err(error) => {
                let message = match error {
                    RotationRequestError::InvalidPublicKey => "invalid public_key",
                    RotationRequestError::InvalidSignature => "invalid signature encoding",
                    RotationRequestError::InvalidExpiresAt => "invalid expires_at",
                    RotationRequestError::Expired => "proof expired",
                    RotationRequestError::ExpiresTooFar => "expires_at exceeds proof_ttl",
                    RotationRequestError::InvalidNonce => "invalid nonce",
                };
                return Err(ApiError::BadRequest(message.to_string()));
            }
        };
        let DecodedRotationRequest {
            public_key: new_key_array,
            signature: signature_bytes,
            expires_at: proof_expires_at,
            nonce,
        } = decoded;
        if context.device.public_key.len() != 32 {
            return Err(ApiError::Internal);
        }
        if new_key_array.as_slice() == context.device.public_key.as_slice() {
            return Err(ApiError::Conflict("public key unchanged".to_string()));
        }
        if self.state.config.device_rotation.min_interval > StdDuration::ZERO {
            let threshold =
                chrono::Duration::from_std(self.state.config.device_rotation.min_interval)
                    .map_err(|_| ApiError::Internal)?;
            if let Some(latest) = self
                .state
                .storage
                .latest_device_key_event(&context.device.device_id)
                .await
                .map_err(|_| ApiError::Internal)?
                && now - latest.recorded_at < threshold
            {
                return Err(ApiError::Conflict(
                    "rotation interval not elapsed".to_string(),
                ));
            }
        }
        let mut current_key = [0u8; 32];
        current_key.copy_from_slice(&context.device.public_key);
        let verifying = VerifyingKey::from_bytes(&current_key).map_err(|_| ApiError::Internal)?;
        let signature = Ed25519Signature::from_bytes(&signature_bytes);
        let proof_message = rotation_proof_message(
            &context.device.device_id,
            &new_key_array,
            proof_expires_at,
            nonce.as_deref(),
        );
        verifying
            .verify(proof_message.as_bytes(), &signature)
            .map_err(|_| ApiError::BadRequest("signature verification failed".to_string()))?;
        let rotation_id = generate_id(&format!(
            "rot:{}:{}",
            &context.device.device_id,
            now.timestamp_nanos_opt().unwrap_or_default()
        ));
        let event_id = generate_id(&format!(
            "dke:{}:{}",
            &context.device.device_id,
            now.timestamp_nanos_opt().unwrap_or_default()
        ));
        let old_key = context.device.public_key.clone();
        let new_key_vec = new_key_array.to_vec();
        let rotation_record = DeviceRotationRecord {
            rotation_id: &rotation_id,
            device_id: &context.device.device_id,
            user_id: &context.user.user_id,
            old_public_key: old_key.as_slice(),
            new_public_key: new_key_vec.as_slice(),
            signature: signature_bytes.as_slice(),
            nonce: nonce.as_deref(),
            proof_expires_at,
            applied_at: now,
            event_id: &event_id,
        };
        self.state
            .storage
            .apply_device_key_rotation(&rotation_record)
            .await
            .map_err(|err| match err {
                StorageError::Missing => ApiError::Conflict("device not found".to_string()),
                _ => ApiError::Internal,
            })?;
        let certificate = self
            .issue_device_certificate(
                &context.user.user_id,
                &context.device.device_id,
                &new_key_array,
            )
            .map_err(|_| ApiError::Internal)?;
        let certificate_value =
            serde_json::to_value(&certificate).map_err(|_| ApiError::Internal)?;
        let ledger_entry = LedgerRecord {
            digest: new_key_array,
            recorded_at: now,
            metadata: json!({
                "device": context.device.device_id,
                "user": context.user.user_id,
                "action": "rotate",
                "source": "device-csr",
                "rotation_id": rotation_id,
                "event_id": event_id,
                "certificate_serial": certificate.data.serial,
                "certificate_issued_at": certificate.data.issued_at,
                "certificate_expires_at": certificate.data.expires_at,
            }),
        };
        if let Err(err) = self.state.ledger.submit(&ledger_entry) {
            warn!("ledger submission failed: {}", err);
        }
        self.state.metrics.mark_device_rotation();
        let new_key_hex = encode_hex(&new_key_vec);
        let old_key_hex = encode_hex(&old_key);
        let notification = RotationNotification {
            r#type: "device-key-rotated",
            device_id: &context.device.device_id,
            user_id: &context.user.user_id,
            public_key: &new_key_hex,
            old_public_key: &old_key_hex,
            rotation_id: &rotation_id,
            event_id: &event_id,
            certificate: &certificate_value,
            issued_at: certificate.data.issued_at,
            expires_at: certificate.data.expires_at,
        };
        if let Ok(notification_value) = serde_json::to_value(&notification) {
            self.notify_device_key_rotation(&context.device.device_id, notification_value)
                .await;
        }
        let response = json!({
            "device_id": context.device.device_id,
            "user_id": context.user.user_id,
            "public_key": new_key_hex,
            "old_public_key": old_key_hex,
            "rotation_id": rotation_id,
            "event_id": event_id,
            "applied_at": now.to_rfc3339(),
            "proof_expires_at": proof_expires_at.to_rfc3339(),
            "certificate": certificate_value,
        });
        self.respond_json(session, 200, response, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn handle_device_revoke(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ApiError> {
        let context = self.authenticate_session(session).await?;
        let body = Self::read_body(session).await?;
        let request = serde_json::from_slice::<DeviceRevokeRequest>(&body)
            .map_err(|_| ApiError::BadRequest("invalid JSON payload".to_string()))?;
        let target = request.device_id.trim();
        if target.is_empty() {
            return Err(ApiError::BadRequest("device_id is required".to_string()));
        }
        if target == context.device.device_id {
            return Err(ApiError::Conflict(
                "cannot revoke active session device".to_string(),
            ));
        }
        let target_record =
            self.state
                .storage
                .load_device(target)
                .await
                .map_err(|err| match err {
                    StorageError::Missing => ApiError::NotFound,
                    _ => ApiError::Internal,
                })?;
        if target_record.user_id != context.user.user_id {
            return Err(ApiError::Forbidden);
        }
        self.state
            .storage
            .deactivate_device(target)
            .await
            .map_err(|err| match err {
                StorageError::Missing => ApiError::NotFound,
                _ => ApiError::Internal,
            })?;
        self.cleanup_connection(target).await;
        let payload = json!({
            "device_id": target,
            "status": "revoked",
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
    }

    async fn authenticate_session(
        &self,
        session: &ServerSession,
    ) -> Result<SessionContext, ApiError> {
        let header = session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                debug!("authentication failed: missing authorization header");
                ApiError::Unauthorized(Some("missing Authorization header".to_string()))
            })?;
        let token = header
            .trim()
            .strip_prefix("Bearer ")
            .unwrap_or(header.trim());
        if token.is_empty() {
            debug!("authentication failed: empty token");
            return Err(ApiError::Unauthorized(Some(
                "empty token provided".to_string(),
            )));
        }
        let session_record =
            self.state
                .storage
                .load_session(token)
                .await
                .map_err(|err| match err {
                    StorageError::Missing => {
                        debug!("authentication failed: session not found");
                        ApiError::Unauthorized(Some("session not found or expired".to_string()))
                    }
                    _ => {
                        error!("authentication failed: storage error loading session");
                        ApiError::Internal
                    }
                })?;
        let expiry = session_record.created_at + Duration::seconds(session_record.ttl_seconds);
        if expiry <= Utc::now() {
            debug!(
                session_id = %session_record.session_id,
                "authentication failed: session expired"
            );
            return Err(ApiError::Unauthorized(Some(
                "session expired, please reconnect".to_string(),
            )));
        }
        let device = self
            .state
            .storage
            .load_device(&session_record.device_id)
            .await
            .map_err(|err| match err {
                StorageError::Missing => {
                    debug!(
                        device_id = %session_record.device_id,
                        "authentication failed: device not found"
                    );
                    ApiError::Unauthorized(Some("device not found".to_string()))
                }
                _ => {
                    error!("authentication failed: storage error loading device");
                    ApiError::Internal
                }
            })?;
        if device.status != "active" {
            debug!(
                device_id = %device.device_id,
                status = %device.status,
                "authentication failed: device not active"
            );
            return Err(ApiError::Forbidden);
        }
        let user = self
            .state
            .storage
            .load_user(&session_record.user_id)
            .await
            .map_err(|err| match err {
                StorageError::Missing => {
                    debug!(
                        user_id = %session_record.user_id,
                        "authentication failed: user not found"
                    );
                    ApiError::Unauthorized(Some("user not found".to_string()))
                }
                _ => {
                    error!("authentication failed: storage error loading user");
                    ApiError::Internal
                }
            })?;
        Ok(SessionContext { user, device })
    }

    async fn respond_json(
        &self,
        session: &mut ServerSession,
        status: u16,
        payload: serde_json::Value,
        content_type: &str,
    ) -> Result<(), ServerError> {
        let mut response =
            ResponseHeader::build_no_case(status, None).map_err(|_| ServerError::Invalid)?;
        response
            .append_header("content-type", content_type)
            .map_err(|_| ServerError::Invalid)?;
        response
            .append_header("cache-control", "no-store")
            .map_err(|_| ServerError::Invalid)?;
        session
            .write_response_header(Box::new(response))
            .await
            .map_err(|_| ServerError::Io)?;
        session
            .write_response_body(payload.to_string().into_bytes().into(), true)
            .await
            .map_err(|_| ServerError::Io)?;
        self.state.metrics.mark_egress();
        Ok(())
    }

    async fn respond_api_error(
        &self,
        session: &mut ServerSession,
        error: ApiError,
    ) -> Result<(), ServerError> {
        let status = error.status();
        let title = error.title();
        let detail = match &error {
            ApiError::Unauthorized(reason) => {
                Some(reason.as_deref().unwrap_or("authorization required"))
            }
            ApiError::Forbidden => Some("access denied"),
            ApiError::NotFound => Some("resource not found"),
            ApiError::Internal => Some("internal server error"),
            ApiError::BadRequest(reason) => Some(reason.as_str()),
            ApiError::Conflict(reason) => Some(reason.as_str()),
        };
        let mut body = json!({
            "type": "about:blank",
            "title": title,
            "status": status,
        });
        if let Some(message) = detail
            && let Some(obj) = body.as_object_mut()
        {
            obj.insert("detail".to_string(), json!(message));
        }
        self.respond_json(session, status, body, "application/problem+json")
            .await
    }

    async fn respond_problem(
        &self,
        session: &mut ServerSession,
        status: u16,
        title: &str,
        detail: Option<&str>,
    ) -> Result<(), ServerError> {
        let mut body = json!({
            "type": "about:blank",
            "title": title,
            "status": status,
        });
        if let Some(message) = detail
            && let Some(obj) = body.as_object_mut()
        {
            obj.insert("detail".to_string(), json!(message));
        }
        self.respond_json(session, status, body, "application/problem+json")
            .await
    }

    async fn notify_device_key_rotation(&self, device_id: &str, payload: Value) {
        let (sender, sequence) = {
            let connections = self.state.connections.read().await;
            match connections.get(device_id) {
                Some(entry) => (entry.sender.clone(), entry.next_sequence()),
                None => return,
            }
        };
        let frame = Frame {
            channel_id: self.state.config.device_rotation.notify_channel,
            sequence,
            frame_type: FrameType::KeyUpdate,
            payload: FramePayload::Control(ControlEnvelope {
                properties: payload,
            }),
        };
        if sender.send(frame).await.is_err() {
            warn!(
                device = device_id,
                "failed to deliver key rotation notification"
            );
        }
    }

    async fn collect_friend_device_snapshots(
        &self,
        friend_ids: &[String],
    ) -> Result<HashMap<String, Vec<FriendDeviceSnapshot>>, ServerError> {
        let mut map = HashMap::new();
        for friend_id in friend_ids {
            let devices = self.state.storage.list_devices_for_user(friend_id).await?;
            let mut snapshots = Vec::with_capacity(devices.len());
            for device in devices {
                let rotation = self
                    .state
                    .storage
                    .latest_device_key_event(&device.device_id)
                    .await?;
                let last_rotated_at = rotation.map(|event| event.recorded_at.to_rfc3339());
                let DeviceRecord {
                    device_id,
                    user_id: _,
                    public_key,
                    status,
                    created_at,
                } = device;
                snapshots.push(FriendDeviceSnapshot {
                    device_id,
                    public_key: encode_hex(&public_key),
                    status,
                    created_at: created_at.to_rfc3339(),
                    last_rotated_at,
                });
            }
            map.insert(friend_id.clone(), snapshots);
        }
        Ok(map)
    }

    fn build_friend_devices_value(
        &self,
        friends: &[FriendEntryPayload],
        snapshots: HashMap<String, Vec<FriendDeviceSnapshot>>,
    ) -> Result<serde_json::Value, serde_json::Error> {
        let mut map_value = serde_json::Map::new();
        for entry in friends {
            let devices = snapshots
                .get(&entry.user_id)
                .cloned()
                .unwrap_or_else(Vec::new);
            map_value.insert(entry.user_id.clone(), serde_json::to_value(devices)?);
        }
        Ok(serde_json::Value::Object(map_value))
    }

    async fn handle_federation_event(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ServerError> {
        let body = match Self::read_body(session).await {
            Ok(bytes) => bytes,
            Err(_) => {
                self.state.metrics.mark_federation_inbound_rejected();
                return self
                    .respond_problem(
                        session,
                        500,
                        "ReadFailure",
                        Some("failed to read request body"),
                    )
                    .await;
            }
        };
        if body.is_empty() {
            self.state.metrics.mark_federation_inbound_rejected();
            return self
                .respond_problem(
                    session,
                    400,
                    "InvalidRequest",
                    Some("request body required"),
                )
                .await;
        }
        let signed = match serde_json::from_slice::<SignedEvent>(&body) {
            Ok(event) => event,
            Err(_) => {
                self.state.metrics.mark_federation_inbound_rejected();
                return self
                    .respond_problem(session, 400, "InvalidRequest", Some("invalid JSON payload"))
                    .await;
            }
        };
        let origin = signed.event.origin.to_ascii_lowercase();
        let peer = match self.fetch_peer_config(&origin).await {
            Some(peer) => peer,
            None => {
                self.state.metrics.mark_federation_inbound_rejected();
                return self
                    .respond_problem(session, 403, "UnknownPeer", Some("origin not allowed"))
                    .await;
            }
        };
        let verifier = EventVerifier {
            public: peer.public_key,
        };
        if verify_event(&signed, &verifier).is_err() {
            self.state.metrics.mark_federation_inbound_rejected();
            return self
                .respond_problem(
                    session,
                    403,
                    "InvalidSignature",
                    Some("signature verification failed"),
                )
                .await;
        }
        let idempotency = IdempotencyKey {
            key: format!("federation:{}:{}", origin, signed.event.event_id),
            scope: "federation-inbox".to_string(),
            created_at: Utc::now(),
        };
        if !self.state.storage.store_idempotency(&idempotency).await? {
            let payload = json!({
                "status": "duplicate",
            });
            return self
                .respond_json(session, 200, payload, "application/json")
                .await;
        }
        let relay_payload =
            match serde_json::from_value::<FederationRelayPayload>(signed.event.payload.clone()) {
                Ok(value) => value,
                Err(_) => {
                    self.state.metrics.mark_federation_inbound_rejected();
                    return self
                        .respond_problem(
                            session,
                            400,
                            "InvalidPayload",
                            Some("unsupported federation payload"),
                        )
                        .await;
                }
            };
        let (device_id, domain) = match relay_payload.target.split_once('@') {
            Some((dev, dom)) => (dev.trim(), Some(dom.trim())),
            None => (relay_payload.target.trim(), None),
        };
        if let Some(domain) = domain
            && domain != self.state.config.domain
        {
            self.state.metrics.mark_federation_inbound_rejected();
            return self
                .respond_problem(
                    session,
                    400,
                    "InvalidTarget",
                    Some("target domain mismatch"),
                )
                .await;
        }
        if device_id.is_empty() {
            self.state.metrics.mark_federation_inbound_rejected();
            return self
                .respond_problem(session, 400, "InvalidTarget", Some("missing target device"))
                .await;
        }
        match self.state.storage.load_device(device_id).await {
            Ok(_) => {}
            Err(StorageError::Missing) => {
                self.state.metrics.mark_federation_inbound_rejected();
                return self
                    .respond_problem(session, 404, "UnknownDevice", Some("device not found"))
                    .await;
            }
            Err(err) => return Err(err.into()),
        }
        let payload_bytes = match decode_hex(&relay_payload.payload) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.state.metrics.mark_federation_inbound_rejected();
                return self
                    .respond_problem(
                        session,
                        400,
                        "InvalidPayload",
                        Some("payload hex decode failed"),
                    )
                    .await;
            }
        };
        let (frame, _) = match Frame::decode(&payload_bytes) {
            Ok(pair) => pair,
            Err(err) => {
                self.state.metrics.mark_federation_inbound_rejected();
                return self
                    .respond_problem(
                        session,
                        400,
                        "InvalidFrame",
                        Some(&format!("frame decode failed: {err}")),
                    )
                    .await;
            }
        };
        if let Err(err) = self.deliver_federation_frame(device_id, frame).await {
            self.state.metrics.mark_federation_inbound_rejected();
            return self
                .respond_problem(session, 500, "DeliveryFailed", Some(&format!("{}", err)))
                .await;
        }
        self.state.metrics.mark_federation_inbound_processed();
        let response = json!({
            "status": "accepted",
        });
        self.respond_json(session, 202, response, "application/json")
            .await
    }

    async fn deliver_federation_frame(
        &self,
        device_id: &str,
        mut frame: Frame,
    ) -> Result<(), ServerError> {
        let now = Utc::now();
        if let Some((sender, sequence)) = {
            let connections = self.state.connections.read().await;
            connections
                .get(device_id)
                .map(|entry| (entry.sender.clone(), entry.next_sequence()))
        } {
            frame.sequence = sequence;
            if sender.send(frame).await.is_err() {
                warn!(
                    device = device_id,
                    "failed to deliver federation frame to online target"
                );
            }
            return Ok(());
        }
        let encoded = frame.encode()?;
        let inbox_key = format!("inbox:{}", device_id);
        let envelope = RelayEnvelope {
            envelope_id: generate_id(&format!(
                "federation:{}:{}",
                device_id,
                now.timestamp_nanos_opt().unwrap_or_default()
            )),
            channel_id: inbox_key.clone(),
            payload: encoded,
            deliver_after: now,
            expires_at: now + Duration::seconds(self.state.relay_ttl),
        };
        self.state.storage.enqueue_relay(&envelope).await?;
        let offset = InboxOffset {
            entity_id: device_id.to_string(),
            channel_id: inbox_key,
            last_envelope_id: Some(envelope.envelope_id.clone()),
            updated_at: now,
        };
        self.state.storage.store_inbox_offset(&offset).await?;
        self.state.metrics.mark_relay();
        Ok(())
    }

    async fn ensure_pairing_limit(&self, user_id: &str) -> Result<(), ServerError> {
        if !self.state.config.auto_approve_devices {
            return Err(ServerError::PairingRequired);
        }
        let limit = self.state.config.max_auto_devices_per_user;
        if limit <= 0 {
            return Ok(());
        }
        let count = self.state.storage.count_active_devices(user_id).await?;
        if count >= limit {
            return Err(ServerError::PairingRequired);
        }
        Ok(())
    }

    async fn fetch_peer_config(&self, domain: &str) -> Option<PeerConfig> {
        let normalized = domain.to_ascii_lowercase();
        if let Some(peer) = self.state.allowed_peers.get(&normalized) {
            return Some(peer.clone());
        }
        if let Some(peer) = self
            .state
            .dynamic_peers
            .read()
            .await
            .get(&normalized)
            .cloned()
        {
            return Some(peer);
        }
        match self.state.storage.load_federation_peer(&normalized).await {
            Ok(record)
                if matches!(
                    record.status,
                    FederationPeerStatus::Active | FederationPeerStatus::Pending
                ) =>
            {
                let peer = PeerConfig {
                    domain: record.domain.clone(),
                    endpoint: record.endpoint.clone(),
                    public_key: record.public_key,
                };
                {
                    let mut peers = self.state.dynamic_peers.write().await;
                    peers.insert(normalized.clone(), peer.clone());
                }
                if matches!(record.status, FederationPeerStatus::Pending) {
                    let _ = self
                        .state
                        .storage
                        .set_federation_peer_status(&record.domain, FederationPeerStatus::Active)
                        .await;
                }
                Some(peer)
            }
            _ => None,
        }
    }

    fn issue_device_certificate(
        &self,
        user_id: &str,
        device_id: &str,
        public_key: &[u8; 32],
    ) -> Result<DeviceCertificate, ServerError> {
        let mut rng = OsRng;
        let serial = rng.next_u64();
        let issued_at = Utc::now().timestamp();
        let expires_at = issued_at + DEVICE_CERT_VALIDITY_SECS;
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let data = DeviceCertificateData::new(
            serial,
            user_id,
            device_id,
            key,
            self.state.device_ca_public,
            issued_at,
            expires_at,
        );
        Ok(self.state.federation_signer.sign_certificate(&data))
    }

    async fn read_body(session: &mut ServerSession) -> Result<Vec<u8>, ApiError> {
        let mut body = Vec::new();
        loop {
            match session.read_request_body().await {
                Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(_) => return Err(ApiError::Internal),
            }
        }
        Ok(body)
    }

    async fn authorize_admin(&self, session: &ServerSession) -> bool {
        if !self.state.secrets.admin_token_required().await {
            return true;
        }
        let header = session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok());
        let bearer = match header {
            Some(value) => value.trim(),
            None => return false,
        };
        let token = bearer.strip_prefix("Bearer ").unwrap_or(bearer).trim();
        if token.is_empty() {
            return false;
        }
        let candidate = token.to_string();
        self.state.secrets.verify_admin_token(&candidate).await
    }

    fn client_identity(session: &ServerSession) -> String {
        session
            .client_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    async fn check_rate_limit(
        &self,
        session: &ServerSession,
        scope: RateScope,
    ) -> Option<StdDuration> {
        let identity = Self::client_identity(session);
        let decision = self.state.rate_limits.check(scope, &identity).await;
        if decision.allowed {
            None
        } else {
            Some(
                decision
                    .retry_after
                    .unwrap_or_else(|| StdDuration::from_secs(1)),
            )
        }
    }

    async fn respond_rate_limited(
        &self,
        mut session: ServerSession,
        retry_after: StdDuration,
    ) -> Result<(), ServerError> {
        let mut response =
            ResponseHeader::build_no_case(429, None).map_err(|_| ServerError::Invalid)?;
        response
            .append_header("content-type", "application/problem+json")
            .map_err(|_| ServerError::Invalid)?;
        let retry_secs = retry_after.as_secs().max(1);
        response
            .append_header("retry-after", retry_secs.to_string())
            .map_err(|_| ServerError::Invalid)?;
        session
            .write_response_header(Box::new(response))
            .await
            .map_err(|_| ServerError::Io)?;
        let body = json!({
            "type": "about:blank",
            "title": "Too Many Requests",
            "status": 429,
        })
        .to_string();
        session
            .write_response_body(body.into_bytes().into(), true)
            .await
            .map_err(|_| ServerError::Io)?;
        session.finish().await.map_err(|_| ServerError::Io)?;
        self.state.metrics.mark_egress();
        Ok(())
    }

    async fn process_connect(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
        if let Some(retry_after) = self.check_rate_limit(&session, RateScope::Connect).await {
            self.state.metrics.mark_connect_rate_limited();
            if let Err(err) = self.respond_rate_limited(session, retry_after).await {
                error!("connect rate limit response failed: {}", err);
            }
            return None;
        }
        let remote_addr = session.client_addr().map(|addr| addr.to_string());
        let mut response = ResponseHeader::build_no_case(200, None).ok()?;
        response
            .append_header("content-type", "application/octet-stream")
            .ok()?;
        response.append_header("cache-control", "no-store").ok()?;
        session
            .write_response_header(Box::new(response))
            .await
            .ok()?;

        let mut buffer = Vec::new();
        let mut handshake = HandshakeContext {
            stage: HandshakeStage::Hello,
            device_id: String::new(),
            device_public: [0u8; 32],
            session_id: String::new(),
            user_id: String::new(),
            user_profile: None,
            handshake: None,
            protocol_version: PROTOCOL_VERSION,
            certificate: None,
            noise_key: None,
            transport: None,
        };
        let mut server_sequence = 1u64;
        let mut shutdown_rx = shutdown.clone();

        while !matches!(handshake.stage, HandshakeStage::Established) {
            match session.read_request_body().await {
                Ok(Some(chunk)) => buffer.extend_from_slice(&chunk),
                Ok(None) => {
                    return None;
                }
                Err(err) => {
                    error!("handshake read failed: {}", err);
                    return None;
                }
            }
            loop {
                let decoded = commucat_proto::Frame::decode(&buffer);
                match decoded {
                    Ok((frame, consumed)) => {
                        buffer.drain(0..consumed);
                        if let Err(err) = self
                            .process_handshake_frame(
                                &mut session,
                                &mut handshake,
                                frame,
                                &mut server_sequence,
                            )
                            .await
                        {
                            let mut properties = json!({
                                "error": "handshake",
                                "detail": err.to_string(),
                            });
                            if matches!(err, ServerError::PairingRequired)
                                && let Some(obj) = properties.as_object_mut()
                            {
                                obj.insert("title".to_string(), json!("PairingRequired"));
                                obj.insert("pairing_required".to_string(), json!(true));
                            }
                            let error_frame = Frame {
                                channel_id: 0,
                                sequence: server_sequence,
                                frame_type: FrameType::Error,
                                payload: FramePayload::Control(ControlEnvelope { properties }),
                            };
                            let _ = self.write_frame(&mut session, error_frame, None).await;
                            session.finish().await.ok()?;
                            return None;
                        }
                        if matches!(handshake.stage, HandshakeStage::Established) {
                            break;
                        }
                    }
                    Err(commucat_proto::CodecError::UnexpectedEof) => break,
                    Err(err) => {
                        error!("handshake decode failure: {}", err);
                        let error_frame = Frame {
                            channel_id: 0,
                            sequence: server_sequence,
                            frame_type: FrameType::Error,
                            payload: FramePayload::Control(ControlEnvelope {
                                properties: json!({
                                    "error": "decode",
                                }),
                            }),
                        };
                        let _ = self.write_frame(&mut session, error_frame, None).await;
                        session.finish().await.ok()?;
                        return None;
                    }
                }
            }
        }

        let device_id = handshake.device_id.clone();
        let session_id = handshake.session_id.clone();
        let user_id = handshake.user_id.clone();
        let user_profile = match handshake.user_profile.clone() {
            Some(profile) => profile,
            None => match self.state.storage.load_user(&user_id).await {
                Ok(profile) => profile,
                Err(err) => {
                    error!("user profile load failed: {}", err);
                    return None;
                }
            },
        };

        if let Some(addr) = remote_addr.clone() {
            let mut peers = self.state.peer_sessions.write().await;
            peers.insert(
                device_id.clone(),
                PeerPresence {
                    address: Some(addr),
                    last_seen: Utc::now(),
                },
            );
        }

        let (tx_out, mut rx_out) = mpsc::channel::<Frame>(128);
        {
            let mut connections = self.state.connections.write().await;
            connections.insert(
                device_id.clone(),
                ConnectionEntry::new(tx_out.clone(), session_id.clone(), user_id.clone()),
            );
        }

        self.state.metrics.incr_connections();
        let presence = PresenceSnapshot {
            entity: device_id.clone(),
            state: "online".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.state.presence_ttl),
            user_id: Some(user_id.clone()),
            handle: Some(user_profile.handle.clone()),
            display_name: user_profile.display_name.clone(),
            avatar_url: user_profile.avatar_url.clone(),
        };
        if let Err(err) = self.state.storage.publish_presence(&presence).await {
            warn!("presence publish failed: {}", err);
        }
        let session_record = SessionRecord {
            session_id: session_id.clone(),
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            tls_fingerprint: generate_id(&session.request_summary()),
            created_at: Utc::now(),
            ttl_seconds: self.state.config.connection_keepalive as i64,
        };
        if let Err(err) = self.state.storage.record_session(&session_record).await {
            warn!("session record failed: {}", err);
        }
        if let Err(err) = self
            .state
            .storage
            .register_route(&device_id, &session_id, self.state.presence_ttl)
            .await
        {
            warn!("route register failed: {}", err);
        }

        let pairing_required_flag = if !self.state.config.auto_approve_devices {
            true
        } else if self.state.config.max_auto_devices_per_user > 0 {
            match self
                .state
                .storage
                .count_active_devices(&user_profile.user_id)
                .await
            {
                Ok(count) => count >= self.state.config.max_auto_devices_per_user,
                Err(err) => {
                    warn!("pairing requirement probe failed: {}", err);
                    false
                }
            }
        } else {
            false
        };
        let noise_catalog = self.state.secrets.noise_catalog().await;
        let noise_keys_payload = noise_catalog
            .iter()
            .map(|key| {
                json!({
                    "version": key.version,
                    "public": encode_hex(&key.public),
                    "valid_after": key.valid_after.to_rfc3339(),
                    "rotates_at": key.rotates_at.to_rfc3339(),
                    "expires_at": key.expires_at.to_rfc3339(),
                })
            })
            .collect::<Vec<_>>();
        let current_noise_public = if let Some(noise_key) = handshake.noise_key.as_ref() {
            encode_hex(&noise_key.public)
        } else {
            encode_hex(&self.state.config.noise_public)
        };
        let mut ack_properties = json!({
            "handshake": "ok",
            "session": session_id.clone(),
            "user_id": user_profile.user_id.clone(),
            "user": user_snapshot(&user_profile),
        });
        if let Some(obj) = ack_properties.as_object_mut() {
            obj.insert("pairing_required".to_string(), json!(pairing_required_flag));
            obj.insert(
                "device_ca_public".to_string(),
                json!(encode_hex(&self.state.device_ca_public)),
            );
            obj.insert("noise_public".to_string(), json!(current_noise_public));
            if let Some(noise_key) = handshake.noise_key.as_ref() {
                obj.insert("noise_key_version".to_string(), json!(noise_key.version));
                obj.insert(
                    "noise_rotates_at".to_string(),
                    json!(noise_key.rotates_at.to_rfc3339()),
                );
                obj.insert(
                    "noise_expires_at".to_string(),
                    json!(noise_key.expires_at.to_rfc3339()),
                );
            }
            obj.insert(
                "noise_keys".to_string(),
                serde_json::Value::Array(noise_keys_payload),
            );
            if let Some(cert) = handshake.certificate.as_ref() {
                obj.insert(
                    "certificate".to_string(),
                    json!({
                        "serial": cert.data.serial,
                        "issued_at": cert.data.issued_at,
                        "expires_at": cert.data.expires_at,
                    }),
                );
                if let Ok(value) = serde_json::to_value(cert) {
                    obj.insert("device_certificate".to_string(), value);
                }
            }
        }
        let ack_frame = Frame {
            channel_id: 0,
            sequence: server_sequence,
            frame_type: FrameType::Ack,
            payload: FramePayload::Control(ControlEnvelope {
                properties: ack_properties,
            }),
        };
        server_sequence += 1;
        if let Err(err) = self.write_frame(&mut session, ack_frame, None).await {
            error!("handshake ack send failed: {}", err);
            return None;
        }

        let digest = blake3_hash(session_id.as_bytes());
        let mut digest_bytes = [0u8; 32];
        digest_bytes.copy_from_slice(digest.as_bytes());
        let ledger_record = LedgerRecord {
            digest: digest_bytes,
            recorded_at: Utc::now(),
            metadata: json!({
                "device": device_id,
                "user": user_id,
                "session": session_id,
            }),
        };
        if let Err(err) = self.state.ledger.submit(&ledger_record) {
            warn!("ledger submission failed: {}", err);
        }

        if let Ok(pending) = self
            .state
            .storage
            .claim_envelopes(&format!("inbox:{}", device_id), 128)
            .await
        {
            let mut last_envelope = None;
            for item in pending {
                if let Ok((mut stored_frame, _)) = Frame::decode(&item.payload) {
                    let sequence = {
                        let connections = self.state.connections.read().await;
                        connections
                            .get(device_id.as_str())
                            .map(|entry| entry.next_sequence())
                    };
                    if let Some(seq) = sequence {
                        stored_frame.sequence = seq;
                        let _ = tx_out.send(stored_frame).await;
                        last_envelope = Some(item.envelope_id.clone());
                    }
                }
            }
            if let Some(last) = last_envelope {
                let offset = InboxOffset {
                    entity_id: device_id.clone(),
                    channel_id: format!("inbox:{}", device_id),
                    last_envelope_id: Some(last),
                    updated_at: Utc::now(),
                };
                if let Err(err) = self.state.storage.store_inbox_offset(&offset).await {
                    warn!("inbox offset persist failed: {}", err);
                }
            }
        }

        let transport = match handshake.transport.clone() {
            Some(handle) => handle,
            None => {
                error!("noise transport missing after handshake");
                return None;
            }
        };
        let mut cipher_buffer: Vec<u8> = Vec::new();

        'session_loop: loop {
            select! {
                inbound = session.read_request_body() => {
                    match inbound {
                        Ok(Some(chunk)) => {
                            if chunk.is_empty() {
                                continue;
                            }
                            cipher_buffer.extend_from_slice(chunk.as_ref());
                            let mut decrypted_any = false;
                            loop {
                                let Some((message_len, header_len)) = decode_varint_prefix(&cipher_buffer) else {
                                    break;
                                };
                                let total_len = header_len + message_len;
                                if cipher_buffer.len() < total_len {
                                    break;
                                }
                                let ciphertext = cipher_buffer[header_len..total_len].to_vec();
                                cipher_buffer.drain(0..total_len);
                                let plaintext = {
                                    let mut guard = transport.lock().await;
                                    match guard.read_message(&ciphertext) {
                                        Ok(data) => data,
                                        Err(_) => {
                                            error!("noise decrypt failed");
                                            break 'session_loop;
                                        }
                                    }
                                };
                                if !plaintext.is_empty() {
                                    buffer.extend_from_slice(&plaintext);
                                }
                                decrypted_any = true;
                            }
                            if decrypted_any {
                                match self.consume_established_frames(
                                    &mut session,
                                    &device_id,
                                    &mut buffer,
                                    &tx_out,
                                    &mut server_sequence,
                                    Some(&transport),
                                )
                                .await
                                {
                                    Ok(continue_running) => {
                                        if !continue_running {
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        error!("frame processing failure: {}", err);
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            break;
                        }
                        Err(err) => {
                            error!("read failure: {}", err);
                            break;
                        }
                    }
                }
                outbound = rx_out.recv() => {
                    match outbound {
                        Some(frame) => {
                            if let Err(err) = self.write_frame(&mut session, frame, Some(&transport)).await {
                                error!("outbound send failed: {}", err);
                                break;
                            }
                        }
                        None => {
                            break;
                        }
                    }
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() {
                        break;
                    }
                }
            }
        }

        self.cleanup_connection(&device_id).await;
        session.finish().await.ok()?;
        None
    }

    async fn process_handshake_frame(
        &self,
        session: &mut ServerSession,
        context: &mut HandshakeContext,
        frame: Frame,
        server_sequence: &mut u64,
    ) -> Result<(), ServerError> {
        match context.stage {
            HandshakeStage::Hello => {
                if frame.frame_type != FrameType::Hello {
                    return Err(ServerError::Invalid);
                }
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let negotiated_version = if let Some(list_value) =
                    envelope.properties.get("supported_versions")
                {
                    let list = list_value.as_array().ok_or_else(|| {
                        ServerError::ProtocolNegotiation(
                            "supported_versions must be an array".to_string(),
                        )
                    })?;
                    let mut versions = Vec::with_capacity(list.len());
                    for entry in list.iter() {
                        let number = entry.as_u64().ok_or_else(|| {
                            ServerError::ProtocolNegotiation(
                                "supported_versions entries must be unsigned integers".to_string(),
                            )
                        })?;
                        let version = u16::try_from(number).map_err(|_| {
                            ServerError::ProtocolNegotiation(format!(
                                "protocol version {} out of range",
                                number
                            ))
                        })?;
                        versions.push(version);
                    }
                    if versions.is_empty() {
                        return Err(ServerError::ProtocolNegotiation(
                            "supported_versions cannot be empty".to_string(),
                        ));
                    }
                    negotiate_protocol_version(&versions).ok_or_else(|| {
                        ServerError::ProtocolNegotiation(format!(
                            "no common protocol version; peer={:?}; supported={:?}",
                            versions, SUPPORTED_PROTOCOL_VERSIONS
                        ))
                    })?
                } else if let Some(version_value) = envelope.properties.get("protocol_version") {
                    let number = version_value.as_u64().ok_or_else(|| {
                        ServerError::ProtocolNegotiation(
                            "protocol_version must be an unsigned integer".to_string(),
                        )
                    })?;
                    let version = u16::try_from(number).map_err(|_| {
                        ServerError::ProtocolNegotiation(format!(
                            "protocol version {} out of range",
                            number
                        ))
                    })?;
                    if is_supported_protocol_version(version) {
                        version
                    } else {
                        return Err(ServerError::ProtocolNegotiation(format!(
                            "unsupported protocol version {}; supported={:?}",
                            version, SUPPORTED_PROTOCOL_VERSIONS
                        )));
                    }
                } else {
                    PROTOCOL_VERSION
                };
                context.protocol_version = negotiated_version;
                let pattern_value = envelope
                    .properties
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?;
                let pattern = match pattern_value {
                    "XK" => HandshakePattern::Xk,
                    "IK" => HandshakePattern::Ik,
                    _ => return Err(ServerError::Invalid),
                };
                let device_id = envelope
                    .properties
                    .get("device_id")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?
                    .to_string();
                let handshake_hex = envelope
                    .properties
                    .get("handshake")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?;
                let handshake_bytes =
                    decode_hex(handshake_hex).map_err(|_| ServerError::Invalid)?;
                let client_static_hex = envelope
                    .properties
                    .get("client_static")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?;
                let client_static =
                    decode_hex32(client_static_hex).map_err(|_| ServerError::Invalid)?;
                let device_public_hex = envelope
                    .properties
                    .get("device_public")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?;
                let device_public =
                    decode_hex32(device_public_hex).map_err(|_| ServerError::Invalid)?;
                let proof_value = envelope
                    .properties
                    .get("zkp")
                    .ok_or(ServerError::Invalid)?
                    .clone();
                let proof: KnowledgeProof =
                    serde_json::from_value(proof_value).map_err(|_| ServerError::Invalid)?;
                let proof_context = zkp::derive_handshake_context(
                    &self.state.config.domain,
                    &device_id,
                    &device_public,
                    &client_static,
                );
                zkp::verify_handshake(&device_public, &proof_context, &proof)
                    .map_err(|_| ServerError::Invalid)?;
                context.device_public = device_public;
                let prologue = self.state.config.prologue.clone();
                let noise_candidates = self.state.secrets.active_noise_keys().await;
                let mut selected_noise: Option<NoiseKey> = None;
                let mut handshake_state_opt: Option<NoiseHandshake> = None;
                for key in noise_candidates.iter() {
                    let noise = NoiseConfig {
                        pattern,
                        prologue: prologue.clone(),
                        local_private: key.private,
                        local_static_public: Some(key.public),
                        remote_static_public: Some(client_static),
                    };
                    if let Ok(mut candidate) = build_handshake(&noise, false)
                        && candidate.read_message(&handshake_bytes).is_ok()
                    {
                        handshake_state_opt = Some(candidate);
                        selected_noise = Some(key.clone());
                        break;
                    }
                }
                let mut handshake_state = handshake_state_opt.ok_or(ServerError::Invalid)?;
                let selected_noise = selected_noise.ok_or(ServerError::Invalid)?;
                context.noise_key = Some(selected_noise.clone());
                let user_payload = envelope.properties.get("user").and_then(|v| v.as_object());
                let user_id_hint = user_payload
                    .and_then(|map| map.get("id").or_else(|| map.get("user_id")))
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                let handle_hint = user_payload
                    .and_then(|map| map.get("handle"))
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                let display_hint = user_payload
                    .and_then(|map| map.get("display_name"))
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                let avatar_hint = user_payload
                    .and_then(|map| map.get("avatar_url"))
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());

                let certificate_value = envelope.properties.get("certificate").cloned();
                let mut certificate = match certificate_value {
                    Some(value) => Some(
                        serde_json::from_value::<DeviceCertificate>(value)
                            .map_err(|_| ServerError::Invalid)?,
                    ),
                    None => None,
                };

                let mut ledger_action: Option<&'static str> = None;
                let public_key_vec = device_public.to_vec();

                let (user_id, mut user_profile, device_was_known) =
                    match self.state.storage.load_device(&device_id).await {
                        Ok(record) => {
                            if record.status != "active" {
                                return Err(ServerError::Invalid);
                            }
                            if let Some(provided) = &user_id_hint
                                && provided != &record.user_id
                            {
                                return Err(ServerError::Invalid);
                            }
                            let profile = self.state.storage.load_user(&record.user_id).await?;
                            if let Some(handle) = &handle_hint
                                && profile.handle != *handle
                            {
                                return Err(ServerError::Invalid);
                            }
                            if record.public_key != public_key_vec {
                                let update = DeviceRecord {
                                    device_id: record.device_id.clone(),
                                    user_id: record.user_id.clone(),
                                    public_key: public_key_vec.clone(),
                                    status: record.status.clone(),
                                    created_at: record.created_at,
                                };
                                self.state.storage.upsert_device(&update).await?;
                                ledger_action = Some("rotate");
                            }
                            (record.user_id.clone(), profile, true)
                        }
                        Err(StorageError::Missing) => {
                            let (resolved_id, profile) = if let Some(cert) = certificate.as_ref() {
                                let profile =
                                    self.state.storage.load_user(&cert.data.user_id).await?;
                                (cert.data.user_id.clone(), profile)
                            } else if let Some(provided) = &user_id_hint {
                                let profile = self.state.storage.load_user(provided).await?;
                                (profile.user_id.clone(), profile)
                            } else if let Some(handle) = &handle_hint {
                                match self.state.storage.load_user_by_handle(handle).await {
                                    Ok(profile) => (profile.user_id.clone(), profile),
                                    Err(StorageError::Missing) => {
                                        let new_profile = NewUserProfile {
                                            user_id: generate_id(handle),
                                            handle: handle.clone(),
                                            display_name: display_hint.clone(),
                                            avatar_url: avatar_hint.clone(),
                                        };
                                        let profile =
                                            self.state.storage.create_user(&new_profile).await?;
                                        (profile.user_id.clone(), profile)
                                    }
                                    Err(err) => return Err(err.into()),
                                }
                            } else {
                                return Err(ServerError::Invalid);
                            };
                            self.ensure_pairing_limit(&resolved_id).await?;
                            let insert = DeviceRecord {
                                device_id: device_id.clone(),
                                user_id: resolved_id.clone(),
                                public_key: public_key_vec.clone(),
                                status: "active".to_string(),
                                created_at: Utc::now(),
                            };
                            self.state.storage.upsert_device(&insert).await?;
                            ledger_action = Some("register");
                            (resolved_id, profile, false)
                        }
                        Err(err) => return Err(err.into()),
                    };

                if let Some(existing) = certificate.clone() {
                    let mut current = existing;
                    current
                        .verify(&self.state.device_ca_public)
                        .map_err(ServerError::from)?;
                    if current.data.device_id != device_id {
                        return Err(ServerError::Invalid);
                    }
                    if current.data.user_id != user_id {
                        return Err(ServerError::Invalid);
                    }
                    if current.data.public_key != device_public {
                        if current.data.public_key == client_static {
                            current = self.issue_device_certificate(
                                &user_id,
                                &device_id,
                                &device_public,
                            )?;
                            ledger_action.get_or_insert("certificate");
                            certificate = Some(current.clone());
                        } else {
                            return Err(ServerError::Invalid);
                        }
                    }
                    if current.data.issued_at >= current.data.expires_at {
                        return Err(ServerError::Invalid);
                    }
                    let now_ts = Utc::now().timestamp();
                    if current.data.expires_at <= now_ts {
                        return Err(ServerError::Invalid);
                    }
                    if current.data.issued_at > now_ts + DEVICE_CERT_MAX_SKEW {
                        return Err(ServerError::Invalid);
                    }
                }

                if certificate.is_none() {
                    let issued =
                        self.issue_device_certificate(&user_id, &device_id, &device_public)?;
                    certificate = Some(issued);
                    if ledger_action.is_none() {
                        ledger_action = Some(if device_was_known {
                            "certificate"
                        } else {
                            "register"
                        });
                    }
                }

                let certificate = certificate.ok_or(ServerError::Invalid)?;

                let display_update = display_hint.clone();
                let avatar_update = avatar_hint.clone();
                if display_hint.is_some() || avatar_hint.is_some() {
                    self.state
                        .storage
                        .update_user_profile(
                            &user_id,
                            display_hint.as_deref(),
                            avatar_hint.as_deref(),
                        )
                        .await?;
                    if let Some(value) = display_update {
                        user_profile.display_name = Some(value);
                    }
                    if let Some(value) = avatar_update {
                        user_profile.avatar_url = Some(value);
                    }
                }

                if let Some(action) = ledger_action {
                    let recorded_at = Utc::now();
                    let event = DeviceKeyEvent {
                        event_id: generate_id(&format!(
                            "dke:{}:{}",
                            device_id,
                            recorded_at.timestamp_nanos_opt().unwrap_or_default()
                        )),
                        device_id: device_id.clone(),
                        public_key: public_key_vec.clone(),
                        recorded_at,
                    };
                    self.state.storage.record_device_key_event(&event).await?;
                    let ledger_entry = LedgerRecord {
                        digest: certificate.data.public_key,
                        recorded_at,
                        metadata: json!({
                            "device": device_id,
                            "user": user_id,
                            "action": action,
                            "source": "certificate",
                            "certificate_serial": certificate.data.serial,
                            "certificate_issued_at": certificate.data.issued_at,
                            "certificate_expires_at": certificate.data.expires_at,
                        }),
                    };
                    if let Err(err) = self.state.ledger.submit(&ledger_entry) {
                        warn!("ledger submission failed: {}", err);
                    }
                }

                context.user_id = user_id.clone();
                context.user_profile = Some(user_profile.clone());
                context.certificate = Some(certificate.clone());

                let session_id = generate_id(&device_id);
                let user_payload = user_snapshot(&user_profile);
                let payload = json!({
                    "session": session_id.clone(),
                    "domain": self.state.config.domain.clone(),
                    "protocol_version": context.protocol_version,
                    "user_id": user_profile.user_id.clone(),
                    "user": user_payload,
                })
                .to_string()
                .into_bytes();
                let response_bytes = handshake_state.write_message(&payload)?;
                let response_frame = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Auth,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: json!({
                            "session": session_id,
                            "device_id": device_id.clone(),
                            "handshake": encode_hex(&response_bytes),
                            "server_static": encode_hex(&selected_noise.public),
                            "protocol_version": context.protocol_version,
                            "supported_versions": SUPPORTED_PROTOCOL_VERSIONS,
                        }),
                    }),
                };
                *server_sequence += 1;
                self.write_frame(session, response_frame, None).await?;
                context.device_id = device_id;
                context.session_id = session_id;
                context.handshake = Some(handshake_state);
                context.stage = HandshakeStage::AwaitClient;
                Ok(())
            }
            HandshakeStage::AwaitClient => {
                if frame.frame_type != FrameType::Auth {
                    return Err(ServerError::Invalid);
                }
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let handshake_hex = envelope
                    .properties
                    .get("handshake")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?;
                let handshake_bytes =
                    decode_hex(handshake_hex).map_err(|_| ServerError::Invalid)?;
                let mut handshake_state = context.handshake.take().ok_or(ServerError::Invalid)?;
                let _ = handshake_state.read_message(&handshake_bytes)?;
                let transport = handshake_state.into_transport()?;
                context.transport = Some(Arc::new(Mutex::new(transport)));
                context.stage = HandshakeStage::Established;
                Ok(())
            }
            HandshakeStage::Established => Ok(()),
        }
    }

    async fn write_frame(
        &self,
        session: &mut ServerSession,
        frame: Frame,
        transport: Option<&Arc<Mutex<NoiseTransport>>>,
    ) -> Result<(), ServerError> {
        let encoded = frame.encode()?;
        let payload = if let Some(noise) = transport {
            let ciphertext = {
                let mut guard = noise.lock().await;
                guard
                    .write_message(&encoded)
                    .map_err(|_| ServerError::Crypto)?
            };
            let mut framed = encode_varint_usize(ciphertext.len());
            framed.extend_from_slice(&ciphertext);
            framed
        } else {
            encoded
        };
        session
            .write_response_body(payload.into(), false)
            .await
            .map_err(|_| ServerError::Io)?;
        self.state.metrics.mark_egress();
        Ok(())
    }

    fn emit_call_event(&self, call_id: &str, event: &str, extra: serde_json::Value) {
        let hash = blake3_hash(call_id.as_bytes());
        let mut digest = [0u8; 32];
        digest.copy_from_slice(hash.as_bytes());
        let metadata = json!({
            "scope": "call",
            "event": event,
            "call_id": call_id,
            "data": extra,
        });
        let record = LedgerRecord {
            digest,
            recorded_at: Utc::now(),
            metadata,
        };
        if let Err(err) = self.state.ledger.submit(&record) {
            warn!("call ledger submission failed: {}", err);
        }
    }

    fn call_mode_label(mode: CallMode) -> &'static str {
        match mode {
            CallMode::FullDuplex => "full_duplex",
            CallMode::HalfDuplex => "half_duplex",
        }
    }

    fn call_reject_reason_label(reason: CallRejectReason) -> &'static str {
        match reason {
            CallRejectReason::Busy => "busy",
            CallRejectReason::Decline => "decline",
            CallRejectReason::Unsupported => "unsupported",
            CallRejectReason::Timeout => "timeout",
            CallRejectReason::Error => "error",
        }
    }

    fn call_end_reason_label(reason: CallEndReason) -> &'static str {
        match reason {
            CallEndReason::Hangup => "hangup",
            CallEndReason::Cancel => "cancel",
            CallEndReason::Failure => "failure",
            CallEndReason::Timeout => "timeout",
        }
    }

    async fn register_call_offer(
        &self,
        device_id: &str,
        channel_id: u64,
        offer: &ProtoCallOffer,
    ) -> Result<(), ServerError> {
        if offer.call_id.is_empty() {
            return Err(ServerError::Invalid);
        }
        let participants = {
            let routes = self.state.channel_routes.read().await;
            let route = routes.get(&channel_id).ok_or(ServerError::Invalid)?;
            if !route.members.contains(device_id) {
                return Err(ServerError::Invalid);
            }
            route.members.clone()
        };
        let mut sessions = self.state.call_sessions.write().await;
        if sessions.contains_key(&offer.call_id) {
            return Err(ServerError::Invalid);
        }
        let started = Utc::now();
        let mut accepted = HashSet::new();
        accepted.insert(device_id.to_string());
        let session = CallSession {
            call_id: offer.call_id.clone(),
            channel_id,
            initiator: device_id.to_string(),
            started_at: started,
            last_update: started,
            media: offer.media.clone(),
            accepted,
            participants: participants.clone(),
            stats: HashMap::new(),
            transport: offer.transport.clone(),
            transport_updates: HashMap::new(),
        };
        sessions.insert(offer.call_id.clone(), session);
        drop(sessions);
        self.ensure_call_transcoder(&offer.call_id, &offer.media)
            .await?;
        self.state.metrics.mark_call_started();
        let participant_list: Vec<String> = participants.iter().cloned().collect();
        self.emit_call_event(
            &offer.call_id,
            "offer",
            json!({
                "channel_id": channel_id,
                "initiator": device_id,
                "participants": participant_list,
                "mode": Self::call_mode_label(offer.media.mode),
                "video": offer.media.video.is_some(),
            }),
        );
        Ok(())
    }

    async fn ensure_call_transcoder(
        &self,
        call_id: &str,
        profile: &CallMediaProfile,
    ) -> Result<(), ServerError> {
        let transcoder = CallMediaTranscoder::new(profile)?;
        let mut guard = self.state.media_transcoders.write().await;
        guard.insert(call_id.to_string(), Arc::new(Mutex::new(transcoder)));
        Ok(())
    }

    async fn update_call_transcoder(&self, call_id: &str, profile: &CallMediaProfile) {
        if let Some(handle) = self
            .state
            .media_transcoders
            .read()
            .await
            .get(call_id)
            .cloned()
        {
            let mut guard = handle.lock().await;
            if let Err(err) = guard.update_profile(profile) {
                warn!(call = %call_id, error = %err, "failed to update call media profile");
            }
        }
    }

    async fn remove_call_transcoder(&self, call_id: &str) {
        let mut guard = self.state.media_transcoders.write().await;
        guard.remove(call_id);
    }

    async fn apply_call_answer(
        &self,
        device_id: &str,
        answer: &ProtoCallAnswer,
    ) -> Result<(), ServerError> {
        let call_id = answer.call_id.clone();
        let mut sessions = self.state.call_sessions.write().await;
        let Some(session) = sessions.get_mut(&call_id) else {
            return Err(ServerError::Invalid);
        };
        if !session.participants.contains(device_id) {
            return Err(ServerError::Invalid);
        }
        session.last_update = Utc::now();
        if !answer.accept {
            sessions.remove(&call_id);
            drop(sessions);
            self.remove_call_transcoder(&call_id).await;
            self.state.metrics.mark_call_ended();
            let reason = answer.reason.map(Self::call_reject_reason_label);
            self.emit_call_event(
                &call_id,
                "answer",
                json!({
                    "device": device_id,
                    "accept": false,
                    "reason": reason,
                }),
            );
            return Ok(());
        }
        session.accepted.insert(device_id.to_string());
        if let Some(profile) = &answer.media {
            session.media = profile.clone();
        }
        if let Some(transport) = &answer.transport {
            session.transport = Some(transport.clone());
        }
        let updated_profile = session.media.clone();
        let mode = updated_profile.mode;
        let video = updated_profile.video.is_some();
        let accepted = session.accepted.len();
        drop(sessions);
        self.update_call_transcoder(&call_id, &updated_profile)
            .await;
        self.emit_call_event(
            &call_id,
            "answer",
            json!({
                "device": device_id,
                "accept": true,
                "mode": Self::call_mode_label(mode),
                "video": video,
                "accepted": accepted,
            }),
        );
        Ok(())
    }

    async fn terminate_call(&self, device_id: &str, end: &ProtoCallEnd) -> Result<(), ServerError> {
        let mut sessions = self.state.call_sessions.write().await;
        let Some(session) = sessions.get(&end.call_id) else {
            warn!(call = %end.call_id, "call termination for unknown session");
            return Ok(());
        };
        if !session.participants.contains(device_id) {
            return Err(ServerError::Invalid);
        }
        let started = session.started_at;
        let initiator = session.initiator.clone();
        sessions.remove(&end.call_id);
        drop(sessions);
        self.remove_call_transcoder(&end.call_id).await;
        self.state.metrics.mark_call_ended();
        let duration = (Utc::now() - started).num_seconds().max(0);
        self.emit_call_event(
            &end.call_id,
            "end",
            json!({
                "device": device_id,
                "initiator": initiator,
                "reason": Self::call_end_reason_label(end.reason),
                "duration_secs": duration,
            }),
        );
        Ok(())
    }

    async fn update_call_stats(
        &self,
        device_id: &str,
        stats: &ProtoCallStats,
    ) -> Result<(), ServerError> {
        let mut sessions = self.state.call_sessions.write().await;
        let Some(session) = sessions.get_mut(&stats.call_id) else {
            return Err(ServerError::Invalid);
        };
        if !session.participants.contains(device_id) {
            return Err(ServerError::Invalid);
        }
        session.last_update = Utc::now();
        session.stats.insert(device_id.to_string(), stats.clone());
        Ok(())
    }

    async fn apply_transport_update(
        &self,
        device_id: &str,
        update: &CallTransportUpdate,
    ) -> Result<(), ServerError> {
        let mut sessions = self.state.call_sessions.write().await;
        let Some(session) = sessions.get_mut(&update.call_id) else {
            return Err(ServerError::Invalid);
        };
        if !session.participants.contains(device_id) {
            return Err(ServerError::Invalid);
        }
        session.last_update = Utc::now();
        session
            .transport_updates
            .insert(device_id.to_string(), update.clone());
        match &update.payload {
            TransportUpdatePayload::Candidate { .. } => {
                self.state.metrics.mark_transport_candidate();
            }
            TransportUpdatePayload::SelectedCandidatePair { .. } => {
                self.state.metrics.mark_transport_pair_selected();
            }
            TransportUpdatePayload::ConsentKeepalive { interval_secs } => {
                if let Some(interval) = interval_secs {
                    if let Some(transport) = session.transport.as_mut() {
                        transport.consent_interval_secs = Some(*interval);
                    } else {
                        session.transport = Some(CallTransport {
                            consent_interval_secs: Some(*interval),
                            ..CallTransport::default()
                        });
                    }
                }
                self.state.metrics.mark_transport_keepalive();
            }
        }
        Ok(())
    }

    async fn call_id_by_channel(&self, channel_id: u64) -> Option<String> {
        let sessions = self.state.call_sessions.read().await;
        sessions
            .values()
            .find(|session| session.channel_id == channel_id)
            .map(|session| session.call_id.clone())
    }

    async fn process_voice_payload(
        &self,
        channel_id: u64,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, ServerError> {
        let Some(call_id) = self.call_id_by_channel(channel_id).await else {
            return Ok(payload);
        };
        let handle = {
            let guard = self.state.media_transcoders.read().await;
            guard.get(&call_id).cloned()
        };
        let Some(handle) = handle else {
            return Ok(payload);
        };
        let mut transcoder = handle.lock().await;
        match transcoder.process_audio(payload) {
            Ok(result) => Ok(result),
            Err(err) => {
                warn!(call = %call_id, channel = channel_id, error = %err, "voice transcoding failed");
                Err(ServerError::from(err))
            }
        }
    }

    async fn process_video_payload(
        &self,
        channel_id: u64,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, ServerError> {
        let Some(call_id) = self.call_id_by_channel(channel_id).await else {
            return Ok(payload);
        };
        let handle = {
            let guard = self.state.media_transcoders.read().await;
            guard.get(&call_id).cloned()
        };
        let Some(handle) = handle else {
            return Ok(payload);
        };
        let mut transcoder = handle.lock().await;
        match transcoder.process_video(payload) {
            Ok(result) => Ok(result),
            Err(err) => {
                warn!(call = %call_id, channel = channel_id, error = %err, "video transcoding failed");
                Err(ServerError::from(err))
            }
        }
    }

    async fn consume_established_frames(
        &self,
        session: &mut ServerSession,
        device_id: &str,
        buffer: &mut Vec<u8>,
        tx_out: &mpsc::Sender<Frame>,
        server_sequence: &mut u64,
        transport: Option<&Arc<Mutex<NoiseTransport>>>,
    ) -> Result<bool, ServerError> {
        loop {
            match Frame::decode(buffer) {
                Ok((frame, consumed)) => {
                    buffer.drain(0..consumed);
                    self.state.metrics.mark_ingress();
                    self.handle_established_frame(device_id, frame, tx_out, server_sequence)
                        .await?;
                }
                Err(commucat_proto::CodecError::UnexpectedEof) => return Ok(true),
                Err(err) => {
                    error!("decode failure: {}", err);
                    let error_frame = Frame {
                        channel_id: 0,
                        sequence: *server_sequence,
                        frame_type: FrameType::Error,
                        payload: FramePayload::Control(ControlEnvelope {
                            properties: json!({
                                "error": "decode",
                            }),
                        }),
                    };
                    *server_sequence += 1;
                    let _ = self.write_frame(session, error_frame, transport).await;
                    return Err(ServerError::Codec);
                }
            }
        }
    }

    async fn handle_established_frame(
        &self,
        device_id: &str,
        mut frame: Frame,
        tx_out: &mpsc::Sender<Frame>,
        server_sequence: &mut u64,
    ) -> Result<(), ServerError> {
        match frame.frame_type {
            FrameType::Join => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let relay = envelope
                    .properties
                    .get("relay")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let mut declared = HashSet::new();
                if let Some(members_value) = envelope
                    .properties
                    .get("members")
                    .and_then(|v| v.as_array())
                {
                    for entry in members_value {
                        if let Some(value) = entry.as_str() {
                            declared.insert(value.to_string());
                        }
                    }
                }
                let group_id = envelope
                    .properties
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                let mut members = if let Some(ref gid) = group_id {
                    let persisted = self.state.storage.list_group_members(gid).await?;
                    let mut set = HashSet::new();
                    for member in persisted {
                        set.insert(member.device_id);
                    }
                    if !set.contains(device_id) {
                        return Err(ServerError::Invalid);
                    }
                    set
                } else {
                    declared
                };
                members.insert(device_id.to_string());
                {
                    let mut routes = self.state.channel_routes.write().await;
                    routes.insert(
                        frame.channel_id,
                        ChannelRoute {
                            members: members.clone(),
                            relay,
                            group_id: group_id.clone(),
                        },
                    );
                }
                let candidates = if relay {
                    Vec::new()
                } else {
                    let now = Utc::now();
                    let peers = self.state.peer_sessions.read().await;
                    members
                        .iter()
                        .filter_map(|member| {
                            peers.get(member).and_then(|p| {
                                let addr = p.address.clone()?;
                                let elapsed = now.signed_duration_since(p.last_seen);
                                let fresh = elapsed <= Duration::seconds(self.state.presence_ttl);
                                if fresh {
                                    Some((member.clone(), addr))
                                } else {
                                    None
                                }
                            })
                        })
                        .collect::<Vec<_>>()
                };
                if candidates.len() > 1 {
                    for (member, addr) in candidates.iter() {
                        if member == device_id {
                            continue;
                        }
                        if let Some(target) = self.state.connections.read().await.get(member) {
                            let frame = Frame {
                                channel_id: frame.channel_id,
                                sequence: target.next_sequence(),
                                frame_type: FrameType::Presence,
                                payload: FramePayload::Control(ControlEnvelope {
                                    properties: json!({
                                        "channel": frame.channel_id,
                                        "peer": device_id,
                                        "candidate": addr,
                                    }),
                                }),
                            };
                            let _ = target.sender.send(frame).await;
                        }
                    }
                }
                let mut ack_payload = json!({
                    "ack": frame.sequence,
                });
                if let Some(gid) = group_id {
                    ack_payload["group_id"] = json!(gid);
                }
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: ack_payload,
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::Leave => {
                {
                    let mut routes = self.state.channel_routes.write().await;
                    routes.remove(&frame.channel_id);
                }
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: json!({
                            "ack": frame.sequence,
                        }),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::CallOffer => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let offer = ProtoCallOffer::try_from(envelope).map_err(|_| ServerError::Invalid)?;
                self.register_call_offer(device_id, frame.channel_id, &offer)
                    .await?;
                self.broadcast_frame(device_id, frame.clone()).await?;
                let mut properties = serde_json::Map::new();
                properties.insert("ack".to_string(), json!(frame.sequence));
                properties.insert("call_id".to_string(), json!(offer.call_id.clone()));
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: serde_json::Value::Object(properties),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::CallAnswer => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let answer =
                    ProtoCallAnswer::try_from(envelope).map_err(|_| ServerError::Invalid)?;
                self.apply_call_answer(device_id, &answer).await?;
                self.broadcast_frame(device_id, frame.clone()).await?;
                let mut properties = serde_json::Map::new();
                properties.insert("ack".to_string(), json!(frame.sequence));
                properties.insert("call_id".to_string(), json!(answer.call_id.clone()));
                properties.insert("accept".to_string(), json!(answer.accept));
                if let Some(reason) = answer.reason {
                    properties.insert(
                        "reason".to_string(),
                        json!(Self::call_reject_reason_label(reason)),
                    );
                }
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: serde_json::Value::Object(properties),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::CallEnd => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let end = ProtoCallEnd::try_from(envelope).map_err(|_| ServerError::Invalid)?;
                self.terminate_call(device_id, &end).await?;
                self.broadcast_frame(device_id, frame.clone()).await?;
                let mut properties = serde_json::Map::new();
                properties.insert("ack".to_string(), json!(frame.sequence));
                properties.insert("call_id".to_string(), json!(end.call_id.clone()));
                properties.insert(
                    "reason".to_string(),
                    json!(Self::call_end_reason_label(end.reason)),
                );
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: serde_json::Value::Object(properties),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::CallStats => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let stats = ProtoCallStats::try_from(envelope).map_err(|_| ServerError::Invalid)?;
                self.update_call_stats(device_id, &stats).await?;
                self.broadcast_frame(device_id, frame.clone()).await?;
                let mut properties = serde_json::Map::new();
                properties.insert("ack".to_string(), json!(frame.sequence));
                properties.insert("call_id".to_string(), json!(stats.call_id.clone()));
                properties.insert(
                    "direction".to_string(),
                    json!(match stats.direction {
                        CallMediaDirection::Send => "send",
                        CallMediaDirection::Receive => "receive",
                    }),
                );
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: serde_json::Value::Object(properties),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::TransportUpdate => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let update =
                    CallTransportUpdate::try_from(envelope).map_err(|_| ServerError::Invalid)?;
                self.apply_transport_update(device_id, &update).await?;
                self.broadcast_frame(device_id, frame.clone()).await?;
                let update_label = match &update.payload {
                    TransportUpdatePayload::Candidate { .. } => "candidate",
                    TransportUpdatePayload::SelectedCandidatePair { .. } => {
                        "selected_candidate_pair"
                    }
                    TransportUpdatePayload::ConsentKeepalive { .. } => "consent_keepalive",
                };
                let mut properties = serde_json::Map::new();
                properties.insert("ack".to_string(), json!(frame.sequence));
                properties.insert("call_id".to_string(), json!(update.call_id.clone()));
                properties.insert("update".to_string(), json!(update_label));
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: serde_json::Value::Object(properties),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::VoiceFrame => {
                let payload = match frame.payload {
                    FramePayload::Opaque(ref mut data) => std::mem::take(data),
                    _ => return Err(ServerError::Invalid),
                };
                let processed = self
                    .process_voice_payload(frame.channel_id, payload)
                    .await?;
                frame.payload = FramePayload::Opaque(processed);
                let inbound_sequence = frame.sequence;
                self.state.metrics.mark_call_voice_frame();
                self.broadcast_frame(device_id, frame.clone()).await?;
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: json!({
                            "ack": inbound_sequence,
                        }),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::VideoFrame => {
                let payload = match frame.payload {
                    FramePayload::Opaque(ref mut data) => std::mem::take(data),
                    _ => return Err(ServerError::Invalid),
                };
                let processed = self
                    .process_video_payload(frame.channel_id, payload)
                    .await?;
                frame.payload = FramePayload::Opaque(processed);
                let inbound_sequence = frame.sequence;
                self.state.metrics.mark_call_video_frame();
                self.broadcast_frame(device_id, frame.clone()).await?;
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: json!({
                            "ack": inbound_sequence,
                        }),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::Msg | FrameType::Typing | FrameType::KeyUpdate | FrameType::GroupEvent => {
                let inbound_sequence = frame.sequence;
                self.broadcast_frame(device_id, frame.clone()).await?;
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: json!({
                            "ack": inbound_sequence,
                        }),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::Presence => {
                let envelope = match frame.payload {
                    FramePayload::Control(env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let state = envelope
                    .properties
                    .get("state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("online")
                    .to_string();
                let profile = match self.state.storage.load_device(device_id).await {
                    Ok(record) => match self.state.storage.load_user(&record.user_id).await {
                        Ok(profile) => Some(profile),
                        Err(err) => {
                            warn!("user profile load during presence update failed: {}", err);
                            None
                        }
                    },
                    Err(_) => None,
                };
                let snapshot = PresenceSnapshot {
                    entity: device_id.to_string(),
                    state,
                    expires_at: Utc::now() + Duration::seconds(self.state.presence_ttl),
                    user_id: profile.as_ref().map(|p| p.user_id.clone()),
                    handle: profile.as_ref().map(|p| p.handle.clone()),
                    display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
                    avatar_url: profile.as_ref().and_then(|p| p.avatar_url.clone()),
                };
                if let Err(err) = self.state.storage.publish_presence(&snapshot).await {
                    warn!("presence publish failed: {}", err);
                }
                let address = {
                    let peers = self.state.peer_sessions.read().await;
                    peers.get(device_id).and_then(|p| p.address.clone())
                };
                let mut peers = self.state.peer_sessions.write().await;
                peers.insert(
                    device_id.to_string(),
                    PeerPresence {
                        address,
                        last_seen: Utc::now(),
                    },
                );
                Ok(())
            }
            FrameType::GroupCreate => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let provided_group_id = envelope
                    .properties
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string());
                let group_id = provided_group_id
                    .unwrap_or_else(|| generate_id(&format!("group:{}", device_id)));
                let created_at = Utc::now();
                let relay = envelope
                    .properties
                    .get("relay")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let mut members = HashSet::new();
                members.insert(device_id.to_string());
                if let Some(array) = envelope
                    .properties
                    .get("members")
                    .and_then(|v| v.as_array())
                {
                    for entry in array {
                        if let Some(value) = entry.as_str() {
                            members.insert(value.to_string());
                        }
                    }
                }
                let roles_map = envelope
                    .properties
                    .get("roles")
                    .and_then(|v| v.as_object())
                    .cloned();
                let group = ChatGroup {
                    group_id: group_id.clone(),
                    owner_device: device_id.to_string(),
                    created_at,
                };
                self.state.storage.create_group(&group).await?;
                for member in members.iter() {
                    let role = if member == device_id {
                        GroupRole::Owner
                    } else if let Some(map) = roles_map.as_ref() {
                        map.get(member)
                            .and_then(|value| value.as_str())
                            .and_then(|name| GroupRole::from_str(name).ok())
                            .unwrap_or(GroupRole::Member)
                    } else {
                        GroupRole::Member
                    };
                    let record = GroupMember {
                        group_id: group_id.clone(),
                        device_id: member.clone(),
                        role,
                        joined_at: created_at,
                    };
                    self.state.storage.add_group_member(&record).await?;
                }
                {
                    let mut routes = self.state.channel_routes.write().await;
                    routes.insert(
                        frame.channel_id,
                        ChannelRoute {
                            members: members.clone(),
                            relay,
                            group_id: Some(group_id.clone()),
                        },
                    );
                }
                self.broadcast_frame(device_id, frame.clone()).await?;
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: json!({
                            "ack": frame.sequence,
                            "group_id": group_id,
                        }),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::GroupInvite => {
                let envelope = match frame.payload {
                    FramePayload::Control(ref env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let group_id = envelope
                    .properties
                    .get("group_id")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?
                    .to_string();
                let invitee = envelope
                    .properties
                    .get("device")
                    .and_then(|v| v.as_str())
                    .ok_or(ServerError::Invalid)?
                    .to_string();
                let requested_role = envelope
                    .properties
                    .get("role")
                    .and_then(|v| v.as_str())
                    .and_then(|value| GroupRole::from_str(value).ok())
                    .unwrap_or(GroupRole::Member);
                let role = match requested_role {
                    GroupRole::Owner => GroupRole::Admin,
                    other => other,
                };
                let members = self.state.storage.list_group_members(&group_id).await?;
                let mut inviter_role = None;
                let mut member_set = HashSet::new();
                for record in members.iter() {
                    if record.device_id == device_id {
                        inviter_role = Some(record.role.clone());
                    }
                    member_set.insert(record.device_id.clone());
                }
                let inviter_role = inviter_role.ok_or(ServerError::Invalid)?;
                if matches!(inviter_role, GroupRole::Member) {
                    return Err(ServerError::Invalid);
                }
                let now = Utc::now();
                let record = GroupMember {
                    group_id: group_id.clone(),
                    device_id: invitee.clone(),
                    role,
                    joined_at: now,
                };
                self.state.storage.add_group_member(&record).await?;
                member_set.insert(invitee.clone());
                {
                    let mut routes = self.state.channel_routes.write().await;
                    routes
                        .entry(frame.channel_id)
                        .and_modify(|route| {
                            route.members.insert(invitee.clone());
                            if route.group_id.is_none() {
                                route.group_id = Some(group_id.clone());
                            }
                        })
                        .or_insert_with(|| ChannelRoute {
                            members: member_set.clone(),
                            relay: true,
                            group_id: Some(group_id.clone()),
                        });
                }
                self.broadcast_frame(device_id, frame.clone()).await?;
                let ack = Frame {
                    channel_id: frame.channel_id,
                    sequence: *server_sequence,
                    frame_type: FrameType::Ack,
                    payload: FramePayload::Control(ControlEnvelope {
                        properties: json!({
                            "ack": frame.sequence,
                            "group_id": group_id,
                            "device": invitee,
                        }),
                    }),
                };
                *server_sequence += 1;
                let _ = tx_out.send(ack).await;
                Ok(())
            }
            FrameType::Ack => Ok(()),
            FrameType::Error => {
                warn!("client error from {}", device_id);
                Ok(())
            }
            FrameType::Hello | FrameType::Auth => Ok(()),
        }
    }

    async fn broadcast_frame(&self, sender: &str, frame: Frame) -> Result<(), ServerError> {
        let route = {
            let routes = self.state.channel_routes.read().await;
            routes.get(&frame.channel_id).cloned()
        };
        let Some(route) = route else {
            return Err(ServerError::Invalid);
        };
        if !route.members.contains(sender) {
            return Err(ServerError::Invalid);
        }
        let relay_mode = route.relay;
        let mut online_targets = Vec::new();
        let mut offline_targets = Vec::new();
        {
            let connections = self.state.connections.read().await;
            for member in route.members.iter() {
                if member == sender {
                    continue;
                }
                if let Some(entry) = connections.get(member) {
                    online_targets.push((
                        member.clone(),
                        entry.sender.clone(),
                        entry.next_sequence(),
                    ));
                } else {
                    offline_targets.push(member.clone());
                }
            }
        }
        for (member, sender_channel, sequence) in online_targets {
            let mut deliver = frame.clone();
            deliver.sequence = sequence;
            let _ = sender_channel.send(deliver).await;
            info!(target = %member, relay = relay_mode, "delivered frame");
        }
        if !offline_targets.is_empty() {
            if matches!(
                frame.frame_type,
                FrameType::VoiceFrame | FrameType::VideoFrame
            ) {
                debug!(
                    channel = frame.channel_id,
                    targets = offline_targets.len(),
                    "skipping offline relay for realtime media frame"
                );
            } else {
                let encoded = frame.encode()?;
                for target in offline_targets.iter() {
                    let now = Utc::now();
                    let inbox_key = format!("inbox:{}", target);
                    let envelope = RelayEnvelope {
                        envelope_id: generate_id(&format!(
                            "{}:{}:{}",
                            sender,
                            target,
                            now.timestamp_nanos_opt().unwrap_or_default()
                        )),
                        channel_id: inbox_key.clone(),
                        payload: encoded.clone(),
                        deliver_after: now,
                        expires_at: now + Duration::seconds(self.state.relay_ttl),
                    };
                    self.state.storage.enqueue_relay(&envelope).await?;
                    let offset = InboxOffset {
                        entity_id: target.clone(),
                        channel_id: inbox_key,
                        last_envelope_id: Some(envelope.envelope_id.clone()),
                        updated_at: now,
                    };
                    self.state.storage.store_inbox_offset(&offset).await?;
                    self.state.metrics.mark_relay();
                    if let Some(pos) = target.find('@') {
                        let domain = &target[pos + 1..];
                        if domain != self.state.config.domain {
                            let peer = self.fetch_peer_config(domain).await;
                            if let Some(peer) = peer {
                                let event = FederationEvent {
                                    event_id: generate_id(target),
                                    origin: self.state.config.domain.clone(),
                                    created_at: now,
                                    payload: json!({
                                        "channel": frame.channel_id,
                                        "sequence": frame.sequence,
                                        "payload": encode_hex(&encoded),
                                        "sender": sender,
                                        "target": target,
                                        "peer_endpoint": peer.endpoint,
                                        "peer_public_key": encode_hex(&peer.public_key),
                                    }),
                                    scope: domain.to_string(),
                                };
                                let signed = sign_event(event, &self.state.federation_signer);
                                match serde_json::to_value(&signed) {
                                    Ok(serialized) => {
                                        let outbox_id = generate_id(&format!(
                                            "federation:{}:{}",
                                            domain, signed.event.event_id
                                        ));
                                        let insert = FederationOutboxInsert {
                                            outbox_id: &outbox_id,
                                            destination: &peer.domain,
                                            endpoint: &peer.endpoint,
                                            payload: &serialized,
                                            public_key: &peer.public_key,
                                            next_attempt_at: now,
                                        };
                                        match self
                                            .state
                                            .storage
                                            .enqueue_federation_outbox(&insert)
                                            .await
                                        {
                                            Ok(()) => {
                                                self.state
                                                    .metrics
                                                    .mark_federation_outbox_enqueued();
                                                info!(
                                                    peer = %domain,
                                                    endpoint = %peer.endpoint,
                                                    event = %signed.event.event_id,
                                                    "federation event enqueued"
                                                );
                                            }
                                            Err(err) => warn!(
                                                peer = %domain,
                                                error = %err,
                                                "failed to enqueue federation event"
                                            ),
                                        }
                                    }
                                    Err(err) => warn!(
                                        peer = %domain,
                                        error = %err,
                                        "failed to serialize federation event"
                                    ),
                                }
                            } else {
                                warn!(peer = %domain, "federation peer not allowed");
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn cleanup_connection(&self, device_id: &str) {
        let mut detached_user = None;
        {
            let mut connections = self.state.connections.write().await;
            if let Some(entry) = connections.remove(device_id) {
                info!(device = device_id, session = %entry.session_id, "connection closed");
                detached_user = Some(entry.user_id);
            }
        }
        {
            let mut peers = self.state.peer_sessions.write().await;
            peers.remove(device_id);
        }
        if let Err(err) = self.state.storage.clear_route(device_id).await {
            warn!("route cleanup failed: {}", err);
        }
        let profile = if let Some(user_id) = detached_user.clone() {
            match self.state.storage.load_user(&user_id).await {
                Ok(profile) => Some(profile),
                Err(err) => {
                    warn!("user profile load during cleanup failed: {}", err);
                    None
                }
            }
        } else {
            match self.state.storage.load_device(device_id).await {
                Ok(record) => match self.state.storage.load_user(&record.user_id).await {
                    Ok(profile) => Some(profile),
                    Err(err) => {
                        warn!("user profile load during cleanup failed: {}", err);
                        None
                    }
                },
                Err(_) => None,
            }
        };
        let snapshot = PresenceSnapshot {
            entity: device_id.to_string(),
            state: "offline".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.state.presence_ttl),
            user_id: profile.as_ref().map(|p| p.user_id.clone()),
            handle: profile.as_ref().map(|p| p.handle.clone()),
            display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
            avatar_url: profile.as_ref().and_then(|p| p.avatar_url.clone()),
        };
        if let Err(err) = self.state.storage.publish_presence(&snapshot).await {
            warn!("presence cleanup failed: {}", err);
        }
        let terminated_calls = {
            let mut sessions = self.state.call_sessions.write().await;
            let affected = sessions
                .values()
                .filter(|session| session.participants.contains(device_id))
                .map(|session| {
                    (
                        session.call_id.clone(),
                        session.channel_id,
                        session.started_at,
                        session.initiator.clone(),
                    )
                })
                .collect::<Vec<_>>();
            for (call_id, _, _, _) in affected.iter() {
                sessions.remove(call_id);
            }
            affected
        };
        for (call_id, channel_id, started_at, initiator) in terminated_calls {
            self.remove_call_transcoder(&call_id).await;
            self.state.metrics.mark_call_ended();
            let duration = (Utc::now() - started_at).num_seconds().max(0);
            self.emit_call_event(
                &call_id,
                "end",
                json!({
                    "device": device_id,
                    "initiator": initiator,
                    "reason": "disconnect",
                    "duration_secs": duration,
                }),
            );
            let call_end = ProtoCallEnd {
                call_id: call_id.clone(),
                reason: CallEndReason::Failure,
                metadata: json!({
                    "system": true,
                    "cause": "disconnect",
                    "device": device_id,
                }),
            };
            match ControlEnvelope::try_from(&call_end) {
                Ok(envelope) => {
                    let frame = Frame {
                        channel_id,
                        sequence: 0,
                        frame_type: FrameType::CallEnd,
                        payload: FramePayload::Control(envelope),
                    };
                    if let Err(err) = self.broadcast_frame(device_id, frame).await {
                        warn!(call = %call_id, "failed to broadcast disconnect CallEnd: {}", err);
                    }
                }
                Err(err) => {
                    warn!(call = %call_id, "failed to encode disconnect CallEnd: {}", err);
                }
            }
        }
        self.state.metrics.decr_connections();
    }
}
