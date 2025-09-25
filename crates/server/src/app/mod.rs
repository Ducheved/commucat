use crate::config::{LedgerAdapter, PeerConfig, ServerConfig};
use crate::metrics::Metrics;
use crate::util::{decode_hex, decode_hex32, encode_hex, generate_id};
use blake3::hash as blake3_hash;
use chrono::{Duration, Utc};
use commucat_crypto::{
    build_handshake, CryptoError, DeviceKeyPair, EventSigner, HandshakePattern, NoiseConfig,
    NoiseHandshake,
};
use commucat_federation::{sign_event, FederationError, FederationEvent};
use commucat_ledger::{
    DebugLedgerAdapter, FileLedgerAdapter, LedgerAdapter as LedgerAdapterTrait, LedgerError,
    LedgerRecord, NullLedger,
};
use commucat_proto::{
    is_supported_protocol_version, negotiate_protocol_version, ControlEnvelope, Frame,
    FramePayload, FrameType, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use commucat_storage::{
    connect, ChatGroup, DeviceKeyEvent, DeviceRecord, FederationPeerStatus, GroupMember, GroupRole,
    InboxOffset, NewUserProfile, PresenceSnapshot, RelayEnvelope, SessionRecord, Storage,
    StorageError, UserProfile,
};
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream};
use pingora::http::ResponseHeader;
use pingora::protocols::http::v2::server::H2Options;
use pingora::protocols::http::ServerSession;
use pingora::server::ShutdownWatch;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use subtle::ConstantTimeEq;
use tokio::select;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{error, info, warn};

const LANDING_PAGE: &str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\" />\n<title>CommuCat</title>\n<style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0b1120;color:#f9fafb;margin:0;display:flex;align-items:center;justify-content:center;height:100vh;}main{max-width:480px;text-align:center;padding:2rem;background:rgba(15,23,42,0.85);border-radius:20px;box-shadow:0 10px 30px rgba(15,23,42,0.4);}h1{font-size:2.25rem;margin-bottom:0.5rem;}p{margin:0.75rem 0;color:#cbd5f5;}a{color:#38bdf8;text-decoration:none;}a:hover{text-decoration:underline;}</style>\n</head>\n<body>\n<main>\n<h1>CommuCat Server</h1>\n<p>Secure Noise + TLS relay for CCP-1 chats.</p>\n<p><a href=\"https://github.com/ducheved/commucat\">Project documentation</a></p>\n<p><a href=\"/healthz\">Health</a> · <a href=\"/readyz\">Readiness</a></p>\n</main>\n</body>\n</html>\n";
const FRIENDS_BLOB_KEY: &str = "friends";

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

pub struct AppState {
    pub config: ServerConfig,
    pub storage: Storage,
    pub ledger: Box<dyn LedgerAdapterTrait + Send + Sync>,
    pub metrics: Metrics,
    pub connections: RwLock<HashMap<String, ConnectionEntry>>,
    pub channel_routes: RwLock<HashMap<u64, ChannelRoute>>,
    pub peer_sessions: RwLock<HashMap<String, PeerPresence>>,
    pub allowed_peers: HashMap<String, PeerConfig>,
    pub dynamic_peers: RwLock<HashMap<String, PeerConfig>>,
    pub federation_signer: EventSigner,
    pub noise_private: [u8; 32],
    pub noise_public: [u8; 32],
    pub presence_ttl: i64,
    pub relay_ttl: i64,
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

pub struct PeerPresence {
    pub address: Option<String>,
    pub last_seen: chrono::DateTime<Utc>,
}

#[derive(Deserialize, Serialize, Clone)]
struct FriendEntryPayload {
    user_id: String,
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    alias: Option<String>,
}

#[derive(Deserialize)]
struct FriendsUpdateRequest {
    friends: Vec<FriendEntryPayload>,
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

struct SessionContext {
    user: UserProfile,
    device: DeviceRecord,
}

enum ApiError {
    Unauthorized,
    Forbidden,
    BadRequest(String),
    NotFound,
    Conflict(String),
    Internal,
}

impl ApiError {
    fn status(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::BadRequest(_) => 400,
            Self::NotFound => 404,
            Self::Conflict(_) => 409,
            Self::Internal => 500,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::BadRequest(_) => "BadRequest",
            Self::NotFound => "NotFound",
            Self::Conflict(_) => "Conflict",
            Self::Internal => "InternalError",
        }
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
    session_id: String,
    user_id: String,
    user_profile: Option<UserProfile>,
    handshake: Option<NoiseHandshake>,
    protocol_version: u16,
}

pub struct CommuCatApp {
    pub state: Arc<AppState>,
}

impl CommuCatApp {
    pub fn new(state: Arc<AppState>) -> Self {
        CommuCatApp { state }
    }

    pub async fn init(config: ServerConfig) -> Result<Arc<AppState>, ServerError> {
        let storage = connect(&config.postgres_dsn, &config.redis_url).await?;
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
        let state = Arc::new(AppState {
            storage,
            ledger,
            metrics: Metrics::new(),
            connections: RwLock::new(HashMap::new()),
            channel_routes: RwLock::new(HashMap::new()),
            peer_sessions: RwLock::new(HashMap::new()),
            allowed_peers,
            dynamic_peers: RwLock::new(dynamic_seed),
            federation_signer: signer,
            noise_private: config.noise_private,
            noise_public: config.noise_public,
            presence_ttl: config.presence_ttl_seconds,
            relay_ttl: config.relay_ttl_seconds,
            config,
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
                if !self.authorize_admin(&session) {
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
        if path == "/api/server-info" && method == "GET" {
            self.state.metrics.mark_ingress();
            if let Err(err) = self.handle_server_info(&mut session).await {
                error!("server info response failed: {}", err);
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
            self.state.metrics.mark_ingress();
            match self.handle_pair_claim(&mut session).await {
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

    async fn handle_server_info(
        self: &Arc<Self>,
        session: &mut ServerSession,
    ) -> Result<(), ServerError> {
        let payload = json!({
            "domain": self.state.config.domain,
            "noise_public": encode_hex(&self.state.noise_public),
            "supported_patterns": ["XK", "IK"],
            "supported_versions": SUPPORTED_PROTOCOL_VERSIONS,
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
            Some(data) => serde_json::from_str::<Vec<FriendEntryPayload>>(&data)
                .map_err(|_| ApiError::Internal)?,
            None => Vec::new(),
        };
        let payload = json!({ "friends": friends });
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
        let request = serde_json::from_slice::<FriendsUpdateRequest>(&body)
            .map_err(|_| ApiError::BadRequest("invalid JSON payload".to_string()))?;
        if request.friends.len() > 512 {
            return Err(ApiError::BadRequest("too many friends".to_string()));
        }
        let serialized = serde_json::to_string(&request.friends).map_err(|_| ApiError::Internal)?;
        self.state
            .storage
            .write_user_blob(&context.user.user_id, FRIENDS_BLOB_KEY, &serialized)
            .await
            .map_err(|_| ApiError::Internal)?;
        let payload = json!({
            "friends": request.friends,
        });
        self.respond_json(session, 200, payload, "application/json")
            .await
            .map_err(|_| ApiError::Internal)
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
        let mut response = json!({
            "device_id": device_id,
            "private_key": encode_hex(&keys.private[..]),
            "public_key": encode_hex(&keys.public[..]),
            "seed": encode_hex(&seed[..]),
            "issuer_device_id": claim.issuer_device_id,
            "user": {
                "id": claim.user.user_id,
                "handle": claim.user.handle,
                "display_name": claim.user.display_name,
                "avatar_url": claim.user.avatar_url,
            },
        });
        if let Some(name) = request.device_name {
            if let Some(obj) = response.as_object_mut() {
                obj.insert("device_name".to_string(), json!(name));
            }
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
            .ok_or(ApiError::Unauthorized)?;
        let token = header
            .trim()
            .strip_prefix("Bearer ")
            .unwrap_or(header.trim());
        if token.is_empty() {
            return Err(ApiError::Unauthorized);
        }
        let session_record =
            self.state
                .storage
                .load_session(token)
                .await
                .map_err(|err| match err {
                    StorageError::Missing => ApiError::Unauthorized,
                    _ => ApiError::Internal,
                })?;
        let expiry = session_record.created_at + Duration::seconds(session_record.ttl_seconds);
        if expiry <= Utc::now() {
            return Err(ApiError::Unauthorized);
        }
        let device = self
            .state
            .storage
            .load_device(&session_record.device_id)
            .await
            .map_err(|err| match err {
                StorageError::Missing => ApiError::Unauthorized,
                _ => ApiError::Internal,
            })?;
        if device.status != "active" {
            return Err(ApiError::Forbidden);
        }
        let user = self
            .state
            .storage
            .load_user(&session_record.user_id)
            .await
            .map_err(|err| match err {
                StorageError::Missing => ApiError::Unauthorized,
                _ => ApiError::Internal,
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
            ApiError::Unauthorized => Some("authorization required"),
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
        if let Some(message) = detail {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("detail".to_string(), json!(message));
            }
        }
        self.respond_json(session, status, body, "application/problem+json")
            .await
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

    fn authorize_admin(&self, session: &ServerSession) -> bool {
        match self.state.config.admin_token.as_ref() {
            None => true,
            Some(expected) => {
                let header = session
                    .req_header()
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok());
                if let Some(value) = header {
                    if let Some(token) = value.trim().strip_prefix("Bearer ") {
                        return bool::from(token.as_bytes().ct_eq(expected.as_bytes()));
                    }
                }
                false
            }
        }
    }

    async fn process_connect(
        self: &Arc<Self>,
        mut session: ServerSession,
        shutdown: &ShutdownWatch,
    ) -> Option<ReusedHttpStream> {
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
            session_id: String::new(),
            user_id: String::new(),
            user_profile: None,
            handshake: None,
            protocol_version: PROTOCOL_VERSION,
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
                            if matches!(err, ServerError::PairingRequired) {
                                if let Some(obj) = properties.as_object_mut() {
                                    obj.insert("title".to_string(), json!("PairingRequired"));
                                    obj.insert("pairing_required".to_string(), json!(true));
                                }
                            }
                            let error_frame = Frame {
                                channel_id: 0,
                                sequence: server_sequence,
                                frame_type: FrameType::Error,
                                payload: FramePayload::Control(ControlEnvelope { properties }),
                            };
                            let _ = self.write_frame(&mut session, error_frame).await;
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
                        let _ = self.write_frame(&mut session, error_frame).await;
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
        let mut ack_properties = json!({
            "handshake": "ok",
            "session": session_id,
            "user": {
                "id": user_profile.user_id.clone(),
                "handle": user_profile.handle.clone(),
                "display_name": user_profile.display_name.clone(),
                "avatar_url": user_profile.avatar_url.clone(),
            },
        });
        if let Some(obj) = ack_properties.as_object_mut() {
            obj.insert("pairing_required".to_string(), json!(pairing_required_flag));
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
        if let Err(err) = self.write_frame(&mut session, ack_frame).await {
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

        loop {
            select! {
                inbound = session.read_request_body() => {
                    match inbound {
                        Ok(Some(chunk)) => {
                            buffer.extend_from_slice(&chunk);
                            match self.consume_established_frames(&mut session, &device_id, &mut buffer, &tx_out, &mut server_sequence).await {
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
                            if let Err(err) = self.write_frame(&mut session, frame).await {
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
                let user_payload = envelope.properties.get("user").and_then(|v| v.as_object());
                let user_id_hint = user_payload
                    .and_then(|map| map.get("id"))
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

                let mut ledger_action = None;
                let user_id: String;
                let mut user_profile: UserProfile;

                match self.state.storage.load_device(&device_id).await {
                    Ok(record) => {
                        if record.status != "active" {
                            return Err(ServerError::Invalid);
                        }
                        if let Some(provided) = &user_id_hint {
                            if provided != &record.user_id {
                                return Err(ServerError::Invalid);
                            }
                        }
                        user_id = record.user_id.clone();
                        user_profile = self.state.storage.load_user(&user_id).await?;
                        if let Some(handle) = &handle_hint {
                            if user_profile.handle != *handle {
                                return Err(ServerError::Invalid);
                            }
                        }
                        if record.public_key != client_static.to_vec() {
                            if !self.state.config.auto_approve_devices {
                                return Err(ServerError::Invalid);
                            }
                            let update = DeviceRecord {
                                device_id: device_id.clone(),
                                user_id: record.user_id.clone(),
                                public_key: client_static.to_vec(),
                                status: record.status.clone(),
                                created_at: record.created_at,
                            };
                            self.state.storage.upsert_device(&update).await?;
                            ledger_action = Some("rotate");
                        }
                    }
                    Err(StorageError::Missing) => {
                        let (resolved_id, profile) = if let Some(provided) = &user_id_hint {
                            let profile = self.state.storage.load_user(provided).await?;
                            if let Some(handle) = &handle_hint {
                                if profile.handle != *handle {
                                    return Err(ServerError::Invalid);
                                }
                            }
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
                            public_key: client_static.to_vec(),
                            status: "active".to_string(),
                            created_at: Utc::now(),
                        };
                        self.state.storage.upsert_device(&insert).await?;
                        user_id = resolved_id;
                        user_profile = profile;
                        ledger_action = Some("register");
                    }
                    Err(err) => return Err(err.into()),
                }

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
                        public_key: client_static.to_vec(),
                        recorded_at,
                    };
                    self.state.storage.record_device_key_event(&event).await?;
                    let ledger_entry = LedgerRecord {
                        digest: client_static,
                        recorded_at,
                        metadata: json!({
                            "device": device_id,
                            "user": user_id,
                            "action": action,
                            "source": "auto-approve",
                        }),
                    };
                    if let Err(err) = self.state.ledger.submit(&ledger_entry) {
                        warn!("ledger submission failed: {}", err);
                    }
                }

                context.user_id = user_id.clone();
                context.user_profile = Some(user_profile.clone());

                let noise = NoiseConfig {
                    pattern,
                    prologue: self.state.config.prologue.clone(),
                    local_private: self.state.noise_private,
                    local_static_public: Some(self.state.noise_public),
                    remote_static_public: Some(client_static),
                };
                let mut handshake_state = build_handshake(&noise, false)?;
                let _ = handshake_state.read_message(&handshake_bytes)?;
                let session_id = generate_id(&device_id);
                let user_payload = json!({
                    "id": user_id.clone(),
                    "handle": user_profile.handle.clone(),
                    "display_name": user_profile.display_name.clone(),
                    "avatar_url": user_profile.avatar_url.clone(),
                });
                let payload = json!({
                    "session": session_id,
                    "domain": self.state.config.domain,
                    "protocol_version": context.protocol_version,
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
                            "server_static": encode_hex(&self.state.noise_public),
                            "protocol_version": context.protocol_version,
                            "supported_versions": SUPPORTED_PROTOCOL_VERSIONS,
                        }),
                    }),
                };
                *server_sequence += 1;
                self.write_frame(session, response_frame).await?;
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
                let _ = handshake_state.into_transport()?;
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
    ) -> Result<(), ServerError> {
        let encoded = frame.encode()?;
        session
            .write_response_body(encoded.into(), false)
            .await
            .map_err(|_| ServerError::Io)?;
        self.state.metrics.mark_egress();
        Ok(())
    }

    async fn consume_established_frames(
        &self,
        session: &mut ServerSession,
        device_id: &str,
        buffer: &mut Vec<u8>,
        tx_out: &mpsc::Sender<Frame>,
        server_sequence: &mut u64,
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
                    let _ = self.write_frame(session, error_frame).await;
                    return Err(ServerError::Codec);
                }
            }
        }
    }

    async fn handle_established_frame(
        &self,
        device_id: &str,
        frame: Frame,
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
                        let normalized = domain.to_ascii_lowercase();
                        let peer = if let Some(peer) = self.state.allowed_peers.get(&normalized) {
                            Some(peer.clone())
                        } else {
                            let cached = {
                                let peers = self.state.dynamic_peers.read().await;
                                peers.get(&normalized).cloned()
                            };
                            if let Some(peer) = cached {
                                Some(peer)
                            } else {
                                match self.state.storage.load_federation_peer(&normalized).await {
                                    Ok(record)
                                        if matches!(
                                            record.status,
                                            FederationPeerStatus::Active
                                                | FederationPeerStatus::Pending
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
                                                .set_federation_peer_status(
                                                    &record.domain,
                                                    FederationPeerStatus::Active,
                                                )
                                                .await;
                                        }
                                        Some(peer)
                                    }
                                    _ => None,
                                }
                            }
                        };
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
                            info!(
                                peer = %domain,
                                endpoint = %peer.endpoint,
                                event = %signed.event.event_id,
                                "federation event queued"
                            );
                        } else {
                            warn!(peer = %domain, "federation peer not allowed");
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
        self.state.metrics.decr_connections();
    }
}
