use crate::config::{LedgerAdapter, PeerConfig, ServerConfig};
use crate::metrics::Metrics;
use crate::util::{decode_hex, decode_hex32, encode_hex, generate_id};
use blake3::hash as blake3_hash;
use chrono::{Duration, Utc};
use commucat_crypto::{
    build_handshake, CryptoError, EventSigner, HandshakePattern, NoiseConfig, NoiseHandshake,
};
use commucat_federation::{sign_event, FederationError, FederationEvent};
use commucat_ledger::{
    DebugLedgerAdapter, FileLedgerAdapter, LedgerAdapter as LedgerAdapterTrait, LedgerError,
    LedgerRecord, NullLedger,
};
use commucat_proto::{ControlEnvelope, Frame, FramePayload, FrameType};
use commucat_storage::{
    connect, PresenceSnapshot, RelayEnvelope, SessionRecord, Storage, StorageError,
};
use pingora::apps::{HttpServerApp, HttpServerOptions, ReusedHttpStream};
use pingora::http::ResponseHeader;
use pingora::protocols::http::v2::server::H2Options;
use pingora::protocols::http::ServerSession;
use pingora::server::ShutdownWatch;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::select;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

#[derive(Debug)]
pub enum ServerError {
    Storage,
    Ledger,
    Crypto,
    Codec,
    Federation,
    Invalid,
    Io,
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
        }
    }
}

impl Error for ServerError {}

impl From<StorageError> for ServerError {
    fn from(_: StorageError) -> Self {
        ServerError::Storage
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
    pub federation_signer: EventSigner,
    pub noise_private: [u8; 32],
    pub noise_public: [u8; 32],
    pub presence_ttl: i64,
    pub relay_ttl: i64,
}

pub struct ConnectionEntry {
    pub sender: mpsc::Sender<Frame>,
    pub session_id: String,
    next_sequence: AtomicU64,
}

impl ConnectionEntry {
    pub fn new(sender: mpsc::Sender<Frame>, session_id: String) -> Self {
        ConnectionEntry {
            sender,
            session_id,
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
}

pub struct PeerPresence {
    pub address: Option<String>,
    pub last_seen: chrono::DateTime<Utc>,
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
    handshake: Option<NoiseHandshake>,
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
        let signer = EventSigner::new(&config.federation_seed);
        Ok(Arc::new(AppState {
            storage,
            ledger,
            metrics: Metrics::new(),
            connections: RwLock::new(HashMap::new()),
            channel_routes: RwLock::new(HashMap::new()),
            peer_sessions: RwLock::new(HashMap::new()),
            allowed_peers,
            federation_signer: signer,
            noise_private: config.noise_private,
            noise_public: config.noise_public,
            presence_ttl: config.presence_ttl_seconds,
            relay_ttl: config.relay_ttl_seconds,
            config,
        }))
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
            "/healthz" => {
                self.state.metrics.mark_ingress();
                let mut response = ResponseHeader::build_no_case(200, None).ok()?;
                response.append_header("content-type", "text/plain").ok()?;
                let _ = session
                    .write_response_header(Box::new(response))
                    .await
                    .ok()?;
                let _ = session
                    .write_response_body(Vec::from("ok".as_bytes()).into(), true)
                    .await
                    .ok()?;
                let _ = session.finish().await.ok()?;
                return None;
            }
            "/readyz" => {
                if self.state.storage.readiness().await.is_ok() {
                    let mut response = ResponseHeader::build_no_case(200, None).ok()?;
                    response.append_header("content-type", "text/plain").ok()?;
                    let _ = session
                        .write_response_header(Box::new(response))
                        .await
                        .ok()?;
                    let _ = session
                        .write_response_body(Vec::from("ready".as_bytes()).into(), true)
                        .await
                        .ok()?;
                } else {
                    let mut response = ResponseHeader::build_no_case(503, None).ok()?;
                    response.append_header("content-type", "text/plain").ok()?;
                    let _ = session
                        .write_response_header(Box::new(response))
                        .await
                        .ok()?;
                    let _ = session
                        .write_response_body(Vec::from("degraded".as_bytes()).into(), true)
                        .await
                        .ok()?;
                }
                let _ = session.finish().await.ok()?;
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
                    let _ = session
                        .write_response_header(Box::new(response))
                        .await
                        .ok()?;
                    let _ = session
                        .write_response_body(body.into_bytes().into(), true)
                        .await
                        .ok()?;
                    let _ = session.finish().await.ok()?;
                    return None;
                }
                let payload = self.state.metrics.encode_prometheus();
                let mut response = ResponseHeader::build_no_case(200, None).ok()?;
                response
                    .append_header("content-type", "text/plain; version=0.0.4")
                    .ok()?;
                let _ = session
                    .write_response_header(Box::new(response))
                    .await
                    .ok()?;
                let _ = session
                    .write_response_body(payload.into_bytes().into(), true)
                    .await
                    .ok()?;
                let _ = session.finish().await.ok()?;
                return None;
            }
            _ => {}
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
        let _ = session
            .write_response_header(Box::new(response))
            .await
            .ok()?;
        let _ = session
            .write_response_body(body.into_bytes().into(), true)
            .await
            .ok()?;
        let _ = session.finish().await.ok()?;
        None
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
        let _ = session
            .write_response_header(Box::new(response))
            .await
            .ok()?;

        let mut buffer = Vec::new();
        let mut handshake = HandshakeContext {
            stage: HandshakeStage::Hello,
            device_id: String::new(),
            session_id: String::new(),
            handshake: None,
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
                            let error_frame = Frame {
                                channel_id: 0,
                                sequence: server_sequence,
                                frame_type: FrameType::Error,
                                payload: FramePayload::Control(ControlEnvelope {
                                    properties: json!({
                                        "error": "handshake",
                                        "detail": err.to_string(),
                                    }),
                                }),
                            };
                            let _ = self.write_frame(&mut session, error_frame).await;
                            let _ = session.finish().await.ok()?;
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
                        let _ = session.finish().await.ok()?;
                        return None;
                    }
                }
            }
        }

        let device_id = handshake.device_id.clone();
        let session_id = handshake.session_id.clone();

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
                ConnectionEntry::new(tx_out.clone(), session_id.clone()),
            );
        }

        self.state.metrics.incr_connections();
        let presence = PresenceSnapshot {
            entity: device_id.clone(),
            state: "online".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.state.presence_ttl),
        };
        if let Err(err) = self.state.storage.publish_presence(&presence).await {
            warn!("presence publish failed: {}", err);
        }
        let session_record = SessionRecord {
            session_id: session_id.clone(),
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

        let ack_frame = Frame {
            channel_id: 0,
            sequence: server_sequence,
            frame_type: FrameType::Ack,
            payload: FramePayload::Control(ControlEnvelope {
                properties: json!({
                    "handshake": "ok",
                    "session": session_id,
                }),
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
                    }
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
        let _ = session.finish().await.ok()?;
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
                    FramePayload::Control(env) => env,
                    _ => return Err(ServerError::Invalid),
                };
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

                let record = self.state.storage.load_device(&device_id).await?;
                if record.public_key != client_static.to_vec() {
                    return Err(ServerError::Invalid);
                }

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
                let payload = json!({
                    "session": session_id,
                    "domain": self.state.config.domain,
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
                            "handshake": encode_hex(&response_bytes),
                            "server_static": encode_hex(&self.state.noise_public),
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
                    FramePayload::Control(env) => env,
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
                    FramePayload::Control(env) => env,
                    _ => return Err(ServerError::Invalid),
                };
                let members_value = envelope
                    .properties
                    .get("members")
                    .and_then(|v| v.as_array())
                    .ok_or(ServerError::Invalid)?;
                let mut members = HashSet::new();
                for entry in members_value {
                    if let Some(value) = entry.as_str() {
                        members.insert(value.to_string());
                    }
                }
                members.insert(device_id.to_string());
                let relay = envelope
                    .properties
                    .get("relay")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                {
                    let mut routes = self.state.channel_routes.write().await;
                    routes.insert(
                        frame.channel_id,
                        ChannelRoute {
                            members: members.clone(),
                            relay,
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
                let snapshot = PresenceSnapshot {
                    entity: device_id.to_string(),
                    state,
                    expires_at: Utc::now() + Duration::seconds(self.state.presence_ttl),
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
            FrameType::GroupCreate | FrameType::GroupInvite => {
                self.broadcast_frame(device_id, frame.clone()).await?;
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
                let inbox_key = format!("inbox:{}", target);
                let envelope = RelayEnvelope {
                    envelope_id: generate_id(&format!("{}:{}", sender, target)),
                    channel_id: inbox_key,
                    payload: encoded.clone(),
                    deliver_after: Utc::now(),
                    expires_at: Utc::now() + Duration::seconds(self.state.relay_ttl),
                };
                self.state.storage.enqueue_relay(&envelope).await?;
                self.state.metrics.mark_relay();
                if let Some(pos) = target.find('@') {
                    let domain = &target[pos + 1..];
                    if domain != self.state.config.domain {
                        let normalized = domain.to_ascii_lowercase();
                        if let Some(peer) = self.state.allowed_peers.get(&normalized) {
                            let event = FederationEvent {
                                event_id: generate_id(target),
                                origin: self.state.config.domain.clone(),
                                created_at: Utc::now(),
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
        {
            let mut connections = self.state.connections.write().await;
            if let Some(entry) = connections.remove(device_id) {
                info!(device = device_id, session = %entry.session_id, "connection closed");
            }
        }
        {
            let mut peers = self.state.peer_sessions.write().await;
            peers.remove(device_id);
        }
        if let Err(err) = self.state.storage.clear_route(device_id).await {
            warn!("route cleanup failed: {}", err);
        }
        let snapshot = PresenceSnapshot {
            entity: device_id.to_string(),
            state: "offline".to_string(),
            expires_at: Utc::now() + Duration::seconds(self.state.presence_ttl),
        };
        if let Err(err) = self.state.storage.publish_presence(&snapshot).await {
            warn!("presence cleanup failed: {}", err);
        }
        self.state.metrics.decr_connections();
    }
}
