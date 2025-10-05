use super::{ApiError, AppState};
use crate::config::{IceConfig, TurnAuthConfig};
use crate::metrics::{Metrics, SecuritySnapshot};
use crate::transport::{
    Endpoint, MultipathEndpoint, MultipathPathInfo, PerformanceTier, RaptorqDecoder, RealityConfig,
    ResistanceLevel, TransportError, TransportType,
};
use crate::util::{decode_hex32, encode_hex, generate_id};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as Base64;
use blake3::hash as blake3_hash;
use chrono::{Duration as ChronoDuration, Utc};
use commucat_crypto::{DeviceKeyPair, HandshakePattern, NoiseConfig, PqxdhBundle, build_handshake};
use hmac::{Hmac, Mac};
use ml_kem::EncodedSizeUser;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::net::UdpSocket;
use tracing::{info, warn};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Deserialize)]
pub struct P2pAssistRequest {
    #[serde(default)]
    pub peer_hint: Option<String>,
    #[serde(default)]
    pub paths: Vec<PathHint>,
    #[serde(default)]
    pub prefer_reality: bool,
    #[serde(default)]
    pub fec: Option<FecHint>,
    #[serde(default)]
    pub min_paths: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct PathHint {
    pub address: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub priority: Option<u8>,
    #[serde(default)]
    pub reality_fingerprint: Option<String>,
    #[serde(default)]
    pub reality_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FecHint {
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub repair_overhead: Option<f32>,
}

#[derive(Debug, Serialize)]
pub struct P2pAssistResponse {
    pub noise: NoiseAdvice,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq: Option<PqAdvice>,
    pub ice: IceAdvice,
    pub transports: Vec<TransportAdvice>,
    pub multipath: MultipathAdvice,
    pub obfuscation: ObfuscationAdvice,
    pub security: SecuritySnapshot,
}

#[derive(Debug, Serialize)]
pub struct NoiseAdvice {
    pub pattern: HandshakePattern,
    pub prologue_hex: String,
    pub device_seed_hex: String,
    pub static_public_hex: String,
}

#[derive(Debug, Serialize)]
pub struct PqAdvice {
    pub identity_public_hex: String,
    pub signed_prekey_public_hex: String,
    pub kem_public_hex: String,
    pub signature_public_hex: String,
}

#[derive(Debug, Serialize)]
pub struct IceAdvice {
    pub username_fragment: String,
    pub password: String,
    pub ttl_secs: u32,
    pub keepalive_interval_secs: u16,
    pub trickle: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<IceServerAdvice>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lite_candidates: Vec<IceCandidateAdvice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IceServerAdvice {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
    pub ttl_secs: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IceCandidateAdvice {
    pub candidate: String,
    pub component: u8,
    pub protocol: String,
    pub foundation: String,
    pub priority: u32,
    pub ip: String,
    pub port: u16,
    pub typ: String,
}

#[derive(Debug, Serialize)]
pub struct TransportAdvice {
    pub path_id: String,
    pub transport: String,
    pub resistance: String,
    pub latency: String,
    pub throughput: String,
}

#[derive(Debug, Serialize)]
pub struct MultipathAdvice {
    pub fec_mtu: u16,
    pub fec_overhead: f32,
    pub primary_path: Option<String>,
    pub sample_segments: HashMap<String, SampleBreakdown>,
}

#[derive(Debug, Serialize, Default)]
pub struct SampleBreakdown {
    pub total: usize,
    pub repair: usize,
}

#[derive(Debug, Serialize, Default)]
pub struct ObfuscationAdvice {
    pub reality_fingerprint_hex: Option<String>,
    pub domain_fronting: bool,
    pub protocol_mimicry: bool,
    pub tor_bridge: bool,
}

#[derive(Clone)]
pub struct IceRuntime {
    pub lite: Option<IceLiteRuntime>,
    pub turn: Vec<TurnServerRuntime>,
    pub credential_ttl: StdDuration,
}

#[derive(Clone)]
pub struct IceLiteRuntime {
    pub public_addr: SocketAddr,
}

#[derive(Clone)]
pub struct TurnServerRuntime {
    pub urls: Vec<String>,
    pub auth: TurnAuth,
    pub realm: Option<String>,
}

#[derive(Clone)]
pub enum TurnAuth {
    Static {
        username: String,
        credential: String,
    },
    Secret {
        secret: String,
    },
}

#[derive(Clone, Copy)]
pub struct IceLiteServerConfig {
    pub bind_addr: SocketAddr,
    pub public_addr: SocketAddr,
}

const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const ICE_SOFTWARE: &str = "CommuCat ICE-lite";

pub(super) fn build_ice_runtime(config: &IceConfig) -> (IceRuntime, Option<IceLiteServerConfig>) {
    let lite_public = if config.lite_enabled {
        config.lite_public_address.or(config.lite_bind)
    } else {
        None
    };
    let lite_runtime = lite_public.map(|addr| IceLiteRuntime { public_addr: addr });
    let lite_server_cfg = if config.lite_enabled {
        match (config.lite_bind, lite_public) {
            (Some(bind_addr), Some(public_addr)) => Some(IceLiteServerConfig {
                bind_addr,
                public_addr,
            }),
            _ => {
                warn!("ice-lite enabled but bind/public address not fully configured");
                None
            }
        }
    } else {
        None
    };
    let turn = config
        .turn_servers
        .iter()
        .map(|entry| TurnServerRuntime {
            urls: entry.urls.clone(),
            auth: match &entry.auth {
                TurnAuthConfig::Static { username, password } => TurnAuth::Static {
                    username: username.clone(),
                    credential: password.clone(),
                },
                TurnAuthConfig::Secret { secret } => TurnAuth::Secret {
                    secret: secret.clone(),
                },
            },
            realm: entry.realm.clone(),
        })
        .collect();
    let runtime = IceRuntime {
        lite: lite_runtime,
        turn,
        credential_ttl: config.turn_ttl,
    };
    (runtime, lite_server_cfg)
}

pub(super) fn spawn_ice_lite(config: IceLiteServerConfig, metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        if let Err(err) = run_ice_lite_server(config, metrics).await {
            warn!(error = %err, "ice-lite server terminated");
        }
    });
}

async fn run_ice_lite_server(config: IceLiteServerConfig, metrics: Arc<Metrics>) -> io::Result<()> {
    let socket = UdpSocket::bind(config.bind_addr).await?;
    info!(bind = %config.bind_addr, public = %config.public_addr, "ice-lite listener started");
    let mut buf = [0u8; 2048];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        match build_binding_response(&buf[..len], config.public_addr) {
            Ok(Some(response)) => {
                if let Err(err) = socket.send_to(&response, peer).await {
                    warn!(peer = %peer, error = %err, "failed to send STUN binding response");
                    metrics.mark_ice_binding_failure();
                } else {
                    metrics.mark_ice_binding_success();
                }
            }
            Ok(None) => {}
            Err(_) => metrics.mark_ice_binding_failure(),
        }
    }
}

fn build_binding_response(packet: &[u8], public_addr: SocketAddr) -> Result<Option<Vec<u8>>, ()> {
    if packet.len() < 20 {
        return Ok(None);
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    // Binding request
    if msg_type != 0x0001 {
        return Ok(None);
    }
    let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < 20 + length {
        return Err(());
    }
    let cookie: [u8; 4] = packet[4..8].try_into().map_err(|_| ())?;
    if cookie != STUN_MAGIC_COOKIE {
        return Err(());
    }
    let txid = &packet[8..20];
    let mut response = Vec::with_capacity(64);
    response.extend_from_slice(&0x0101u16.to_be_bytes());
    response.extend_from_slice(&[0, 0]);
    response.extend_from_slice(&STUN_MAGIC_COOKIE);
    response.extend_from_slice(txid);

    let mut xor_value = Vec::new();
    xor_value.push(0);
    match public_addr {
        SocketAddr::V4(addr) => {
            xor_value.push(0x01);
            let xport =
                addr.port() ^ u16::from_be_bytes([STUN_MAGIC_COOKIE[0], STUN_MAGIC_COOKIE[1]]);
            xor_value.extend_from_slice(&xport.to_be_bytes());
            let ip = addr.ip().octets();
            for (octet, mask) in ip.iter().zip(STUN_MAGIC_COOKIE.iter()) {
                xor_value.push(octet ^ mask);
            }
        }
        SocketAddr::V6(addr) => {
            xor_value.push(0x02);
            let xport =
                addr.port() ^ u16::from_be_bytes([STUN_MAGIC_COOKIE[0], STUN_MAGIC_COOKIE[1]]);
            xor_value.extend_from_slice(&xport.to_be_bytes());
            let ip = addr.ip().octets();
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&STUN_MAGIC_COOKIE);
            mask[4..].copy_from_slice(txid);
            for (octet, mask_byte) in ip.iter().zip(mask.iter()) {
                xor_value.push(octet ^ mask_byte);
            }
        }
    }
    append_attribute(&mut response, 0x0020, &xor_value);

    let tie_breaker = blake3_hash(public_addr.to_string().as_bytes());
    append_attribute(&mut response, 0x8029, &tie_breaker.as_bytes()[..8]);
    append_attribute(&mut response, 0x8022, ICE_SOFTWARE.as_bytes());

    let attr_len = (response.len() - 20) as u16;
    response[2] = (attr_len >> 8) as u8;
    response[3] = attr_len as u8;
    Ok(Some(response))
}

fn append_attribute(message: &mut Vec<u8>, ty: u16, value: &[u8]) {
    message.extend_from_slice(&ty.to_be_bytes());
    message.extend_from_slice(&(value.len() as u16).to_be_bytes());
    message.extend_from_slice(value);
    let padding = (4 - (value.len() % 4)) % 4;
    if padding > 0 {
        message.extend(std::iter::repeat_n(0, padding));
    }
}

fn foundation_for_ip(ip: IpAddr) -> String {
    let bytes = match ip {
        IpAddr::V4(addr) => addr.octets().to_vec(),
        IpAddr::V6(addr) => addr.octets().to_vec(),
    };
    let hash = blake3_hash(&bytes);
    hash.as_bytes()
        .iter()
        .take(4)
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn host_candidate_priority(component: u8) -> u32 {
    let type_preference = 126u32;
    let local_preference = 65_535u32;
    let component_preference = 256u32 - u32::from(component);
    (type_preference << 24) | (local_preference << 8) | component_preference
}

fn build_lite_candidate(addr: SocketAddr) -> IceCandidateAdvice {
    let foundation = foundation_for_ip(addr.ip());
    let component = 1;
    let priority = host_candidate_priority(component);
    let candidate = format!(
        "candidate:{} {} udp {} {} {} typ host generation 0",
        foundation,
        component,
        priority,
        addr.ip(),
        addr.port()
    );
    IceCandidateAdvice {
        candidate,
        component,
        protocol: "udp".to_string(),
        foundation,
        priority,
        ip: addr.ip().to_string(),
        port: addr.port(),
        typ: "host".to_string(),
    }
}

fn generate_turn_credentials(
    auth: &TurnAuth,
    username_fragment: &str,
    ttl: StdDuration,
) -> (String, String, u32, Option<String>) {
    match auth {
        TurnAuth::Static {
            username,
            credential,
        } => (username.clone(), credential.clone(), 0, None),
        TurnAuth::Secret { secret } => {
            let mut ttl_secs = ttl.as_secs();
            if ttl_secs < 60 {
                ttl_secs = 60;
            }
            if ttl_secs > u32::MAX as u64 {
                ttl_secs = u32::MAX as u64;
            }
            let ttl_secs_u32 = ttl_secs as u32;
            let expires = Utc::now().timestamp() + ttl_secs as i64;
            let username = format!("{}:{}", expires, username_fragment);
            let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("hmac key");
            mac.update(username.as_bytes());
            let credential = Base64.encode(mac.finalize().into_bytes());
            let expires_at = (Utc::now() + ChronoDuration::seconds(ttl_secs as i64)).to_rfc3339();
            (username, credential, ttl_secs_u32, Some(expires_at))
        }
    }
}

pub(super) async fn handle_assist(
    state: &AppState,
    request: P2pAssistRequest,
) -> Result<P2pAssistResponse, ApiError> {
    let fec_profile = request
        .fec
        .as_ref()
        .map(|hint| {
            crate::transport::FecProfile::new(
                hint.mtu.unwrap_or(1152),
                hint.repair_overhead.unwrap_or(0.35),
            )
        })
        .unwrap_or_else(crate::transport::FecProfile::default_low_latency);

    let requested_paths = request.min_paths.unwrap_or(2).max(1);
    let mut endpoints = Vec::new();
    if request.paths.is_empty() {
        endpoints.extend(default_paths(
            state,
            request.prefer_reality,
            request.peer_hint.as_deref(),
        ));
    } else {
        for (idx, hint) in request.paths.iter().enumerate() {
            endpoints.push(path_from_hint(state, hint, idx)?);
        }
    }
    if endpoints.is_empty() {
        return Err(ApiError::BadRequest("no paths provided".to_string()));
    }

    let required_paths = requested_paths.min(endpoints.len().max(1));
    let mut path_info: Vec<MultipathPathInfo> = Vec::new();
    let mut transports_advice: Vec<TransportAdvice> = Vec::new();
    let mut sample_segments: HashMap<String, SampleBreakdown> = HashMap::new();
    let mut primary_path: Option<String> = None;

    {
        let mut manager = state.transports.write().await;
        match manager
            .establish_multipath(&endpoints, required_paths, fec_profile.clone())
            .await
        {
            Ok(tunnel) => {
                state.metrics.mark_multipath_session(tunnel.path_count());
                path_info = tunnel.path_info();
                transports_advice = path_info.iter().map(transport_advice_from_info).collect();
                if let Some(primary) = tunnel.primary_path_id() {
                    primary_path = Some(primary.to_string());
                }

                let sample_payload = generate_sample_payload(fec_profile.mtu as usize);
                let dispatch = tunnel.encode_frame(&sample_payload);
                let mut decoder = RaptorqDecoder::new(dispatch.oti);
                let mut recovered = None;
                for segment in dispatch.segments.iter() {
                    let entry = sample_segments.entry(segment.path_id.clone()).or_default();
                    entry.total += 1;
                    if segment.repair {
                        entry.repair += 1;
                    }
                    if recovered.is_none() {
                        recovered = decoder.absorb(&segment.payload);
                    }
                }
                if let Some(decoded) = recovered {
                    if decoded == sample_payload {
                        state
                            .metrics
                            .mark_fec_packets(dispatch.segments.len() as u64);
                    } else {
                        warn!("fec probe decode mismatch for assist response");
                    }
                }
            }
            Err(err) => {
                warn!(error = %err, "p2p assist multipath establishment failed");
                if matches!(err, TransportError::Censorship) {
                    state.metrics.mark_censorship_deflection();
                }
            }
        }
    }

    if transports_advice.is_empty() {
        transports_advice = fallback_transport_advice(&endpoints);
    }
    if sample_segments.is_empty() {
        sample_segments = fallback_sample_segments(&endpoints);
    }

    if primary_path.is_none() {
        primary_path = transports_advice
            .first()
            .map(|advice| advice.path_id.clone());
    }

    for endpoint in &endpoints {
        sample_segments.entry(endpoint.id.clone()).or_default();
    }

    let obfuscation = build_obfuscation_advice(&path_info, &endpoints);
    let noise = build_noise_advice(state)?;
    state.metrics.mark_noise_handshake();

    // PQ advice - опционально, если настроено на сервере
    let pq = build_pq_advice_from_state(state);
    if pq.is_some() {
        state.metrics.mark_pq_handshake();
    }

    let ice = build_ice_advice(state);

    let response = P2pAssistResponse {
        noise,
        pq,
        ice,
        transports: transports_advice,
        multipath: MultipathAdvice {
            fec_mtu: fec_profile.mtu,
            fec_overhead: fec_profile.repair_overhead,
            primary_path,
            sample_segments,
        },
        obfuscation,
        security: state.metrics.security_snapshot(),
    };

    Ok(response)
}

fn transport_advice_from_info(info: &MultipathPathInfo) -> TransportAdvice {
    TransportAdvice {
        path_id: info.id.clone(),
        transport: transport_label(info.transport).to_string(),
        resistance: resistance_label_str(info.resistance).to_string(),
        latency: tier_label_str(info.performance.latency).to_string(),
        throughput: tier_label_str(info.performance.throughput).to_string(),
    }
}

fn transport_label(transport: TransportType) -> &'static str {
    match transport {
        TransportType::AmnesiaWg => "AmnesiaWG",
        TransportType::Reality => "Reality",
        TransportType::Shadowsocks => "Shadowsocks",
        TransportType::Onion => "Onion",
        TransportType::QuicMasque => "QUICMasque",
        TransportType::WebSocket => "WebSocket",
        TransportType::Dns => "DNS",
    }
}

fn resistance_label_str(level: ResistanceLevel) -> &'static str {
    match level {
        ResistanceLevel::Basic => "Basic",
        ResistanceLevel::Enhanced => "Enhanced",
        ResistanceLevel::Maximum => "Maximum",
        ResistanceLevel::Paranoid => "Paranoid",
    }
}

fn tier_label_str(tier: PerformanceTier) -> &'static str {
    match tier {
        PerformanceTier::High => "High",
        PerformanceTier::Medium => "Medium",
        PerformanceTier::Low => "Low",
    }
}

fn default_transport_profile(
    transport: TransportType,
) -> (ResistanceLevel, PerformanceTier, PerformanceTier) {
    match transport {
        TransportType::Reality => (
            ResistanceLevel::Maximum,
            PerformanceTier::High,
            PerformanceTier::High,
        ),
        TransportType::AmnesiaWg => (
            ResistanceLevel::Maximum,
            PerformanceTier::Medium,
            PerformanceTier::Medium,
        ),
        TransportType::QuicMasque => (
            ResistanceLevel::Enhanced,
            PerformanceTier::High,
            PerformanceTier::High,
        ),
        TransportType::Shadowsocks => (
            ResistanceLevel::Enhanced,
            PerformanceTier::Medium,
            PerformanceTier::High,
        ),
        TransportType::Onion => (
            ResistanceLevel::Paranoid,
            PerformanceTier::Low,
            PerformanceTier::Low,
        ),
        TransportType::Dns => (
            ResistanceLevel::Enhanced,
            PerformanceTier::Low,
            PerformanceTier::Low,
        ),
        TransportType::WebSocket => (
            ResistanceLevel::Basic,
            PerformanceTier::Medium,
            PerformanceTier::Medium,
        ),
    }
}

fn fallback_transport_advice(endpoints: &[MultipathEndpoint]) -> Vec<TransportAdvice> {
    endpoints
        .iter()
        .map(|endpoint| {
            let transport = if endpoint.endpoint.reality.is_some() {
                TransportType::Reality
            } else {
                TransportType::WebSocket
            };
            let (resistance, latency, throughput) = default_transport_profile(transport);
            TransportAdvice {
                path_id: endpoint.id.clone(),
                transport: transport_label(transport).to_string(),
                resistance: resistance_label_str(resistance).to_string(),
                latency: tier_label_str(latency).to_string(),
                throughput: tier_label_str(throughput).to_string(),
            }
        })
        .collect()
}

fn fallback_sample_segments(endpoints: &[MultipathEndpoint]) -> HashMap<String, SampleBreakdown> {
    let mut result = HashMap::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let total = if index == 0 { 12 } else { 8 };
        let repair = ((total as f32) * if index == 0 { 0.3 } else { 0.2 })
            .round()
            .max(1.0) as usize;
        result.insert(endpoint.id.clone(), SampleBreakdown { total, repair });
    }
    result
}

fn generate_sample_payload(mtu: usize) -> Vec<u8> {
    let chunk = mtu.clamp(512, 2048);
    let mut payload = vec![0u8; chunk * 3];
    OsRng.fill_bytes(&mut payload);
    payload
}

fn default_paths(
    state: &AppState,
    use_reality: bool,
    peer_hint: Option<&str>,
) -> Vec<MultipathEndpoint> {
    let base_endpoint = Endpoint {
        address: state.config.domain.clone(),
        port: 443,
        server_name: Some(state.config.domain.clone()),
        reality: state
            .config
            .transport
            .reality
            .as_ref()
            .filter(|_| use_reality)
            .map(|cfg| RealityConfig {
                certificate_pem: Arc::new(cfg.certificate_pem.clone()),
                fingerprint: cfg.fingerprint,
            }),
    };
    let backup_address = peer_hint
        .map(|hint| hint.to_string())
        .unwrap_or_else(|| format!("relay.{}", state.config.domain));
    let backup_endpoint = Endpoint {
        address: backup_address,
        ..base_endpoint.clone()
    };
    vec![
        MultipathEndpoint::new("primary", base_endpoint.clone()).with_priority(0),
        MultipathEndpoint::new("backup", backup_endpoint).with_priority(1),
    ]
}

fn path_from_hint(
    state: &AppState,
    hint: &PathHint,
    index: usize,
) -> Result<MultipathEndpoint, ApiError> {
    let port = hint.port.unwrap_or(443);
    let id = hint
        .id
        .clone()
        .unwrap_or_else(|| format!("path-{}", index + 1));
    let mut reality = None;
    if let Some(fingerprint_hex) = hint.reality_fingerprint.as_ref() {
        let fp = decode_hex32(fingerprint_hex)
            .map_err(|_| ApiError::BadRequest("invalid reality fingerprint".to_string()))?;
        let pem = hint
            .reality_pem
            .clone()
            .or_else(|| {
                state
                    .config
                    .transport
                    .reality
                    .as_ref()
                    .map(|cfg| cfg.certificate_pem.clone())
            })
            .ok_or_else(|| ApiError::BadRequest("reality certificate missing".to_string()))?;
        reality = Some(RealityConfig {
            fingerprint: fp,
            certificate_pem: Arc::new(pem),
        });
    } else if hint.reality_pem.is_some() {
        warn!("reality certificate provided without fingerprint");
    }
    let endpoint = Endpoint {
        address: hint.address.clone(),
        port,
        server_name: hint
            .server_name
            .clone()
            .or_else(|| Some(state.config.domain.clone())),
        reality,
    };
    Ok(MultipathEndpoint::new(id, endpoint).with_priority(hint.priority.unwrap_or(100)))
}

fn build_obfuscation_advice(
    paths: &[crate::transport::MultipathPathInfo],
    endpoints: &[MultipathEndpoint],
) -> ObfuscationAdvice {
    let mut advice = ObfuscationAdvice::default();
    for info in paths {
        match info.transport {
            TransportType::WebSocket | TransportType::QuicMasque | TransportType::Dns => {
                advice.domain_fronting = true;
            }
            TransportType::Shadowsocks => {
                advice.protocol_mimicry = true;
            }
            TransportType::Onion => {
                advice.tor_bridge = true;
            }
            TransportType::Reality => {
                advice.protocol_mimicry = true;
            }
            _ => {}
        }
    }
    for endpoint in endpoints {
        if let Some(reality) = endpoint.endpoint.reality.as_ref() {
            advice.reality_fingerprint_hex = Some(encode_hex(&reality.fingerprint));
        }
    }
    advice
}

fn build_noise_advice(state: &AppState) -> Result<NoiseAdvice, ApiError> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let device = DeviceKeyPair::from_seed(&seed).map_err(|_| ApiError::Internal)?;
    let prologue = state.config.prologue.clone();
    let config = NoiseConfig {
        pattern: HandshakePattern::Xk,
        prologue: prologue.clone(),
        local_private: device.private,
        local_static_public: Some(device.public),
        remote_static_public: None,
    };
    // Produce a dummy initiator handshake to ensure parameters are valid.
    let mut handshake = build_handshake(&config, true).map_err(|_| ApiError::Internal)?;
    let _ = handshake
        .write_message(&[])
        .map_err(|_| ApiError::Internal)?;
    Ok(NoiseAdvice {
        pattern: config.pattern,
        prologue_hex: encode_hex(&prologue),
        device_seed_hex: encode_hex(&seed),
        static_public_hex: encode_hex(&device.public),
    })
}

fn build_pq_advice_from_state(state: &AppState) -> Option<PqAdvice> {
    // Если PQ не настроен в конфиге, возвращаем None
    let pq_runtime = state.pq.as_ref()?;

    // Используем публичный ключ из конфигурации вместо генерации нового
    // Для полноценного PQXDH нужны ephemeral ключи, но для assist-advice
    // достаточно показать что сервер поддерживает PQ
    Some(PqAdvice {
        identity_public_hex: String::new(), // Ephemeral, генерится клиентом
        signed_prekey_public_hex: String::new(), // Ephemeral, генерится клиентом
        kem_public_hex: encode_hex(&pq_runtime.kem_public),
        signature_public_hex: String::new(), // Опционально для assist
    })
}

// Deprecated: используйте build_pq_advice_from_state
// Оставлено для обратной совместимости если нужно генерировать полный bundle
#[allow(dead_code)]
fn build_pq_advice_full() -> Result<PqAdvice, ApiError> {
    let mut rng = OsRng;
    let bundle = PqxdhBundle::generate(4, 2, &mut rng).map_err(|_| ApiError::Internal)?;
    let identity_public = bundle.identity_key.verifying_key().to_bytes();
    let signed_prekey_public = bundle.signed_prekey_public();
    let kem_public = bundle.pq_identity.public().as_bytes();
    let signature_public = bundle.pq_signature.verifying_key().inner().encode();
    Ok(PqAdvice {
        identity_public_hex: encode_hex(&identity_public),
        signed_prekey_public_hex: encode_hex(signed_prekey_public.as_bytes()),
        kem_public_hex: encode_hex(kem_public.as_ref()),
        signature_public_hex: encode_hex(signature_public.as_ref()),
    })
}

fn build_ice_advice(state: &AppState) -> IceAdvice {
    let ufrag_seed = generate_id("ice-ufrag");
    let pwd_seed = generate_id("ice-password");
    let username_fragment: String = ufrag_seed.chars().take(16).collect();
    let password: String = pwd_seed.chars().take(64).collect();
    let ttl_secs = state.config.pairing_ttl_seconds.clamp(60, 3_600) as u32;
    let keepalive = state.config.connection_keepalive.clamp(5, 120);
    let keepalive_interval_secs = u16::try_from(keepalive).unwrap_or(30);
    let mut servers = Vec::new();
    for server in &state.ice.turn {
        let (username, credential, ttl, expires_at) =
            generate_turn_credentials(&server.auth, &username_fragment, state.ice.credential_ttl);
        servers.push(IceServerAdvice {
            urls: server.urls.clone(),
            username,
            credential,
            ttl_secs: ttl,
            expires_at,
            realm: server.realm.clone(),
        });
    }
    let lite_candidates = state
        .ice
        .lite
        .as_ref()
        .map(|lite| build_lite_candidate(lite.public_addr))
        .into_iter()
        .collect();
    let expires_at = Some((Utc::now() + ChronoDuration::seconds(ttl_secs as i64)).to_rfc3339());
    IceAdvice {
        username_fragment,
        password,
        ttl_secs,
        keepalive_interval_secs,
        trickle: true,
        servers,
        lite_candidates,
        expires_at,
    }
}
