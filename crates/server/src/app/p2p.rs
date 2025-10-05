use super::{ApiError, AppState};
use crate::metrics::SecuritySnapshot;
use crate::transport::{
    Endpoint, MultipathEndpoint, RaptorqDecoder, RealityConfig, ResistanceLevel, TransportType,
};
use crate::util::{decode_hex32, encode_hex, generate_id};
use commucat_crypto::{DeviceKeyPair, HandshakePattern, NoiseConfig, PqxdhBundle, build_handshake};
use ml_kem::EncodedSizeUser;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use tracing::{info, warn};

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
    pub pq: PqAdvice,
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

pub(super) async fn handle_assist(
    state: &AppState,
    request: P2pAssistRequest,
) -> Result<P2pAssistResponse, ApiError> {
    // P2P Assist API requires at least one real transport implementation
    // Currently all transports are stubs using memory_stream() - they cannot establish real connections
    // We're implementing WebSocket transport right now!
    warn!("P2P Assist called but no real transports available yet - returning 501");
    Err(ApiError::NotImplemented)
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

fn build_pq_advice() -> Result<PqAdvice, ApiError> {
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
    IceAdvice {
        username_fragment,
        password,
        ttl_secs,
        keepalive_interval_secs,
        trickle: true,
    }
}
