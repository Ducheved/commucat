#![cfg(feature = "obfuscation")]

use crate::{CodecError, Frame, FrameType};
use blake3::keyed_hash;
use rand::{
    distributions::{Alphanumeric, DistString, Distribution, Uniform},
    seq::SliceRandom,
    CryptoRng, Rng, RngCore,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ops::RangeInclusive;

const MAC_KEY_LEN: usize = 32;
const MAC_OUTPUT_LEN: usize = 16;

#[derive(Debug)]
pub enum ObfuscationError {
    Codec(CodecError),
    Serialization(serde_json::Error),
    Integrity,
    HeaderMismatch,
}

impl Display for ObfuscationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(err) => write!(f, "codec error: {err}"),
            Self::Serialization(err) => write!(f, "serialization error: {err}"),
            Self::Integrity => write!(f, "integrity verification failed"),
            Self::HeaderMismatch => write!(f, "frame header mismatch"),
        }
    }
}

impl Error for ObfuscationError {}

impl From<CodecError> for ObfuscationError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<serde_json::Error> for ObfuscationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CensorshipSignal {
    None,
    SuspectedDpi,
    HardBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolFlavor {
    QuicInitial,
    DnsQuery,
    SipInvite,
    HttpsHandshake,
    WebRtc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum ProtocolMimicry {
    QuicInitial(QuicHandshakeSnapshot),
    DnsQuery(DnsPacketSnapshot),
    SipInvite(SipMessageSnapshot),
    HttpsHandshake(TlsHandshakeSnapshot),
    WebRtc(WebRtcDataChannelSnapshot),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSnapshot {
    pub flavor: ProtocolFlavor,
    pub mimicry: ProtocolMimicry,
    pub amnesia: AmnesiaSignature,
    pub daita: DaitaProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicHandshakeSnapshot {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token_length: u8,
    pub alpn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPacketSnapshot {
    pub transaction_id: u16,
    pub qname: String,
    pub qtype: u16,
    pub padding_len: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SipMethod {
    Invite,
    Register,
    Options,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipMessageSnapshot {
    pub call_id: String,
    pub cseq: u32,
    pub method: SipMethod,
    pub via_branch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityTicket {
    pub server_name: String,
    pub fingerprint: [u8; 32],
    pub issued_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsHandshakeSnapshot {
    pub sni: String,
    pub cipher_suites: Vec<u16>,
    pub grease: u16,
    pub alpn: Vec<String>,
    pub reality: Option<RealityTicket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebRtcDataChannelSnapshot {
    pub stream_id: u16,
    pub label: String,
    pub ordered: bool,
    pub reliability: u8,
    pub srtp_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmnesiaSignature {
    pub salt: [u8; 8],
    pub jitter_ns: u32,
    pub packet_mask: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaitaProfile {
    pub automaton_state: u8,
    pub acceptance_probability: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameHeader {
    pub channel_id: u64,
    pub sequence: u64,
    pub frame_type: FrameType,
}

impl FrameHeader {
    pub fn from_frame(frame: &Frame) -> Self {
        Self {
            channel_id: frame.channel_id,
            sequence: frame.sequence,
            frame_type: frame.frame_type,
        }
    }

    fn matches(&self, frame: &Frame) -> bool {
        self.channel_id == frame.channel_id
            && self.sequence == frame.sequence
            && self.frame_type == frame.frame_type
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscatedPacket {
    pub random_prefix_s1: Vec<u8>,
    pub protocol_snapshot: ProtocolSnapshot,
    pub original_header: FrameHeader,
    pub payload: Vec<u8>,
    pub random_suffix_s2: Vec<u8>,
    pub integrity_mac: [u8; MAC_OUTPUT_LEN],
}

impl ObfuscatedPacket {
    pub fn encode(&self) -> Result<Vec<u8>, ObfuscationError> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ObfuscationError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn into_frame(&self, key: &ObfuscationKey) -> Result<Frame, ObfuscationError> {
        key.verify(self)
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolWeight {
    flavor: ProtocolFlavor,
    weight: f32,
}

#[derive(Debug, Clone)]
pub struct AdaptiveMimicPolicy {
    prefix_range: RangeInclusive<usize>,
    suffix_range: RangeInclusive<usize>,
    baseline: Vec<ProtocolWeight>,
    weights: Vec<ProtocolWeight>,
}

impl AdaptiveMimicPolicy {
    pub fn default() -> Self {
        let baseline = vec![
            ProtocolWeight::new(ProtocolFlavor::HttpsHandshake, 3.0),
            ProtocolWeight::new(ProtocolFlavor::QuicInitial, 2.2),
            ProtocolWeight::new(ProtocolFlavor::WebRtc, 1.8),
            ProtocolWeight::new(ProtocolFlavor::DnsQuery, 1.0),
            ProtocolWeight::new(ProtocolFlavor::SipInvite, 0.8),
        ];
        Self {
            prefix_range: 0..=48,
            suffix_range: 0..=48,
            weights: baseline.clone(),
            baseline,
        }
    }

    pub fn record_signal(&mut self, signal: CensorshipSignal) {
        self.weights = match signal {
            CensorshipSignal::None => self.baseline.clone(),
            CensorshipSignal::SuspectedDpi => vec![
                ProtocolWeight::new(ProtocolFlavor::HttpsHandshake, 4.5),
                ProtocolWeight::new(ProtocolFlavor::WebRtc, 3.2),
                ProtocolWeight::new(ProtocolFlavor::QuicInitial, 1.4),
                ProtocolWeight::new(ProtocolFlavor::DnsQuery, 0.6),
                ProtocolWeight::new(ProtocolFlavor::SipInvite, 0.4),
            ],
            CensorshipSignal::HardBlock => vec![
                ProtocolWeight::new(ProtocolFlavor::DnsQuery, 3.8),
                ProtocolWeight::new(ProtocolFlavor::SipInvite, 2.5),
                ProtocolWeight::new(ProtocolFlavor::QuicInitial, 1.2),
                ProtocolWeight::new(ProtocolFlavor::HttpsHandshake, 1.0),
                ProtocolWeight::new(ProtocolFlavor::WebRtc, 0.8),
            ],
        };
    }

    pub fn sample_snapshot<R: Rng + ?Sized>(&self, rng: &mut R) -> ProtocolSnapshot {
        let total: f32 = self.weights.iter().map(|w| w.weight).sum();
        let mut draw = rng.gen::<f32>() * total;
        let flavor = self
            .weights
            .iter()
            .find_map(|weight| {
                if draw <= weight.weight {
                    Some(weight.flavor)
                } else {
                    draw -= weight.weight;
                    None
                }
            })
            .unwrap_or(ProtocolFlavor::HttpsHandshake);
        ProtocolSnapshot::random(flavor, rng)
    }

    pub fn prefix_len<R: Rng + ?Sized>(&self, rng: &mut R) -> usize {
        rng.gen_range(self.prefix_range.clone())
    }

    pub fn suffix_len<R: Rng + ?Sized>(&self, rng: &mut R) -> usize {
        rng.gen_range(self.suffix_range.clone())
    }
}

impl ProtocolWeight {
    fn new(flavor: ProtocolFlavor, weight: f32) -> Self {
        Self { flavor, weight }
    }
}

#[derive(Debug, Clone)]
pub struct ObfuscationKey {
    mac_key: [u8; MAC_KEY_LEN],
}

impl ObfuscationKey {
    pub fn from_bytes(bytes: [u8; MAC_KEY_LEN]) -> Self {
        Self { mac_key: bytes }
    }

    pub fn derive(label: &str, seed: &[u8]) -> Self {
        let mut output = [0u8; MAC_KEY_LEN];
        let derived = blake3::derive_key(label, seed);
        output.copy_from_slice(&derived);
        Self { mac_key: output }
    }

    pub fn verify(&self, packet: &ObfuscatedPacket) -> Result<Frame, ObfuscationError> {
        let expected = compute_mac(
            &self.mac_key,
            &packet.random_prefix_s1,
            &packet.protocol_snapshot,
            &packet.original_header,
            &packet.payload,
            &packet.random_suffix_s2,
        )?;
        if expected != packet.integrity_mac {
            return Err(ObfuscationError::Integrity);
        }
        let (frame, used) = Frame::decode(&packet.payload)?;
        if used != packet.payload.len() {
            return Err(ObfuscationError::Codec(CodecError::UnexpectedEof));
        }
        if !packet.original_header.matches(&frame) {
            return Err(ObfuscationError::HeaderMismatch);
        }
        Ok(frame)
    }
}

#[derive(Debug)]
pub struct AdaptiveObfuscator<R> {
    key: ObfuscationKey,
    policy: AdaptiveMimicPolicy,
    rng: R,
}

impl<R> AdaptiveObfuscator<R>
where
    R: CryptoRng + RngCore,
{
    pub fn new(key: ObfuscationKey, rng: R) -> Self {
        Self {
            key,
            policy: AdaptiveMimicPolicy::default(),
            rng,
        }
    }

    pub fn with_policy(key: ObfuscationKey, policy: AdaptiveMimicPolicy, rng: R) -> Self {
        Self { key, policy, rng }
    }

    pub fn policy(&self) -> &AdaptiveMimicPolicy {
        &self.policy
    }

    pub fn update_signal(&mut self, signal: CensorshipSignal) {
        self.policy.record_signal(signal);
    }

    pub fn wrap_frame(&mut self, frame: &Frame) -> Result<ObfuscatedPacket, ObfuscationError> {
        let prefix_len = self.policy.prefix_len(&mut self.rng);
        let suffix_len = self.policy.suffix_len(&mut self.rng);
        let mut prefix = vec![0u8; prefix_len];
        let mut suffix = vec![0u8; suffix_len];
        self.rng.fill_bytes(&mut prefix);
        self.rng.fill_bytes(&mut suffix);
        let snapshot = self.policy.sample_snapshot(&mut self.rng);
        let payload = frame.encode()?;
        let header = FrameHeader::from_frame(frame);
        let mac = compute_mac(
            &self.key.mac_key,
            &prefix,
            &snapshot,
            &header,
            &payload,
            &suffix,
        )?;
        Ok(ObfuscatedPacket {
            random_prefix_s1: prefix,
            protocol_snapshot: snapshot,
            original_header: header,
            payload,
            random_suffix_s2: suffix,
            integrity_mac: mac,
        })
    }

    pub fn unwrap_packet(&self, packet: &ObfuscatedPacket) -> Result<Frame, ObfuscationError> {
        self.key.verify(packet)
    }
}

impl ProtocolSnapshot {
    fn random<R: Rng + ?Sized>(flavor: ProtocolFlavor, rng: &mut R) -> Self {
        let amnesia = AmnesiaSignature::random(rng);
        let daita = DaitaProfile::random(rng);
        let mimicry = match flavor {
            ProtocolFlavor::QuicInitial => {
                ProtocolMimicry::QuicInitial(QuicHandshakeSnapshot::random(rng))
            }
            ProtocolFlavor::DnsQuery => ProtocolMimicry::DnsQuery(DnsPacketSnapshot::random(rng)),
            ProtocolFlavor::SipInvite => {
                ProtocolMimicry::SipInvite(SipMessageSnapshot::random(rng))
            }
            ProtocolFlavor::HttpsHandshake => {
                ProtocolMimicry::HttpsHandshake(TlsHandshakeSnapshot::random(rng))
            }
            ProtocolFlavor::WebRtc => {
                ProtocolMimicry::WebRtc(WebRtcDataChannelSnapshot::random(rng))
            }
        };
        Self {
            flavor,
            mimicry,
            amnesia,
            daita,
        }
    }
}

impl QuicHandshakeSnapshot {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let version_pool = [0xff00_0001u32, 1, 0xff00_0003];
        let version = *version_pool.choose(rng).unwrap_or(&1);
        let dcid_len = rng.gen_range(8..=20);
        let scid_len = rng.gen_range(8..=20);
        let mut dcid = vec![0u8; dcid_len];
        let mut scid = vec![0u8; scid_len];
        rng.fill_bytes(&mut dcid);
        rng.fill_bytes(&mut scid);
        let token_length = rng.gen_range(0..=24);
        let alpns = ["h3", "hq-interop", "quic-transport", "doq"];
        let alpn = alpns
            .choose(rng)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "h3".to_string());
        Self {
            version,
            dcid,
            scid,
            token_length,
            alpn,
        }
    }
}

impl DnsPacketSnapshot {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let transaction_id = rng.gen();
        let qname = random_domain(rng);
        let qtype_pool = [1u16, 15, 28, 16];
        let qtype = *qtype_pool.choose(rng).unwrap_or(&1);
        let padding_len = rng.gen_range(0..=64);
        Self {
            transaction_id,
            qname,
            qtype,
            padding_len,
        }
    }
}

impl SipMessageSnapshot {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let call_id = random_hex(rng, 12);
        let cseq = rng.gen_range(1..=65535);
        let methods = [SipMethod::Invite, SipMethod::Register, SipMethod::Options];
        let method = *methods.choose(rng).unwrap_or(&SipMethod::Invite);
        let via_branch = format!("z9hG4bK{}", random_hex(rng, 8));
        Self {
            call_id,
            cseq,
            method,
            via_branch,
        }
    }
}

impl TlsHandshakeSnapshot {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let sni = random_domain(rng);
        let cipher_catalog: Vec<u16> = vec![
            0x1301, 0x1302, 0x1303, 0xcca8, 0xcca9, 0xcca7, 0x009c, 0x009d,
        ];
        let suite_count = rng.gen_range(3..=cipher_catalog.len().min(6));
        let mut suites = cipher_catalog.clone();
        suites.shuffle(rng);
        suites.truncate(suite_count);
        let grease_values = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a];
        let grease = *grease_values.choose(rng).unwrap_or(&0x0a0a);
        let alpn_options = vec!["h3", "h2", "http/1.1", "dot"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let mut alpn = Vec::new();
        for candidate in &alpn_options {
            if rng.gen_bool(0.6) {
                alpn.push(candidate.clone());
            }
        }
        if alpn.is_empty() {
            alpn.push("h2".to_string());
        }
        let reality = if rng.gen_bool(0.45) {
            Some(RealityTicket::random(rng))
        } else {
            None
        };
        Self {
            sni,
            cipher_suites: suites,
            grease,
            alpn,
            reality,
        }
    }
}

impl RealityTicket {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let hosts = [
            "cdn.cloudflare.com",
            "www.cloudflare-dns.com",
            "discord.com",
            "assets-cdn.github.com",
            "www.google.com",
        ];
        let server_name = hosts
            .choose(rng)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "cdn.cloudflare.com".to_string());
        let mut fingerprint = [0u8; 32];
        rng.fill_bytes(&mut fingerprint);
        let issued_at = rng.gen_range(1_700_000_000u64..=1_900_000_000);
        Self {
            server_name,
            fingerprint,
            issued_at,
        }
    }
}

impl WebRtcDataChannelSnapshot {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let stream_id = rng.gen();
        let label_length = rng.gen_range(4..=12);
        let label = Alphanumeric.sample_string(rng, label_length);
        let ordered = rng.gen_bool(0.7);
        let reliability = if ordered { 0 } else { rng.gen_range(1..=3) };
        let srtp_profiles = ["UDP/TLS/RTP/SAVPF", "UDP/DTLS/SCTP", "RTP/SAVP"];
        let srtp_profile = srtp_profiles
            .choose(rng)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "UDP/TLS/RTP/SAVPF".to_string());
        Self {
            stream_id,
            label,
            ordered,
            reliability,
            srtp_profile,
        }
    }
}

impl AmnesiaSignature {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut salt = [0u8; 8];
        rng.fill_bytes(&mut salt);
        let jitter_ns = rng.gen_range(50_000..=5_000_000);
        let packet_mask = rng.gen();
        Self {
            salt,
            jitter_ns,
            packet_mask,
        }
    }
}

impl DaitaProfile {
    fn random<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let automaton_state = rng.gen_range(0..=7);
        let probability = Uniform::new_inclusive(0.45f32, 0.95f32).sample(rng);
        Self {
            automaton_state,
            acceptance_probability: probability,
        }
    }
}

fn compute_mac(
    key: &[u8; MAC_KEY_LEN],
    prefix: &[u8],
    snapshot: &ProtocolSnapshot,
    header: &FrameHeader,
    payload: &[u8],
    suffix: &[u8],
) -> Result<[u8; MAC_OUTPUT_LEN], ObfuscationError> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(prefix);
    buffer.extend_from_slice(&serde_json::to_vec(snapshot)?);
    buffer.extend_from_slice(&serde_json::to_vec(header)?);
    buffer.extend_from_slice(payload);
    buffer.extend_from_slice(suffix);
    let hash = keyed_hash(key, &buffer);
    let mut mac = [0u8; MAC_OUTPUT_LEN];
    mac.copy_from_slice(&hash.as_bytes()[..MAC_OUTPUT_LEN]);
    Ok(mac)
}

fn random_domain<R: Rng + ?Sized>(rng: &mut R) -> String {
    let prefixes = ["cdn", "api", "img", "edge", "static", "data"];
    let middles = ["cloud", "global", "mesh", "relay", "signal", "atlas"];
    let tlds = ["com", "net", "org", "io", "app", "cloud"];
    format!(
        "{}.{}.{}",
        prefixes.choose(rng).unwrap_or(&"cdn"),
        middles.choose(rng).unwrap_or(&"mesh"),
        tlds.choose(rng).unwrap_or(&"net")
    )
}

fn random_hex<R: Rng + ?Sized>(rng: &mut R, len: usize) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    (0..len)
        .map(|_| {
            let index = rng.gen_range(0..HEX.len());
            HEX[index] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FramePayload;
    use rand::{rngs::StdRng, SeedableRng};
    use serde_json::json;

    fn sample_frame() -> Frame {
        Frame {
            channel_id: 7,
            sequence: 42,
            frame_type: FrameType::Msg,
            payload: FramePayload::Opaque(vec![1, 2, 3, 4, 5]),
        }
    }

    #[test]
    fn wrap_and_unwrap_roundtrip() {
        let key = ObfuscationKey::derive("commucat.obf", b"seed");
        let rng = StdRng::seed_from_u64(1);
        let mut obfuscator = AdaptiveObfuscator::new(key, rng);
        let frame = sample_frame();
        let packet = obfuscator.wrap_frame(&frame).unwrap();
        let restored = obfuscator.unwrap_packet(&packet).unwrap();
        assert_eq!(restored.channel_id, frame.channel_id);
        assert_eq!(restored.sequence, frame.sequence);
        match (restored.payload, frame.payload) {
            (FramePayload::Opaque(a), FramePayload::Opaque(b)) => assert_eq!(a, b),
            _ => panic!("unexpected payload variant"),
        }
    }

    #[test]
    fn tampered_payload_is_detected() {
        let key = ObfuscationKey::derive("commucat.obf", b"seed");
        let rng = StdRng::seed_from_u64(7);
        let mut obfuscator = AdaptiveObfuscator::new(key, rng);
        let frame = sample_frame();
        let mut packet = obfuscator.wrap_frame(&frame).unwrap();
        packet.payload[0] ^= 0xff;
        let err = obfuscator.unwrap_packet(&packet).unwrap_err();
        assert!(matches!(err, ObfuscationError::Integrity));
    }

    #[test]
    fn packet_serialization_roundtrip() {
        let key = ObfuscationKey::derive("commucat.obf", b"seed");
        let rng = StdRng::seed_from_u64(11);
        let mut obfuscator = AdaptiveObfuscator::new(key, rng);
        let frame = Frame {
            channel_id: 3,
            sequence: 1,
            frame_type: FrameType::Presence,
            payload: FramePayload::Control(crate::ControlEnvelope {
                properties: json!({ "state": "online" }),
            }),
        };
        let packet = obfuscator.wrap_frame(&frame).unwrap();
        let encoded = packet.encode().unwrap();
        let decoded = ObfuscatedPacket::decode(&encoded).unwrap();
        let restored = obfuscator.unwrap_packet(&decoded).unwrap();
        assert_eq!(restored.channel_id, frame.channel_id);
    }
}
