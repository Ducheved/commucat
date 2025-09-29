use crate::{CodecError, ControlEnvelope};
use commucat_media_types::{
    AudioCodec, AudioCodecDescriptor, HardwareAcceleration, MediaCapabilities, MediaSourceMode,
    VideoCodec, VideoCodecDescriptor, VideoResolution,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CallMode {
    #[default]
    FullDuplex,
    HalfDuplex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioParameters {
    pub codec: AudioCodec,
    pub bitrate: u32,
    pub sample_rate: u32,
    pub channels: u8,
    #[serde(default)]
    pub fec: bool,
    #[serde(default)]
    pub dtx: bool,
    #[serde(default)]
    pub source: MediaSourceMode,
    #[serde(default)]
    pub preferred_codecs: Vec<AudioCodec>,
    #[serde(default)]
    pub available_codecs: Vec<AudioCodecDescriptor>,
    #[serde(default)]
    pub allow_passthrough: bool,
}

impl Default for AudioParameters {
    fn default() -> Self {
        AudioParameters {
            codec: AudioCodec::Opus,
            bitrate: 16_000,
            sample_rate: 48_000,
            channels: 1,
            fec: true,
            dtx: true,
            source: MediaSourceMode::Raw,
            preferred_codecs: vec![AudioCodec::Opus],
            available_codecs: vec![AudioCodecDescriptor::default()],
            allow_passthrough: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoParameters {
    pub codec: VideoCodec,
    pub max_bitrate: u32,
    pub max_resolution: VideoResolution,
    pub frame_rate: u8,
    #[serde(default)]
    pub adaptive: bool,
    #[serde(default)]
    pub source: MediaSourceMode,
    #[serde(default)]
    pub preferred_codecs: Vec<VideoCodec>,
    #[serde(default)]
    pub available_codecs: Vec<VideoCodecDescriptor>,
    #[serde(default)]
    pub hardware: Vec<HardwareAcceleration>,
    #[serde(default)]
    pub allow_passthrough: bool,
    #[serde(default)]
    pub capabilities: Option<MediaCapabilities>,
}

impl Default for VideoParameters {
    fn default() -> Self {
        VideoParameters {
            codec: VideoCodec::Vp8,
            max_bitrate: 750_000,
            max_resolution: VideoResolution::default(),
            frame_rate: 24,
            adaptive: true,
            source: MediaSourceMode::Raw,
            preferred_codecs: vec![VideoCodec::Vp8],
            available_codecs: vec![VideoCodecDescriptor::default()],
            hardware: vec![HardwareAcceleration::Cpu],
            allow_passthrough: true,
            capabilities: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallMediaProfile {
    pub audio: AudioParameters,
    #[serde(default)]
    pub video: Option<VideoParameters>,
    #[serde(default)]
    pub mode: CallMode,
    #[serde(default)]
    pub capabilities: Option<MediaCapabilities>,
}

impl Default for CallMediaProfile {
    fn default() -> Self {
        CallMediaProfile {
            audio: AudioParameters::default(),
            video: None,
            mode: CallMode::FullDuplex,
            capabilities: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    #[default]
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IceCandidateType {
    Host,
    Srflx,
    Prflx,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IceTcpCandidateType {
    Active,
    Passive,
    So,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCredentials {
    pub username_fragment: String,
    pub password: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCandidate {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: TransportProtocol,
    #[serde(default)]
    pub foundation: Option<String>,
    #[serde(default)]
    pub component: Option<u8>,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub candidate_type: Option<IceCandidateType>,
    #[serde(default)]
    pub related_address: Option<String>,
    #[serde(default)]
    pub related_port: Option<u16>,
    #[serde(default)]
    pub tcp_type: Option<IceTcpCandidateType>,
    #[serde(default)]
    pub sdp_mid: Option<String>,
    #[serde(default)]
    pub sdp_mline_index: Option<u16>,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CallTransport {
    #[serde(default)]
    pub prefer_relay: bool,
    #[serde(default, alias = "udp_candidates")]
    pub candidates: Vec<TransportCandidate>,
    #[serde(default)]
    pub fingerprints: Vec<String>,
    #[serde(default)]
    pub ice_credentials: Option<IceCredentials>,
    #[serde(default)]
    pub trickle: bool,
    #[serde(default)]
    pub consent_interval_secs: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCandidateRef {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: TransportProtocol,
    #[serde(default)]
    pub candidate_type: Option<IceCandidateType>,
    #[serde(default)]
    pub foundation: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallTransportUpdate {
    pub call_id: String,
    #[serde(flatten)]
    pub payload: TransportUpdatePayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "update", rename_all = "snake_case")]
pub enum TransportUpdatePayload {
    Candidate {
        candidate: TransportCandidate,
    },
    SelectedCandidatePair {
        local: TransportCandidateRef,
        remote: TransportCandidateRef,
        #[serde(default)]
        rtt_ms: Option<u32>,
    },
    ConsentKeepalive {
        #[serde(default)]
        interval_secs: Option<u16>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallOffer {
    pub call_id: String,
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub media: CallMediaProfile,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
    #[serde(default)]
    pub transport: Option<CallTransport>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub ephemeral_key: Option<String>,
}

fn default_metadata() -> Value {
    Value::Null
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallAnswer {
    pub call_id: String,
    pub accept: bool,
    #[serde(default)]
    pub media: Option<CallMediaProfile>,
    #[serde(default)]
    pub transport: Option<CallTransport>,
    #[serde(default)]
    pub reason: Option<CallRejectReason>,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
    #[serde(default)]
    pub selected_audio_codec: Option<AudioCodec>,
    #[serde(default)]
    pub selected_video_codec: Option<VideoCodec>,
    #[serde(default)]
    pub audio_source: Option<MediaSourceMode>,
    #[serde(default)]
    pub video_source: Option<MediaSourceMode>,
    #[serde(default)]
    pub video_hardware: Option<HardwareAcceleration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallRejectReason {
    Busy,
    Decline,
    Unsupported,
    Timeout,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallEnd {
    pub call_id: String,
    pub reason: CallEndReason,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallEndReason {
    Hangup,
    Cancel,
    Failure,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallMediaDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaStreamStats {
    pub bitrate: u32,
    #[serde(default)]
    pub packet_loss: f32,
    #[serde(default)]
    pub jitter_ms: u32,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub frames_per_second: Option<u8>,
    #[serde(default)]
    pub key_frames: Option<u32>,
    #[serde(default)]
    pub codec: Option<String>,
    #[serde(default)]
    pub source: Option<MediaSourceMode>,
    #[serde(default)]
    pub hardware: Option<HardwareAcceleration>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallStats {
    pub call_id: String,
    pub direction: CallMediaDirection,
    #[serde(default)]
    pub audio: Option<MediaStreamStats>,
    #[serde(default)]
    pub video: Option<MediaStreamStats>,
    #[serde(default)]
    pub timestamp: Option<u64>,
}

fn encode_control<T: Serialize>(value: T) -> Result<ControlEnvelope, CodecError> {
    serde_json::to_value(value)
        .map(|properties| ControlEnvelope { properties })
        .map_err(|_| CodecError::InvalidControlJson)
}

fn decode_control<T: DeserializeOwned>(envelope: &ControlEnvelope) -> Result<T, CodecError> {
    serde_json::from_value(envelope.properties.clone()).map_err(|_| CodecError::InvalidControlJson)
}

macro_rules! impl_control_codec {
    ($ty:ty) => {
        impl TryFrom<$ty> for ControlEnvelope {
            type Error = CodecError;

            fn try_from(value: $ty) -> Result<Self, Self::Error> {
                encode_control(value)
            }
        }

        impl TryFrom<&$ty> for ControlEnvelope {
            type Error = CodecError;

            fn try_from(value: &$ty) -> Result<Self, Self::Error> {
                encode_control(value)
            }
        }

        impl TryFrom<&ControlEnvelope> for $ty {
            type Error = CodecError;

            fn try_from(envelope: &ControlEnvelope) -> Result<Self, Self::Error> {
                decode_control::<$ty>(envelope)
            }
        }
    };
}

impl_control_codec!(CallOffer);
impl_control_codec!(CallAnswer);
impl_control_codec!(CallEnd);
impl_control_codec!(CallStats);
impl_control_codec!(CallTransportUpdate);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlEnvelope;
    use commucat_media_types::CodecPriority;

    #[test]
    fn offer_roundtrip() {
        let offer = CallOffer {
            call_id: "call-123".to_string(),
            from: "alice:device".to_string(),
            to: vec!["bob:device".to_string()],
            media: CallMediaProfile {
                audio: AudioParameters {
                    codec: AudioCodec::Opus,
                    bitrate: 24_000,
                    sample_rate: 48_000,
                    channels: 1,
                    fec: true,
                    dtx: false,
                    source: MediaSourceMode::Raw,
                    preferred_codecs: vec![AudioCodec::Opus, AudioCodec::RawPcm],
                    available_codecs: vec![
                        AudioCodecDescriptor {
                            codec: AudioCodec::Opus,
                            bitrate: Some(32_000),
                            sample_rate: Some(48_000),
                            channels: Some(1),
                            priority: CodecPriority(120),
                        },
                        AudioCodecDescriptor {
                            codec: AudioCodec::RawPcm,
                            bitrate: Some(1_536_000),
                            sample_rate: Some(48_000),
                            channels: Some(2),
                            priority: CodecPriority(60),
                        },
                    ],
                    allow_passthrough: true,
                },
                video: Some(VideoParameters {
                    codec: VideoCodec::Vp8,
                    max_bitrate: 350_000,
                    max_resolution: VideoResolution::new(640, 360),
                    frame_rate: 20,
                    adaptive: true,
                    source: MediaSourceMode::Raw,
                    preferred_codecs: vec![VideoCodec::Vp8, VideoCodec::H264Baseline],
                    available_codecs: vec![
                        VideoCodecDescriptor {
                            codec: VideoCodec::Vp8,
                            max_bitrate: Some(350_000),
                            max_resolution: Some(VideoResolution::new(640, 360)),
                            frame_rate: Some(25),
                            hardware: vec![HardwareAcceleration::Cpu],
                            priority: CodecPriority(110),
                            supports_scalability: true,
                        },
                        VideoCodecDescriptor {
                            codec: VideoCodec::H264Baseline,
                            max_bitrate: Some(1_000_000),
                            max_resolution: Some(VideoResolution::new(1280, 720)),
                            frame_rate: Some(30),
                            hardware: vec![
                                HardwareAcceleration::Nvidia,
                                HardwareAcceleration::Intel,
                            ],
                            priority: CodecPriority(80),
                            supports_scalability: false,
                        },
                    ],
                    hardware: vec![HardwareAcceleration::Cpu, HardwareAcceleration::Nvidia],
                    allow_passthrough: true,
                    capabilities: Some(MediaCapabilities {
                        audio: vec![],
                        video: vec![VideoCodecDescriptor::default()],
                        allow_raw_audio: false,
                        allow_raw_video: true,
                    }),
                }),
                mode: CallMode::FullDuplex,
                capabilities: Some(MediaCapabilities {
                    audio: vec![AudioCodecDescriptor::default()],
                    video: vec![VideoCodecDescriptor::default()],
                    allow_raw_audio: true,
                    allow_raw_video: true,
                }),
            },
            metadata: serde_json::json!({"mode": "voice"}),
            transport: Some(CallTransport {
                prefer_relay: false,
                candidates: vec![TransportCandidate {
                    address: "203.0.113.10".to_string(),
                    port: 3478,
                    protocol: TransportProtocol::Udp,
                    foundation: Some("foundation-1".to_string()),
                    component: Some(1),
                    priority: Some(1_234_567),
                    candidate_type: Some(IceCandidateType::Srflx),
                    related_address: Some("10.0.0.5".to_string()),
                    related_port: Some(52_333),
                    tcp_type: None,
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    url: Some("stun:stun.commucat".to_string()),
                }],
                fingerprints: vec!["abc123".to_string()],
                ice_credentials: Some(IceCredentials {
                    username_fragment: "ufrag".to_string(),
                    password: "secret".to_string(),
                    expires_at: Some(1_700_000_600),
                }),
                trickle: true,
                consent_interval_secs: Some(20),
            }),
            expires_at: Some(1_700_000_000),
            ephemeral_key: Some("feedface".to_string()),
        };
        let envelope: ControlEnvelope = (&offer).try_into().expect("encode");
        let decoded = CallOffer::try_from(&envelope).expect("decode");
        assert_eq!(decoded.call_id, offer.call_id);
        let transport = decoded.transport.as_ref().expect("transport");
        assert_eq!(transport.candidates.len(), 1);
        assert_eq!(
            transport
                .ice_credentials
                .as_ref()
                .expect("credentials")
                .username_fragment,
            "ufrag"
        );
        assert_eq!(
            decoded
                .media
                .audio
                .available_codecs
                .iter()
                .filter(|desc| desc.codec == AudioCodec::RawPcm)
                .count(),
            1
        );
        assert_eq!(decoded.media.audio.preferred_codecs[0], AudioCodec::Opus);
        assert_eq!(
            decoded
                .media
                .video
                .as_ref()
                .and_then(|video| video.preferred_codecs.first())
                .copied(),
            Some(VideoCodec::Vp8)
        );
    }

    #[test]
    fn transport_update_roundtrip() {
        let candidate = TransportCandidate {
            address: "198.51.100.12".to_string(),
            port: 60_000,
            protocol: TransportProtocol::Udp,
            foundation: Some("f1".to_string()),
            component: Some(1),
            priority: Some(12_345_678),
            candidate_type: Some(IceCandidateType::Srflx),
            related_address: Some("10.0.0.5".to_string()),
            related_port: Some(52_333),
            tcp_type: None,
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
            url: None,
        };
        let update = CallTransportUpdate {
            call_id: "call-xyz".to_string(),
            payload: TransportUpdatePayload::Candidate {
                candidate: candidate.clone(),
            },
        };
        let envelope: ControlEnvelope = (&update).try_into().expect("encode");
        let decoded = CallTransportUpdate::try_from(&envelope).expect("decode");
        assert_eq!(decoded.call_id, update.call_id);
        match decoded.payload {
            TransportUpdatePayload::Candidate {
                candidate: ref decoded_candidate,
            } => {
                assert_eq!(decoded_candidate.address, candidate.address);
                assert_eq!(decoded_candidate.priority, candidate.priority);
            }
            other => panic!("unexpected payload: {:?}", other),
        }

        let selected = CallTransportUpdate {
            call_id: "call-xyz".to_string(),
            payload: TransportUpdatePayload::SelectedCandidatePair {
                local: TransportCandidateRef {
                    address: "10.0.0.5".to_string(),
                    port: 52_333,
                    protocol: TransportProtocol::Udp,
                    candidate_type: Some(IceCandidateType::Srflx),
                    foundation: Some("f1".to_string()),
                    priority: Some(7_654_321),
                },
                remote: TransportCandidateRef {
                    address: "203.0.113.4".to_string(),
                    port: 60_000,
                    protocol: TransportProtocol::Udp,
                    candidate_type: Some(IceCandidateType::Srflx),
                    foundation: Some("f2".to_string()),
                    priority: Some(9_999_999),
                },
                rtt_ms: Some(22),
            },
        };
        let envelope: ControlEnvelope = (&selected).try_into().expect("encode selected");
        let decoded = CallTransportUpdate::try_from(&envelope).expect("decode selected");
        assert_eq!(decoded.call_id, selected.call_id);
        match decoded.payload {
            TransportUpdatePayload::SelectedCandidatePair { rtt_ms, .. } => {
                assert_eq!(rtt_ms, Some(22));
            }
            _ => panic!("unexpected payload kind"),
        }
    }

    #[test]
    fn answer_reject_roundtrip() {
        let answer = CallAnswer {
            call_id: "call-999".to_string(),
            accept: false,
            media: None,
            transport: None,
            reason: Some(CallRejectReason::Busy),
            metadata: Value::Null,
            selected_audio_codec: None,
            selected_video_codec: None,
            audio_source: None,
            video_source: None,
            video_hardware: None,
        };
        let envelope: ControlEnvelope = (&answer).try_into().expect("encode");
        let decoded = CallAnswer::try_from(&envelope).expect("decode");
        assert!(!decoded.accept);
        assert_eq!(decoded.reason, Some(CallRejectReason::Busy));
        assert!(decoded.selected_audio_codec.is_none());
    }

    #[test]
    fn answer_accept_with_selection_roundtrip() {
        let answer = CallAnswer {
            call_id: "call-555".to_string(),
            accept: true,
            media: None,
            transport: None,
            reason: None,
            metadata: Value::Null,
            selected_audio_codec: Some(AudioCodec::Opus),
            selected_video_codec: Some(VideoCodec::Av1Main),
            audio_source: Some(MediaSourceMode::Encoded),
            video_source: Some(MediaSourceMode::Raw),
            video_hardware: Some(HardwareAcceleration::Nvidia),
        };
        let envelope: ControlEnvelope = (&answer).try_into().expect("encode");
        let decoded = CallAnswer::try_from(&envelope).expect("decode");
        assert!(decoded.accept);
        assert_eq!(decoded.selected_video_codec, Some(VideoCodec::Av1Main));
        assert_eq!(decoded.video_hardware, Some(HardwareAcceleration::Nvidia));
    }

    #[test]
    fn stats_roundtrip() {
        let stats = CallStats {
            call_id: "call-1".to_string(),
            direction: CallMediaDirection::Send,
            audio: Some(MediaStreamStats {
                bitrate: 18_000,
                packet_loss: 0.012,
                jitter_ms: 8,
                rtt_ms: Some(90),
                frames_per_second: None,
                key_frames: None,
                codec: Some("opus".to_string()),
                source: Some(MediaSourceMode::Encoded),
                hardware: None,
            }),
            video: Some(MediaStreamStats {
                bitrate: 600_000,
                packet_loss: 0.03,
                jitter_ms: 15,
                rtt_ms: Some(120),
                frames_per_second: Some(30),
                key_frames: Some(4),
                codec: Some("av1".to_string()),
                source: Some(MediaSourceMode::Raw),
                hardware: Some(HardwareAcceleration::Nvidia),
            }),
            timestamp: Some(1_690_000_000),
        };
        let envelope: ControlEnvelope = (&stats).try_into().expect("encode");
        let decoded = CallStats::try_from(&envelope).expect("decode");
        assert_eq!(decoded.audio.as_ref().unwrap().bitrate, 18_000);
        assert_eq!(
            decoded.video.as_ref().unwrap().hardware,
            Some(HardwareAcceleration::Nvidia)
        );
    }
}
