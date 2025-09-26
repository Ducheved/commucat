use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};

pub mod call;

#[cfg(feature = "obfuscation")]
mod obfuscation;

#[cfg(feature = "obfuscation")]
pub use obfuscation::{
    AdaptiveMimicPolicy, AdaptiveObfuscator, AmnesiaSignature, CensorshipSignal, DaitaProfile,
    DnsPacketSnapshot, ObfuscatedPacket, ObfuscationError, ObfuscationKey, ProtocolFlavor,
    ProtocolMimicry, ProtocolSnapshot, QuicHandshakeSnapshot, RealityTicket, SipMessageSnapshot,
    SipMethod, TlsHandshakeSnapshot, WebRtcDataChannelSnapshot,
};

pub const PROTOCOL_VERSION: u16 = 1;
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u16] = &[PROTOCOL_VERSION];
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;
pub const MAX_CONTROL_JSON_LEN: usize = 256 * 1024;
pub const MAX_CHANNEL_ID: u64 = u32::MAX as u64;
pub const MAX_SEQUENCE: u64 = u32::MAX as u64;

/// Returns true when the provided protocol version is supported by the current codec.
pub fn is_supported_protocol_version(version: u16) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .any(|v| v == version)
}

/// Picks the highest mutually supported protocol version between peers.
pub fn negotiate_protocol_version(peer_versions: &[u16]) -> Option<u16> {
    let mut negotiated = None;
    for version in peer_versions.iter().copied() {
        if is_supported_protocol_version(version) {
            negotiated = match negotiated {
                Some(current) if current >= version => Some(current),
                _ => Some(version),
            };
        }
    }
    negotiated
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrameType {
    Hello = 0x01,
    Auth = 0x02,
    Join = 0x03,
    Leave = 0x04,
    Msg = 0x05,
    Ack = 0x06,
    Typing = 0x07,
    Presence = 0x08,
    KeyUpdate = 0x09,
    GroupCreate = 0x0a,
    GroupInvite = 0x0b,
    GroupEvent = 0x0c,
    Error = 0x0d,
    CallOffer = 0x0e,
    CallAnswer = 0x0f,
    CallEnd = 0x10,
    VoiceFrame = 0x11,
    VideoFrame = 0x12,
    CallStats = 0x13,
}

impl FrameType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::Auth),
            0x03 => Some(Self::Join),
            0x04 => Some(Self::Leave),
            0x05 => Some(Self::Msg),
            0x06 => Some(Self::Ack),
            0x07 => Some(Self::Typing),
            0x08 => Some(Self::Presence),
            0x09 => Some(Self::KeyUpdate),
            0x0a => Some(Self::GroupCreate),
            0x0b => Some(Self::GroupInvite),
            0x0c => Some(Self::GroupEvent),
            0x0d => Some(Self::Error),
            0x0e => Some(Self::CallOffer),
            0x0f => Some(Self::CallAnswer),
            0x10 => Some(Self::CallEnd),
            0x11 => Some(Self::VoiceFrame),
            0x12 => Some(Self::VideoFrame),
            0x13 => Some(Self::CallStats),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum CodecError {
    InvalidFrameType,
    InvalidControlJson,
    UnexpectedEof,
    VarintOverflow,
    PayloadTooLarge,
    FrameTooLarge,
    ControlTooLarge,
    ChannelIdTooLarge,
    SequenceTooLarge,
}

impl Display for CodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFrameType => write!(f, "invalid frame type"),
            Self::InvalidControlJson => write!(f, "invalid control payload"),
            Self::UnexpectedEof => write!(f, "unexpected end of frame"),
            Self::VarintOverflow => write!(f, "varint overflow"),
            Self::PayloadTooLarge => write!(f, "payload exceeds limits"),
            Self::FrameTooLarge => write!(f, "frame exceeds limits"),
            Self::ControlTooLarge => write!(f, "control payload exceeds limits"),
            Self::ChannelIdTooLarge => write!(f, "channel id exceeds limits"),
            Self::SequenceTooLarge => write!(f, "sequence exceeds limits"),
        }
    }
}

impl Error for CodecError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlEnvelope {
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePayload {
    Control(ControlEnvelope),
    Opaque(Vec<u8>),
}

impl FramePayload {
    fn bytes(&self) -> Result<Cow<'_, [u8]>, CodecError> {
        match self {
            FramePayload::Control(ctrl) => {
                let encoded =
                    serde_json::to_vec(ctrl).map_err(|_| CodecError::InvalidControlJson)?;
                if encoded.len() > MAX_CONTROL_JSON_LEN {
                    return Err(CodecError::ControlTooLarge);
                }
                Ok(Cow::Owned(encoded))
            }
            FramePayload::Opaque(data) => Ok(Cow::Borrowed(data)),
        }
    }

    fn from_bytes(frame_type: FrameType, data: &[u8]) -> Result<Self, CodecError> {
        match frame_type {
            FrameType::Msg
            | FrameType::KeyUpdate
            | FrameType::VoiceFrame
            | FrameType::VideoFrame => Ok(FramePayload::Opaque(data.to_vec())),
            FrameType::Hello
            | FrameType::Auth
            | FrameType::Join
            | FrameType::Leave
            | FrameType::Ack
            | FrameType::Typing
            | FrameType::Presence
            | FrameType::GroupCreate
            | FrameType::GroupInvite
            | FrameType::GroupEvent
            | FrameType::Error
            | FrameType::CallOffer
            | FrameType::CallAnswer
            | FrameType::CallEnd
            | FrameType::CallStats => {
                if data.len() > MAX_CONTROL_JSON_LEN {
                    return Err(CodecError::ControlTooLarge);
                }
                serde_json::from_slice::<ControlEnvelope>(data)
                    .map(FramePayload::Control)
                    .map_err(|_| CodecError::InvalidControlJson)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel_id: u64,
    pub sequence: u64,
    pub frame_type: FrameType,
    pub payload: FramePayload,
}

impl Frame {
    /// Serializes a frame into a length prefixed binary representation.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        if self.channel_id > MAX_CHANNEL_ID {
            return Err(CodecError::ChannelIdTooLarge);
        }
        if self.sequence > MAX_SEQUENCE {
            return Err(CodecError::SequenceTooLarge);
        }
        let payload = self.payload.bytes()?;
        if payload.len() > MAX_FRAME_LEN {
            return Err(CodecError::PayloadTooLarge);
        }
        let mut body = Vec::new();
        body.push(self.frame_type as u8);
        encode_varint(self.channel_id, &mut body);
        encode_varint(self.sequence, &mut body);
        encode_varint(payload.len() as u64, &mut body);
        body.extend_from_slice(payload.as_ref());
        if body.len() > MAX_FRAME_LEN {
            return Err(CodecError::FrameTooLarge);
        }
        let mut encoded = Vec::new();
        encode_varint(body.len() as u64, &mut encoded);
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    /// Attempts to decode a frame from a contiguous buffer.
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize), CodecError> {
        let (frame_len_raw, header_len) = decode_varint(buffer)?;
        let frame_len = usize::try_from(frame_len_raw).map_err(|_| CodecError::FrameTooLarge)?;
        if frame_len > MAX_FRAME_LEN {
            return Err(CodecError::FrameTooLarge);
        }
        if buffer.len() < header_len + frame_len {
            return Err(CodecError::UnexpectedEof);
        }
        let frame_slice = &buffer[header_len..header_len + frame_len];
        if frame_slice.is_empty() {
            return Err(CodecError::UnexpectedEof);
        }
        let frame_type = FrameType::from_u8(frame_slice[0]).ok_or(CodecError::InvalidFrameType)?;
        let mut cursor = 1;
        let (channel_id, read) = decode_varint(&frame_slice[cursor..])?;
        cursor += read;
        if channel_id > MAX_CHANNEL_ID {
            return Err(CodecError::ChannelIdTooLarge);
        }
        let (sequence, read) = decode_varint(&frame_slice[cursor..])?;
        cursor += read;
        if sequence > MAX_SEQUENCE {
            return Err(CodecError::SequenceTooLarge);
        }
        let (payload_len_raw, read) = decode_varint(&frame_slice[cursor..])?;
        cursor += read;
        let payload_len =
            usize::try_from(payload_len_raw).map_err(|_| CodecError::PayloadTooLarge)?;
        if payload_len > MAX_FRAME_LEN {
            return Err(CodecError::PayloadTooLarge);
        }
        if frame_slice.len() < cursor + payload_len {
            return Err(CodecError::UnexpectedEof);
        }
        let payload_slice = &frame_slice[cursor..cursor + payload_len];
        let payload = FramePayload::from_bytes(frame_type, payload_slice)?;
        let total = header_len + frame_len;
        Ok((
            Frame {
                channel_id,
                sequence,
                frame_type,
                payload,
            },
            total,
        ))
    }
}

fn encode_varint(mut value: u64, buffer: &mut Vec<u8>) {
    while value >= 0x80 {
        buffer.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

fn decode_varint(buffer: &[u8]) -> Result<(u64, usize), CodecError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (index, byte) in buffer.iter().enumerate() {
        let part = (byte & 0x7f) as u64;
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
        if shift > 63 {
            return Err(CodecError::VarintOverflow);
        }
    }
    Err(CodecError::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_version_prefers_highest_supported() {
        let negotiated = negotiate_protocol_version(&[0, PROTOCOL_VERSION, PROTOCOL_VERSION + 1]);
        assert_eq!(negotiated, Some(PROTOCOL_VERSION));
    }

    #[test]
    fn negotiate_version_none_when_disjoint() {
        let negotiated = negotiate_protocol_version(&[42, 43]);
        assert_eq!(negotiated, None);
    }

    #[test]
    fn supported_version_predicate_matches() {
        assert!(is_supported_protocol_version(PROTOCOL_VERSION));
        assert!(!is_supported_protocol_version(PROTOCOL_VERSION + 5));
    }

    #[test]
    fn encode_roundtrip_control_frame() {
        let frame = Frame {
            channel_id: 12,
            sequence: 34,
            frame_type: FrameType::Hello,
            payload: FramePayload::Control(ControlEnvelope {
                properties: serde_json::json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "capabilities": ["noise", "zstd"],
                }),
            }),
        };
        let encoded = frame.encode().unwrap();
        let (decoded, read) = Frame::decode(&encoded).unwrap();
        assert_eq!(read, encoded.len());
        assert_eq!(decoded.channel_id, 12);
        assert_eq!(decoded.sequence, 34);
        assert_eq!(decoded.frame_type, FrameType::Hello);
        match decoded.payload {
            FramePayload::Control(ctrl) => {
                let version = ctrl.properties.get("protocol_version").unwrap();
                assert_eq!(version.as_u64(), Some(PROTOCOL_VERSION as u64));
            }
            _ => panic!("unexpected payload"),
        }
    }

    #[test]
    fn encode_roundtrip_opaque_frame() {
        let frame = Frame {
            channel_id: 9,
            sequence: 1,
            frame_type: FrameType::Msg,
            payload: FramePayload::Opaque(vec![1, 2, 3, 4]),
        };
        let encoded = frame.encode().unwrap();
        let (decoded, _read) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, FramePayload::Opaque(vec![1, 2, 3, 4]));
    }

    #[test]
    fn encode_roundtrip_voice_frame() {
        let frame = Frame {
            channel_id: 42,
            sequence: 5,
            frame_type: FrameType::VoiceFrame,
            payload: FramePayload::Opaque(vec![0xaa, 0xbb, 0xcc, 0xdd]),
        };
        let encoded = frame.encode().unwrap();
        let (decoded, _read) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FrameType::VoiceFrame);
        assert_eq!(
            decoded.payload,
            FramePayload::Opaque(vec![0xaa, 0xbb, 0xcc, 0xdd])
        );
    }

    #[test]
    fn encode_roundtrip_call_offer_frame() {
        use crate::call::{AudioParameters, VideoParameters};
        use crate::call::{CallMediaProfile, TransportCandidate, TransportProtocol};
        use crate::call::{CallMode, CallOffer, CallTransport};
        use commucat_media_types::{VideoCodec, VideoResolution};
        use std::convert::TryInto;

        let video = VideoParameters {
            codec: VideoCodec::Vp8,
            max_bitrate: 500_000,
            max_resolution: VideoResolution::default(),
            frame_rate: 24,
            adaptive: true,
            ..VideoParameters::default()
        };

        let offer = CallOffer {
            call_id: "call-xyz".to_string(),
            from: "alice:device".to_string(),
            to: vec!["bob:device".to_string()],
            media: CallMediaProfile {
                audio: AudioParameters::default(),
                video: Some(video),
                mode: CallMode::FullDuplex,
                capabilities: None,
            },
            metadata: serde_json::json!({"mode": "voice"}),
            transport: Some(CallTransport {
                prefer_relay: false,
                udp_candidates: vec![TransportCandidate {
                    address: "198.51.100.12".to_string(),
                    port: 60000,
                    protocol: TransportProtocol::Udp,
                }],
                fingerprints: vec!["deadbeef".to_string()],
            }),
            expires_at: Some(1_690_000_000),
            ephemeral_key: None,
        };
        let envelope: ControlEnvelope = (&offer).try_into().unwrap();
        let frame = Frame {
            channel_id: 7,
            sequence: 9,
            frame_type: FrameType::CallOffer,
            payload: FramePayload::Control(envelope.clone()),
        };
        let encoded = frame.encode().unwrap();
        let (decoded, _) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FrameType::CallOffer);
        match decoded.payload {
            FramePayload::Control(ctrl) => {
                let decoded_offer = CallOffer::try_from(&ctrl).unwrap();
                assert_eq!(decoded_offer.call_id, offer.call_id);
                assert_eq!(decoded_offer.media.mode, CallMode::FullDuplex);
            }
            _ => panic!("expected control payload"),
        }
    }

    #[test]
    fn decode_multiple_frames_in_sequence() {
        let frame1 = Frame {
            channel_id: 7,
            sequence: 11,
            frame_type: FrameType::Hello,
            payload: FramePayload::Control(ControlEnvelope {
                properties: serde_json::json!({
                    "protocol_version": PROTOCOL_VERSION,
                }),
            }),
        };
        let frame2 = Frame {
            channel_id: 7,
            sequence: 12,
            frame_type: FrameType::Msg,
            payload: FramePayload::Opaque(vec![9, 8, 7]),
        };
        let mut concatenated = frame1.encode().unwrap();
        let second = frame2.encode().unwrap();
        let first_len = concatenated.len();
        concatenated.extend_from_slice(&second);
        let (decoded1, read1) = Frame::decode(&concatenated).unwrap();
        assert_eq!(read1, first_len);
        assert_eq!(decoded1.sequence, 11);
        let (decoded2, read2) = Frame::decode(&concatenated[read1..]).unwrap();
        assert_eq!(read1 + read2, concatenated.len());
        assert_eq!(decoded2.payload, FramePayload::Opaque(vec![9, 8, 7]));
    }

    #[test]
    fn decode_rejects_payload_length_mismatch() {
        let frame = Frame {
            channel_id: 1,
            sequence: 2,
            frame_type: FrameType::Msg,
            payload: FramePayload::Opaque(vec![0xaa, 0xbb, 0xcc]),
        };
        let mut encoded = frame.encode().unwrap();
        let (_, header_len) = decode_varint(&encoded).unwrap();
        let mut cursor = header_len + 1;
        let (_, read) = decode_varint(&encoded[cursor..]).unwrap();
        cursor += read;
        let (_, read) = decode_varint(&encoded[cursor..]).unwrap();
        cursor += read;
        let (payload_len, read) = decode_varint(&encoded[cursor..]).unwrap();
        let mut new_len = Vec::new();
        encode_varint(payload_len + 1, &mut new_len);
        let start = cursor;
        let end = cursor + read;
        encoded.splice(start..end, new_len);
        assert!(matches!(
            Frame::decode(&encoded),
            Err(CodecError::UnexpectedEof)
        ));
    }

    #[test]
    fn decode_rejects_varint_overflow() {
        let buffer = vec![0xff; 10];
        assert!(matches!(
            Frame::decode(&buffer),
            Err(CodecError::VarintOverflow)
        ));
    }

    #[test]
    fn decode_rejects_unknown_frame_type() {
        let frame = Frame {
            channel_id: 3,
            sequence: 4,
            frame_type: FrameType::Ack,
            payload: FramePayload::Control(ControlEnvelope {
                properties: serde_json::json!({"status": "ok"}),
            }),
        };
        let mut encoded = frame.encode().unwrap();
        let (_, header_len) = decode_varint(&encoded).unwrap();
        encoded[header_len] = 0xff;
        assert!(matches!(
            Frame::decode(&encoded),
            Err(CodecError::InvalidFrameType)
        ));
    }

    #[test]
    fn decode_rejects_oversized_frame() {
        let mut buffer = Vec::new();
        encode_varint((MAX_FRAME_LEN + 1) as u64, &mut buffer);
        assert!(matches!(
            Frame::decode(&buffer),
            Err(CodecError::FrameTooLarge)
        ));
    }

    #[test]
    fn encode_group_control_frame() {
        let frame = Frame {
            channel_id: 99,
            sequence: 1,
            frame_type: FrameType::GroupInvite,
            payload: FramePayload::Control(ControlEnvelope {
                properties: serde_json::json!({
                    "group_id": "grp-1",
                    "device": "dev-1",
                }),
            }),
        };
        let encoded = frame.encode().unwrap();
        let (decoded, _) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, FrameType::GroupInvite);
    }

    #[test]
    fn encode_large_batch() {
        let mut buffer = Vec::new();
        for index in 0..512u64 {
            let frame = Frame {
                channel_id: index,
                sequence: index,
                frame_type: FrameType::Msg,
                payload: FramePayload::Opaque(vec![0u8; 16]),
            };
            let encoded = frame.encode().unwrap();
            buffer.extend_from_slice(&encoded);
        }
        let mut cursor = buffer.as_slice();
        let mut decoded = 0;
        while !cursor.is_empty() {
            let (frame, read) = Frame::decode(cursor).unwrap();
            assert_eq!(frame.frame_type, FrameType::Msg);
            cursor = &cursor[read..];
            decoded += 1;
        }
        assert_eq!(decoded, 512);
    }
}
