use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const PROTOCOL_VERSION: u16 = 1;

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
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum CodecError {
    InvalidType,
    UnexpectedEof,
    VarintOverflow,
    PayloadTooLarge,
}

impl Display for CodecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidType => write!(f, "invalid frame type"),
            Self::UnexpectedEof => write!(f, "unexpected end of frame"),
            Self::VarintOverflow => write!(f, "varint overflow"),
            Self::PayloadTooLarge => write!(f, "payload exceeds limits"),
        }
    }
}

impl Error for CodecError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEnvelope {
    pub properties: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FramePayload {
    Control(ControlEnvelope),
    Opaque(Vec<u8>),
}

impl FramePayload {
    fn into_bytes(self) -> Result<Vec<u8>, CodecError> {
        match self {
            FramePayload::Control(ctrl) => {
                serde_json::to_vec(&ctrl).map_err(|_| CodecError::InvalidType)
            }
            FramePayload::Opaque(data) => Ok(data),
        }
    }

    fn from_bytes(frame_type: FrameType, data: Vec<u8>) -> Result<Self, CodecError> {
        match frame_type {
            FrameType::Msg | FrameType::KeyUpdate => Ok(FramePayload::Opaque(data)),
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
            | FrameType::Error => serde_json::from_slice::<ControlEnvelope>(&data)
                .map(FramePayload::Control)
                .map_err(|_| CodecError::InvalidType),
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
        let mut body = Vec::new();
        body.push(self.frame_type as u8);
        encode_varint(self.channel_id, &mut body);
        encode_varint(self.sequence, &mut body);
        let payload = self.payload.clone().into_bytes()?;
        encode_varint(payload.len() as u64, &mut body);
        body.extend_from_slice(&payload);
        if body.len() > (u32::MAX as usize) {
            return Err(CodecError::PayloadTooLarge);
        }
        let mut encoded = Vec::new();
        encode_varint(body.len() as u64, &mut encoded);
        encoded.extend_from_slice(&body);
        Ok(encoded)
    }

    /// Attempts to decode a frame from a contiguous buffer.
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize), CodecError> {
        let (frame_len, header_len) = decode_varint(buffer)?;
        if buffer.len() < header_len + frame_len as usize {
            return Err(CodecError::UnexpectedEof);
        }
        let frame_slice = &buffer[header_len..header_len + frame_len as usize];
        if frame_slice.is_empty() {
            return Err(CodecError::UnexpectedEof);
        }
        let frame_type = FrameType::from_u8(frame_slice[0]).ok_or(CodecError::InvalidType)?;
        let mut cursor = 1;
        let (channel_id, read) = decode_varint(&frame_slice[cursor..])?;
        cursor += read;
        let (sequence, read) = decode_varint(&frame_slice[cursor..])?;
        cursor += read;
        let (payload_len, read) = decode_varint(&frame_slice[cursor..])?;
        cursor += read;
        if frame_slice.len() < cursor + payload_len as usize {
            return Err(CodecError::UnexpectedEof);
        }
        let payload_bytes = frame_slice[cursor..cursor + payload_len as usize].to_vec();
        let payload = FramePayload::from_bytes(frame_type, payload_bytes)?;
        let total = header_len + frame_len as usize;
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
                assert_eq!(version, PROTOCOL_VERSION);
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
}
