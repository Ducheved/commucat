use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioCodec {
    Opus,
    RawPcm,
}

impl Default for AudioCodec {
    fn default() -> Self {
        Self::Opus
    }
}

impl From<AudioCodec> for u8 {
    fn from(value: AudioCodec) -> Self {
        match value {
            AudioCodec::Opus => 0,
            AudioCodec::RawPcm => 1,
        }
    }
}

impl TryFrom<u8> for AudioCodec {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AudioCodec::Opus),
            1 => Ok(AudioCodec::RawPcm),
            _ => Err("unknown audio codec"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoCodec {
    RawI420,
    Vp8,
    Vp9,
    H264Baseline,
    H264Main,
    H265Main,
    Av1Main,
}

impl Default for VideoCodec {
    fn default() -> Self {
        Self::Vp8
    }
}

impl From<VideoCodec> for u8 {
    fn from(value: VideoCodec) -> Self {
        match value {
            VideoCodec::RawI420 => 0,
            VideoCodec::Vp8 => 1,
            VideoCodec::Vp9 => 2,
            VideoCodec::H264Baseline => 3,
            VideoCodec::H264Main => 4,
            VideoCodec::H265Main => 5,
            VideoCodec::Av1Main => 6,
        }
    }
}

impl TryFrom<u8> for VideoCodec {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(VideoCodec::RawI420),
            1 => Ok(VideoCodec::Vp8),
            2 => Ok(VideoCodec::Vp9),
            3 => Ok(VideoCodec::H264Baseline),
            4 => Ok(VideoCodec::H264Main),
            5 => Ok(VideoCodec::H265Main),
            6 => Ok(VideoCodec::Av1Main),
            _ => Err("unknown video codec"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MediaSourceMode {
    #[default]
    Encoded,
    Raw,
    Hybrid,
}

impl From<MediaSourceMode> for u8 {
    fn from(value: MediaSourceMode) -> Self {
        match value {
            MediaSourceMode::Encoded => 0,
            MediaSourceMode::Raw => 1,
            MediaSourceMode::Hybrid => 2,
        }
    }
}

impl TryFrom<u8> for MediaSourceMode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MediaSourceMode::Encoded),
            1 => Ok(MediaSourceMode::Raw),
            2 => Ok(MediaSourceMode::Hybrid),
            _ => Err("unknown media source mode"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareAcceleration {
    Cpu,
    Nvidia,
    Amd,
    Intel,
    Apple,
}

impl Default for HardwareAcceleration {
    fn default() -> Self {
        Self::Cpu
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoResolution {
    pub width: u16,
    pub height: u16,
}

impl VideoResolution {
    #[must_use]
    pub const fn new(width: u16, height: u16) -> Self {
        Self { width, height }
    }
}

impl Default for VideoResolution {
    fn default() -> Self {
        Self {
            width: 640,
            height: 360,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CodecPriority(pub u8);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioCodecDescriptor {
    pub codec: AudioCodec,
    #[serde(default)]
    pub bitrate: Option<u32>,
    #[serde(default)]
    pub sample_rate: Option<u32>,
    #[serde(default)]
    pub channels: Option<u8>,
    #[serde(default)]
    pub priority: CodecPriority,
}

impl Default for AudioCodecDescriptor {
    fn default() -> Self {
        Self {
            codec: AudioCodec::Opus,
            bitrate: Some(16_000),
            sample_rate: Some(48_000),
            channels: Some(1),
            priority: CodecPriority(100),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoCodecDescriptor {
    pub codec: VideoCodec,
    #[serde(default)]
    pub max_bitrate: Option<u32>,
    #[serde(default)]
    pub max_resolution: Option<VideoResolution>,
    #[serde(default)]
    pub frame_rate: Option<u8>,
    #[serde(default)]
    pub hardware: Vec<HardwareAcceleration>,
    #[serde(default)]
    pub priority: CodecPriority,
    #[serde(default)]
    pub supports_scalability: bool,
}

impl Default for VideoCodecDescriptor {
    fn default() -> Self {
        Self {
            codec: VideoCodec::Vp8,
            max_bitrate: Some(750_000),
            max_resolution: Some(VideoResolution::new(640, 360)),
            frame_rate: Some(24),
            hardware: vec![HardwareAcceleration::Cpu],
            priority: CodecPriority(100),
            supports_scalability: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MediaCapabilities {
    #[serde(default)]
    pub audio: Vec<AudioCodecDescriptor>,
    #[serde(default)]
    pub video: Vec<VideoCodecDescriptor>,
    #[serde(default)]
    pub allow_raw_audio: bool,
    #[serde(default)]
    pub allow_raw_video: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audio_codec_roundtrip() {
        for value in [AudioCodec::Opus, AudioCodec::RawPcm] {
            let encoded: u8 = value.into();
            let decoded = AudioCodec::try_from(encoded).expect("audio codec");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn video_codec_roundtrip() {
        for value in [
            VideoCodec::RawI420,
            VideoCodec::Vp8,
            VideoCodec::Vp9,
            VideoCodec::H264Baseline,
            VideoCodec::H264Main,
            VideoCodec::H265Main,
            VideoCodec::Av1Main,
        ] {
            let encoded: u8 = value.into();
            let decoded = VideoCodec::try_from(encoded).expect("video codec");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn media_source_mode_roundtrip() {
        for value in [
            MediaSourceMode::Encoded,
            MediaSourceMode::Raw,
            MediaSourceMode::Hybrid,
        ] {
            let encoded: u8 = value.into();
            let decoded = MediaSourceMode::try_from(encoded).expect("source mode");
            assert_eq!(decoded, value);
        }
    }
}
