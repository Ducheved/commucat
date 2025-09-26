use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MediaSourceMode {
    #[default]
    Encoded,
    Raw,
    Hybrid,
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
