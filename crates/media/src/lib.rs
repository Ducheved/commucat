#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

#[cfg(feature = "video")]
extern crate env_libvpx_sys;

pub mod audio;
#[cfg(feature = "audio-io")]
pub mod capture;
#[cfg(feature = "pipeline")]
pub mod pipeline;
#[cfg(feature = "video")]
pub mod video;
pub mod voice;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MediaError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("operation not supported")]
    Unsupported,
    #[error("buffer underrun")]
    BufferUnderrun,
    #[error("timeout waiting for media data")]
    Timeout,
    #[error("io error: {0}")]
    Io(String),
    #[error("codec error: {0}")]
    Codec(String),
}

pub type MediaResult<T> = Result<T, MediaError>;

#[cfg(feature = "audio")]
impl From<audiopus::Error> for MediaError {
    fn from(err: audiopus::Error) -> Self {
        MediaError::Codec(err.to_string())
    }
}

#[cfg(feature = "video")]
impl From<env_libvpx_sys::vpx_codec_err_t> for MediaError {
    fn from(err: env_libvpx_sys::vpx_codec_err_t) -> Self {
        MediaError::Codec(format!("libvpx error code {err}"))
    }
}

pub mod prelude {
    pub use crate::audio::{
        AudioLevel, VoiceDecoder, VoiceDecoderConfig, VoiceEncoder, VoiceEncoderConfig, VoiceFrame,
    };
    #[cfg(feature = "audio-io")]
    pub use crate::capture::{AudioCapture, AudioCaptureConfig};
    #[cfg(feature = "pipeline")]
    pub use crate::pipeline::{CallMediaPipeline, PipelineConfig};
    #[cfg(feature = "video")]
    pub use crate::video::{
        DecodedFrame, I420Borrowed, VideoDecoder, VideoEncoder, VideoEncoderConfig, VideoFrame,
    };
    pub use crate::voice::VoiceMessage;
    pub use crate::{MediaError, MediaResult};
}
