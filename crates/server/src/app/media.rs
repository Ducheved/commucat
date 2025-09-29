use super::ServerError;
use commucat_media::audio::{VoiceEncoder, VoiceEncoderConfig};
use commucat_media::video::{
    I420Borrowed, VideoDecoder, VideoEncoder, VideoEncoderConfig, VideoFrame,
};
use commucat_media::{AudioCodec, MediaError, MediaSourceMode, VideoCodec};
use commucat_proto::call::{AudioParameters, CallMediaProfile, VideoParameters};
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

const MEDIA_PACKET_VERSION: u8 = 1;
const MEDIA_HEADER_LEN: usize = 3;
const DEFAULT_AUDIO_FRAME_MS: u16 = 20;

pub type SharedCallMediaTranscoder = Arc<Mutex<CallMediaTranscoder>>;

pub struct CallMediaTranscoder {
    audio: Option<AudioTranscoder>,
    video: Option<VideoTranscoder>,
}

impl CallMediaTranscoder {
    pub fn new(profile: &CallMediaProfile) -> Result<Self, MediaTranscoderError> {
        let audio = build_audio_transcoder(&profile.audio)?;
        let video = match &profile.video {
            Some(params) => build_video_transcoder(params)?,
            None => None,
        };
        Ok(Self { audio, video })
    }

    pub fn update_profile(
        &mut self,
        profile: &CallMediaProfile,
    ) -> Result<(), MediaTranscoderError> {
        let mut replacement = CallMediaTranscoder::new(profile)?;
        std::mem::swap(self, &mut replacement);
        Ok(())
    }

    pub fn process_audio(&mut self, packet: Vec<u8>) -> Result<Vec<u8>, MediaTranscoderError> {
        let parsed = ParsedAudioPacket::parse(packet.as_slice())?;
        match parsed.source {
            MediaSourceMode::Raw => {
                let transcoder = self
                    .audio
                    .as_mut()
                    .ok_or(MediaTranscoderError::Unsupported(
                        "audio transcoding unavailable",
                    ))?;
                let encoded = transcoder.encode_raw(parsed.payload)?;
                Ok(build_audio_packet(
                    MediaSourceMode::Encoded,
                    transcoder.target_codec,
                    &encoded,
                ))
            }
            MediaSourceMode::Encoded | MediaSourceMode::Hybrid => Ok(packet),
        }
    }

    pub fn process_video(&mut self, packet: Vec<u8>) -> Result<Vec<u8>, MediaTranscoderError> {
        let parsed = ParsedVideoPacket::parse(packet.as_slice())?;
        match parsed.source {
            MediaSourceMode::Raw => {
                let transcoder = self
                    .video
                    .as_mut()
                    .ok_or(MediaTranscoderError::Unsupported(
                        "video transcoding unavailable",
                    ))?;
                let encoded = transcoder.encode_raw(parsed.payload)?;
                Ok(build_video_packet(
                    MediaSourceMode::Encoded,
                    transcoder.target_codec,
                    &encoded,
                ))
            }
            MediaSourceMode::Encoded | MediaSourceMode::Hybrid => {
                let Some(transcoder) = self.video.as_mut() else {
                    return Ok(packet);
                };
                if parsed.codec == transcoder.target_codec {
                    return Ok(packet);
                }
                match transcoder.transcode_encoded(parsed.codec, parsed.payload) {
                    Ok(converted) => Ok(converted),
                    Err(err) => {
                        warn!(error = %err, "video transcoding failed for encoded payload");
                        Err(err)
                    }
                }
            }
        }
    }
}

struct AudioTranscoder {
    encoder: VoiceEncoder,
    target_codec: AudioCodec,
    frame_duration_ms: u16,
    next_timestamp_ms: u64,
    expected_samples: usize,
}

impl AudioTranscoder {
    fn encode_raw(&mut self, payload: &[u8]) -> Result<Vec<u8>, MediaTranscoderError> {
        let expected_bytes = self.expected_samples * std::mem::size_of::<i16>();
        if payload.len() != expected_bytes {
            return Err(MediaTranscoderError::Invalid("pcm frame length mismatch"));
        }
        let mut pcm = Vec::with_capacity(self.expected_samples);
        for chunk in payload.chunks_exact(2) {
            let bytes = <[u8; 2]>::try_from(chunk).expect("chunks_exact guarantees element size");
            pcm.push(i16::from_le_bytes(bytes));
        }
        let frame = self
            .encoder
            .encode(&pcm, self.next_timestamp_ms)
            .map_err(MediaTranscoderError::from)?;
        self.next_timestamp_ms = self
            .next_timestamp_ms
            .wrapping_add(u64::from(self.frame_duration_ms));
        Ok(frame.payload().to_vec())
    }
}

struct VideoTranscoder {
    encoder: VideoEncoder,
    target_codec: VideoCodec,
    decoder: Option<VideoDecoder>,
    width: u32,
    height: u32,
    uv_width: usize,
    uv_height: usize,
    next_pts: u64,
    force_keyframe: bool,
}

impl VideoTranscoder {
    fn encode_raw(&mut self, payload: &[u8]) -> Result<Vec<u8>, MediaTranscoderError> {
        let expected = self.expected_i420_len();
        if payload.len() != expected {
            return Err(MediaTranscoderError::Invalid("i420 frame length mismatch"));
        }
        let (y_plane, rest) = payload.split_at(self.y_plane_len());
        let (u_plane, v_plane) = rest.split_at(self.uv_plane_len());
        let frames = self
            .encoder
            .encode(
                I420Borrowed {
                    y: y_plane,
                    u: u_plane,
                    v: v_plane,
                    stride_y: self.width as usize,
                    stride_u: self.uv_width,
                    stride_v: self.uv_width,
                },
                self.next_pts,
                self.force_keyframe,
            )
            .map_err(MediaTranscoderError::from)?;
        self.force_keyframe = false;
        self.next_pts = self.next_pts.wrapping_add(1);
        let encoded = frames
            .into_iter()
            .next()
            .ok_or_else(|| MediaTranscoderError::Codec("empty video packet".to_string()))?;
        Ok(encoded.data)
    }

    fn transcode_encoded(
        &mut self,
        source_codec: VideoCodec,
        payload: &[u8],
    ) -> Result<Vec<u8>, MediaTranscoderError> {
        if source_codec == self.target_codec {
            return Ok(build_video_packet(
                MediaSourceMode::Encoded,
                source_codec,
                payload,
            ));
        }
        if self.decoder.is_none() {
            self.decoder = Some(VideoDecoder::new().map_err(MediaTranscoderError::from)?);
        }
        let decoder = self.decoder.as_mut().ok_or(MediaTranscoderError::Codec(
            "video decoder unavailable".to_string(),
        ))?;
        let encoded_frame = VideoFrame {
            timestamp: self.next_pts,
            keyframe: false,
            codec: source_codec,
            width: self.width,
            height: self.height,
            data: payload.to_vec(),
        };
        let decoded = decoder
            .decode(&encoded_frame)
            .map_err(MediaTranscoderError::from)?
            .into_iter()
            .next()
            .ok_or_else(|| MediaTranscoderError::Codec("decoder produced no frame".to_string()))?;
        if decoded.width != self.width || decoded.height != self.height {
            return Err(MediaTranscoderError::Invalid("decoder resolution mismatch"));
        }
        let raw = decoded.data;
        let encoded_payload = self.encode_raw(raw.as_slice())?;
        Ok(build_video_packet(
            MediaSourceMode::Encoded,
            self.target_codec,
            &encoded_payload,
        ))
    }

    fn expected_i420_len(&self) -> usize {
        self.y_plane_len() + 2 * self.uv_plane_len()
    }

    fn y_plane_len(&self) -> usize {
        (self.width as usize) * (self.height as usize)
    }

    fn uv_plane_len(&self) -> usize {
        self.uv_width * self.uv_height
    }
}

struct ParsedAudioPacket<'a> {
    pub source: MediaSourceMode,
    pub payload: &'a [u8],
}

impl<'a> ParsedAudioPacket<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, MediaTranscoderError> {
        if data.len() < MEDIA_HEADER_LEN {
            return Err(MediaTranscoderError::Invalid("audio packet too short"));
        }
        let version = data[0];
        if version != MEDIA_PACKET_VERSION {
            return Err(MediaTranscoderError::Invalid(
                "unsupported audio packet version",
            ));
        }
        let source = MediaSourceMode::try_from(data[1])
            .map_err(|_| MediaTranscoderError::Invalid("unknown audio source"))?;
        AudioCodec::try_from(data[2])
            .map_err(|_| MediaTranscoderError::Invalid("unknown audio codec"))?;
        Ok(Self {
            source,
            payload: &data[MEDIA_HEADER_LEN..],
        })
    }
}

struct ParsedVideoPacket<'a> {
    pub source: MediaSourceMode,
    pub codec: VideoCodec,
    pub payload: &'a [u8],
}

impl<'a> ParsedVideoPacket<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, MediaTranscoderError> {
        if data.len() < MEDIA_HEADER_LEN {
            return Err(MediaTranscoderError::Invalid("video packet too short"));
        }
        let version = data[0];
        if version != MEDIA_PACKET_VERSION {
            return Err(MediaTranscoderError::Invalid(
                "unsupported video packet version",
            ));
        }
        let source = MediaSourceMode::try_from(data[1])
            .map_err(|_| MediaTranscoderError::Invalid("unknown video source"))?;
        let codec = VideoCodec::try_from(data[2])
            .map_err(|_| MediaTranscoderError::Invalid("unknown video codec"))?;
        Ok(Self {
            source,
            codec,
            payload: &data[MEDIA_HEADER_LEN..],
        })
    }
}

#[derive(Debug)]
pub enum MediaTranscoderError {
    Codec(String),
    Unsupported(&'static str),
    Invalid(&'static str),
}

impl Display for MediaTranscoderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Codec(err) => write!(f, "codec error: {}", err),
            Self::Unsupported(reason) => write!(f, "unsupported: {}", reason),
            Self::Invalid(reason) => write!(f, "invalid media packet: {}", reason),
        }
    }
}

impl std::error::Error for MediaTranscoderError {}

impl From<MediaError> for MediaTranscoderError {
    fn from(err: MediaError) -> Self {
        Self::Codec(err.to_string())
    }
}

impl From<MediaTranscoderError> for ServerError {
    fn from(err: MediaTranscoderError) -> Self {
        match err {
            MediaTranscoderError::Codec(_) | MediaTranscoderError::Unsupported(_) => {
                ServerError::Codec
            }
            MediaTranscoderError::Invalid(_) => ServerError::Invalid,
        }
    }
}

fn build_audio_transcoder(
    params: &AudioParameters,
) -> Result<Option<AudioTranscoder>, MediaTranscoderError> {
    match params.codec {
        AudioCodec::Opus => {
            let config = VoiceEncoderConfig {
                codec: AudioCodec::Opus,
                sample_rate: params.sample_rate,
                channels: params.channels,
                frame_duration_ms: DEFAULT_AUDIO_FRAME_MS,
                bitrate: params.bitrate,
                use_vbr: true,
                enable_fec: params.fec,
                enable_dtx: params.dtx,
                max_packet_size: 4_096,
                source: MediaSourceMode::Raw,
                ..VoiceEncoderConfig::default()
            };
            let frame_duration_ms = config.frame_duration_ms;
            let target_codec = config.codec;
            let encoder = VoiceEncoder::new(config).map_err(MediaTranscoderError::from)?;
            let expected_samples = encoder.frame_samples();
            Ok(Some(AudioTranscoder {
                encoder,
                target_codec,
                frame_duration_ms,
                next_timestamp_ms: 0,
                expected_samples,
            }))
        }
        AudioCodec::RawPcm => Ok(None),
    }
}

fn select_video_codec(params: &VideoParameters) -> VideoCodec {
    for candidate in params
        .preferred_codecs
        .iter()
        .chain(std::iter::once(&params.codec))
    {
        match candidate {
            VideoCodec::Vp8 | VideoCodec::Vp9 => return *candidate,
            VideoCodec::Av1Main => {
                #[cfg(feature = "media-av1")]
                {
                    return VideoCodec::Av1Main;
                }
            }
            _ => {}
        }
    }
    VideoCodec::Vp8
}

fn build_video_transcoder(
    params: &VideoParameters,
) -> Result<Option<VideoTranscoder>, MediaTranscoderError> {
    let target = select_video_codec(params);
    match target {
        VideoCodec::Vp8 | VideoCodec::Vp9 => {
            let config = VideoEncoderConfig {
                codec: target,
                width: params.max_resolution.width.into(),
                height: params.max_resolution.height.into(),
                timebase_num: 1,
                timebase_den: u32::from(params.frame_rate.max(1)),
                bitrate: params.max_bitrate,
                source: MediaSourceMode::Raw,
                ..VideoEncoderConfig::default()
            };
            let width = config.width;
            let height = config.height;
            let encoder = VideoEncoder::new(config).map_err(MediaTranscoderError::from)?;
            let width_usize = usize::try_from(width).expect("width fits usize");
            let height_usize = usize::try_from(height).expect("height fits usize");
            let uv_width = width_usize.div_ceil(2);
            let uv_height = height_usize.div_ceil(2);
            Ok(Some(VideoTranscoder {
                encoder,
                target_codec: target,
                decoder: None,
                width,
                height,
                uv_width,
                uv_height,
                next_pts: 0,
                force_keyframe: true,
            }))
        }
        VideoCodec::Av1Main => {
            #[cfg(feature = "media-av1")]
            {
                let config = VideoEncoderConfig {
                    codec: VideoCodec::Av1Main,
                    width: params.max_resolution.width.into(),
                    height: params.max_resolution.height.into(),
                    timebase_num: 1,
                    timebase_den: u32::from(params.frame_rate.max(1)),
                    bitrate: params.max_bitrate,
                    source: MediaSourceMode::Raw,
                    ..VideoEncoderConfig::default()
                };
                let width = config.width;
                let height = config.height;
                let encoder = VideoEncoder::new(config).map_err(MediaTranscoderError::from)?;
                let width_usize = usize::try_from(width).expect("width fits usize");
                let height_usize = usize::try_from(height).expect("height fits usize");
                let uv_width = width_usize.div_ceil(2);
                let uv_height = height_usize.div_ceil(2);
                return Ok(Some(VideoTranscoder {
                    encoder,
                    target_codec: VideoCodec::Av1Main,
                    decoder: None,
                    width,
                    height,
                    uv_width,
                    uv_height,
                    next_pts: 0,
                    force_keyframe: true,
                }));
            }
            #[cfg(not(feature = "media-av1"))]
            {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

fn build_audio_packet(source: MediaSourceMode, codec: AudioCodec, payload: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(MEDIA_HEADER_LEN + payload.len());
    buffer.push(MEDIA_PACKET_VERSION);
    buffer.push(u8::from(source));
    buffer.push(u8::from(codec));
    buffer.extend_from_slice(payload);
    buffer
}

fn build_video_packet(source: MediaSourceMode, codec: VideoCodec, payload: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(MEDIA_HEADER_LEN + payload.len());
    buffer.push(MEDIA_PACKET_VERSION);
    buffer.push(u8::from(source));
    buffer.push(u8::from(codec));
    buffer.extend_from_slice(payload);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use commucat_media::{AudioCodecDescriptor, VideoCodecDescriptor, VideoResolution};
    use commucat_proto::call::CallMode;

    #[test]
    fn audio_transcoder_encodes_pcm() {
        let profile = CallMediaProfile {
            audio: AudioParameters {
                codec: AudioCodec::Opus,
                bitrate: 16_000,
                sample_rate: 48_000,
                channels: 1,
                fec: true,
                dtx: false,
                source: MediaSourceMode::Raw,
                preferred_codecs: vec![AudioCodec::Opus],
                available_codecs: vec![AudioCodecDescriptor::default()],
                allow_passthrough: true,
            },
            video: None,
            mode: CallMode::FullDuplex,
            capabilities: None,
        };
        let mut transcoder = CallMediaTranscoder::new(&profile).expect("transcoder");
        let samples = (profile.audio.sample_rate / 1000 * u32::from(DEFAULT_AUDIO_FRAME_MS))
            * u32::from(profile.audio.channels);
        let raw = vec![0u8; (samples * 2) as usize];
        let packet = build_audio_packet(MediaSourceMode::Raw, AudioCodec::RawPcm, &raw);
        let encoded = transcoder.process_audio(packet).expect("encode");
        let parsed = ParsedAudioPacket::parse(encoded.as_slice()).expect("parse");
        assert_eq!(parsed.source, MediaSourceMode::Encoded);
        assert!(!parsed.payload.is_empty());
    }

    #[test]
    fn video_transcoder_encodes_i420() {
        let profile = CallMediaProfile {
            audio: AudioParameters::default(),
            video: Some(VideoParameters {
                codec: VideoCodec::Vp8,
                max_bitrate: 500_000,
                max_resolution: VideoResolution::new(2, 2),
                frame_rate: 24,
                adaptive: false,
                source: MediaSourceMode::Raw,
                preferred_codecs: vec![VideoCodec::Vp8],
                available_codecs: vec![VideoCodecDescriptor::default()],
                hardware: vec![],
                allow_passthrough: true,
                capabilities: None,
            }),
            mode: CallMode::FullDuplex,
            capabilities: None,
        };
        let mut transcoder = CallMediaTranscoder::new(&profile).expect("transcoder");
        let y = vec![0x80u8; 4];
        let u = vec![0x40u8; 1];
        let v = vec![0x20u8; 1];
        let mut raw = y;
        raw.extend_from_slice(&u);
        raw.extend_from_slice(&v);
        let packet = build_video_packet(MediaSourceMode::Raw, VideoCodec::RawI420, &raw);
        let encoded = transcoder.process_video(packet).expect("encode");
        let parsed = ParsedVideoPacket::parse(encoded.as_slice()).expect("parse");
        assert_eq!(parsed.source, MediaSourceMode::Encoded);
        assert!(!parsed.payload.is_empty());
    }

    #[cfg(feature = "media-av1")]
    #[test]
    fn select_video_codec_prefers_av1() {
        let params = VideoParameters {
            codec: VideoCodec::Vp8,
            max_bitrate: 750_000,
            max_resolution: VideoResolution::new(1280, 720),
            frame_rate: 30,
            adaptive: true,
            source: MediaSourceMode::Raw,
            preferred_codecs: vec![VideoCodec::Av1Main, VideoCodec::Vp8],
            available_codecs: vec![VideoCodecDescriptor::default()],
            hardware: vec![],
            allow_passthrough: true,
            capabilities: None,
        };
        assert_eq!(select_video_codec(&params), VideoCodec::Av1Main);
    }
}
