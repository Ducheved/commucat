use crate::{MediaError, MediaResult};
use audiopus::coder::{Decoder as OpusDecoder, Encoder as OpusEncoder};
use audiopus::{Application, Bitrate, Channels, MutSignals, SampleRate, packet::Packet};
use commucat_media_types::{AudioCodec, MediaSourceMode};
use std::convert::TryFrom;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct AudioLevel {
    pub peak: f32,
    pub rms: f32,
}

impl AudioLevel {
    pub const SILENT: Self = Self {
        peak: 0.0,
        rms: 0.0,
    };
}

#[derive(Debug, Clone)]
pub struct VoiceFrame {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub duration_ms: u16,
    pub payload: Vec<u8>,
    pub level: AudioLevel,
    pub codec: AudioCodec,
    pub source: MediaSourceMode,
}

impl VoiceFrame {
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn duration(&self) -> Duration {
        Duration::from_millis(u64::from(self.duration_ms))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VoiceEncoderConfig {
    pub codec: AudioCodec,
    pub sample_rate: u32,
    pub channels: u8,
    pub frame_duration_ms: u16,
    pub bitrate: u32,
    pub use_vbr: bool,
    pub enable_fec: bool,
    pub enable_dtx: bool,
    pub complexity: u8,
    pub max_packet_size: usize,
    pub source: MediaSourceMode,
}

impl Default for VoiceEncoderConfig {
    fn default() -> Self {
        Self {
            codec: AudioCodec::Opus,
            sample_rate: 48_000,
            channels: 1,
            frame_duration_ms: 20,
            bitrate: 16_000,
            use_vbr: true,
            enable_fec: true,
            enable_dtx: true,
            complexity: 9,
            max_packet_size: 4_096,
            source: MediaSourceMode::Raw,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VoiceDecoderConfig {
    pub codec: AudioCodec,
    pub sample_rate: u32,
    pub channels: u8,
    pub frame_duration_ms: u16,
    pub source: MediaSourceMode,
}

impl Default for VoiceDecoderConfig {
    fn default() -> Self {
        Self {
            codec: AudioCodec::Opus,
            sample_rate: 48_000,
            channels: 1,
            frame_duration_ms: 20,
            source: MediaSourceMode::Encoded,
        }
    }
}

fn opus_sample_rate(value: u32) -> MediaResult<SampleRate> {
    match value {
        8_000 => Ok(SampleRate::Hz8000),
        12_000 => Ok(SampleRate::Hz12000),
        16_000 => Ok(SampleRate::Hz16000),
        24_000 => Ok(SampleRate::Hz24000),
        48_000 => Ok(SampleRate::Hz48000),
        _ => Err(MediaError::InvalidConfig("unsupported sample rate")),
    }
}

fn opus_channels(value: u8) -> MediaResult<Channels> {
    match value {
        1 => Ok(Channels::Mono),
        2 => Ok(Channels::Stereo),
        _ => Err(MediaError::InvalidConfig("unsupported channel count")),
    }
}

fn channel_count(channels: Channels) -> usize {
    match channels {
        Channels::Mono => 1,
        Channels::Stereo => 2,
        Channels::Auto => unreachable!("auto is never returned by opus"),
    }
}

pub(crate) fn frame_samples_per_channel(
    sample_rate: u32,
    frame_duration_ms: u16,
) -> MediaResult<usize> {
    if frame_duration_ms == 0 {
        return Err(MediaError::InvalidConfig("frame duration must be positive"));
    }
    let numer = u64::from(sample_rate) * u64::from(frame_duration_ms);
    if numer % 1_000 != 0 {
        return Err(MediaError::InvalidConfig(
            "frame duration does not align with sample rate",
        ));
    }
    Ok((numer / 1_000) as usize)
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn audio_level_from_pcm(pcm: &[i16]) -> AudioLevel {
    if pcm.is_empty() {
        return AudioLevel::SILENT;
    }
    let mut peak = 0.0_f64;
    let mut square_sum = 0.0_f64;
    for &sample in pcm {
        let value = f64::from(sample) / f64::from(i16::MAX);
        let abs = value.abs();
        if abs > peak {
            peak = abs;
        }
        square_sum += value * value;
    }
    let len = pcm.len() as f64;
    let rms = (square_sum / len).sqrt();
    AudioLevel {
        peak: peak.min(1.0) as f32,
        rms: rms.min(1.0) as f32,
    }
}

enum VoiceEncoderBackend {
    Opus { encoder: OpusEncoder },
    Raw,
}

pub struct VoiceEncoder {
    backend: VoiceEncoderBackend,
    codec: AudioCodec,
    frame_samples_per_channel: usize,
    channels: u8,
    max_packet_size: usize,
    sequence: u64,
    duration_ms: u16,
    bitrate: u32,
}

impl VoiceEncoder {
    /// Creates an encoder for the requested audio codec.
    ///
    /// # Errors
    /// Returns `MediaError` when configuration is invalid or codec initialisation fails.
    pub fn new(config: VoiceEncoderConfig) -> MediaResult<Self> {
        if config.max_packet_size == 0 {
            return Err(MediaError::InvalidConfig("max_packet_size must be > 0"));
        }
        if config.channels == 0 {
            return Err(MediaError::InvalidConfig("channel count must be > 0"));
        }
        if matches!(config.source, MediaSourceMode::Encoded) {
            return Err(MediaError::InvalidConfig(
                "voice encoder expects raw audio input",
            ));
        }
        let frame_samples_per_channel =
            frame_samples_per_channel(config.sample_rate, config.frame_duration_ms)?;
        let backend = match config.codec {
            AudioCodec::Opus => {
                let target_bitrate = i32::try_from(config.bitrate)
                    .map_err(|_| MediaError::InvalidConfig("bitrate out of range"))?;
                if target_bitrate <= 0 {
                    return Err(MediaError::InvalidConfig("bitrate out of range"));
                }
                let sample_rate = opus_sample_rate(config.sample_rate)?;
                let channels = opus_channels(config.channels)?;
                let mut encoder = OpusEncoder::new(sample_rate, channels, Application::Voip)?;
                encoder.set_complexity(config.complexity.min(10))?;
                encoder.set_bitrate(Bitrate::BitsPerSecond(target_bitrate))?;
                encoder.set_vbr(config.use_vbr)?;
                encoder.set_inband_fec(config.enable_fec)?;
                encoder.set_dtx(config.enable_dtx)?;
                VoiceEncoderBackend::Opus { encoder }
            }
            AudioCodec::RawPcm => VoiceEncoderBackend::Raw,
        };
        Ok(Self {
            backend,
            codec: config.codec,
            frame_samples_per_channel,
            channels: config.channels,
            max_packet_size: config.max_packet_size,
            sequence: 0,
            duration_ms: config.frame_duration_ms,
            bitrate: config.bitrate,
        })
    }

    /// Encodes a PCM frame into a transport-ready payload.
    ///
    /// # Errors
    /// Returns `MediaError` when PCM length is unexpected or encoding fails.
    pub fn encode(&mut self, pcm: &[i16], timestamp_ms: u64) -> MediaResult<VoiceFrame> {
        let expected = self.frame_samples_per_channel * usize::from(self.channels);
        if pcm.len() != expected {
            return Err(MediaError::InvalidConfig("pcm frame length mismatch"));
        }
        let level = audio_level_from_pcm(pcm);
        let (payload, source) = match &mut self.backend {
            VoiceEncoderBackend::Opus { encoder, .. } => {
                let mut buffer = vec![0u8; self.max_packet_size];
                let encoded_len = encoder.encode(pcm, &mut buffer)?;
                buffer.truncate(encoded_len);
                (buffer, MediaSourceMode::Encoded)
            }
            VoiceEncoderBackend::Raw => {
                let mut buffer = Vec::with_capacity(expected * 2);
                for sample in pcm {
                    buffer.extend_from_slice(&sample.to_le_bytes());
                }
                (buffer, MediaSourceMode::Raw)
            }
        };
        let frame = VoiceFrame {
            sequence: self.sequence,
            timestamp_ms,
            duration_ms: self.duration_ms,
            payload,
            level,
            codec: self.codec,
            source,
        };
        self.sequence = self.sequence.wrapping_add(1);
        Ok(frame)
    }

    /// Updates the target bitrate for the encoder.
    ///
    /// # Errors
    /// Returns `MediaError::Unsupported` for codecs without bitrate control.
    pub fn set_bitrate(&mut self, bitrate: u32) -> MediaResult<()> {
        if !matches!(self.backend, VoiceEncoderBackend::Opus { .. }) {
            return Err(MediaError::Unsupported);
        }
        let target = i32::try_from(bitrate)
            .map_err(|_| MediaError::InvalidConfig("bitrate out of range"))?;
        if target <= 0 {
            return Err(MediaError::InvalidConfig("bitrate out of range"));
        }
        if let VoiceEncoderBackend::Opus { encoder, .. } = &mut self.backend {
            encoder.set_bitrate(Bitrate::BitsPerSecond(target))?;
        }
        self.bitrate = bitrate;
        Ok(())
    }

    #[must_use]
    pub fn bitrate(&self) -> u32 {
        self.bitrate
    }

    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.frame_samples_per_channel * usize::from(self.channels)
    }

    #[must_use]
    pub fn duration_ms(&self) -> u16 {
        self.duration_ms
    }
}

enum VoiceDecoderBackend {
    Opus {
        decoder: OpusDecoder,
        channels: Channels,
    },
    Raw,
}

pub struct VoiceDecoder {
    backend: VoiceDecoderBackend,
    codec: AudioCodec,
    config: VoiceDecoderConfig,
    frame_samples_per_channel: usize,
}

impl VoiceDecoder {
    /// Creates a decoder for the requested audio codec.
    ///
    /// # Errors
    /// Returns `MediaError` when configuration is invalid or codec initialisation fails.
    pub fn new(config: VoiceDecoderConfig) -> MediaResult<Self> {
        if config.channels == 0 {
            return Err(MediaError::InvalidConfig("channel count must be > 0"));
        }
        let frame_samples_per_channel =
            frame_samples_per_channel(config.sample_rate, config.frame_duration_ms)?;
        let backend = match config.codec {
            AudioCodec::Opus => {
                let sample_rate = opus_sample_rate(config.sample_rate)?;
                let channels = opus_channels(config.channels)?;
                let decoder = OpusDecoder::new(sample_rate, channels)?;
                VoiceDecoderBackend::Opus { decoder, channels }
            }
            AudioCodec::RawPcm => VoiceDecoderBackend::Raw,
        };
        Ok(Self {
            backend,
            codec: config.codec,
            config,
            frame_samples_per_channel,
        })
    }

    fn switch_backend(&mut self, codec: AudioCodec) -> MediaResult<()> {
        if codec == self.codec {
            return Ok(());
        }
        self.backend = match codec {
            AudioCodec::Opus => {
                let sample_rate = opus_sample_rate(self.config.sample_rate)?;
                let channels = opus_channels(self.config.channels)?;
                let decoder = OpusDecoder::new(sample_rate, channels)?;
                VoiceDecoderBackend::Opus { decoder, channels }
            }
            AudioCodec::RawPcm => VoiceDecoderBackend::Raw,
        };
        self.codec = codec;
        Ok(())
    }

    /// Decodes an audio frame.
    ///
    /// # Errors
    /// Returns `MediaError` when decoding fails or payload does not match expectations.
    ///
    /// # Panics
    /// The raw PCM branch relies on fixed-size chunk extraction; the validation performed on
    /// payload length guarantees the chunk size, so this panic path is unreachable for valid
    /// inputs.
    pub fn decode(
        &mut self,
        codec: AudioCodec,
        payload: &[u8],
        fec: bool,
    ) -> MediaResult<Vec<i16>> {
        self.switch_backend(codec)?;
        match &mut self.backend {
            VoiceDecoderBackend::Opus { decoder, channels } => {
                let mut buffer =
                    vec![0i16; self.frame_samples_per_channel * channel_count(*channels)];
                let signals = MutSignals::try_from(buffer.as_mut_slice())
                    .map_err(|err| MediaError::Codec(err.to_string()))?;
                let packet = if payload.is_empty() {
                    None
                } else {
                    Some(
                        Packet::try_from(payload)
                            .map_err(|err| MediaError::Codec(err.to_string()))?,
                    )
                };
                let decoded = decoder
                    .decode(packet, signals, fec)
                    .map_err(|err| MediaError::Codec(err.to_string()))?;
                let total = decoded * channel_count(*channels);
                buffer.truncate(total);
                Ok(buffer)
            }
            VoiceDecoderBackend::Raw => {
                let channels = usize::from(self.config.channels);
                let expected = self.frame_samples_per_channel * channels;
                if payload.len() != expected * 2 {
                    return Err(MediaError::InvalidConfig("raw pcm payload size mismatch"));
                }
                let mut output = Vec::with_capacity(expected);
                for chunk in payload.chunks_exact(2) {
                    let bytes = <[u8; 2]>::try_from(chunk)
                        .expect("chunk size is guaranteed by chunks_exact");
                    output.push(i16::from_le_bytes(bytes));
                }
                Ok(output)
            }
        }
    }

    /// Requests PLC (packet loss concealment) output from the decoder.
    ///
    /// # Errors
    /// Returns `MediaError::Unsupported` for codecs without PLC.
    pub fn conceal_loss(&mut self) -> MediaResult<Vec<i16>> {
        match &mut self.backend {
            VoiceDecoderBackend::Opus { decoder, channels } => {
                let mut buffer =
                    vec![0i16; self.frame_samples_per_channel * channel_count(*channels)];
                let signals = MutSignals::try_from(buffer.as_mut_slice())
                    .map_err(|err| MediaError::Codec(err.to_string()))?;
                let decoded = decoder
                    .decode(None, signals, false)
                    .map_err(|err| MediaError::Codec(err.to_string()))?;
                let total = decoded * channel_count(*channels);
                buffer.truncate(total);
                Ok(buffer)
            }
            VoiceDecoderBackend::Raw => Ok(vec![
                0i16;
                self.frame_samples_per_channel
                    * usize::from(self.config.channels)
            ]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_roundtrip_opus() {
        let mut encoder = VoiceEncoder::new(VoiceEncoderConfig::default()).expect("encoder");
        let mut voice_decoder = VoiceDecoder::new(VoiceDecoderConfig::default()).expect("decoder");
        let samples = encoder.frame_samples();
        let mut pcm = vec![0i16; samples];
        for (idx, sample) in pcm.iter_mut().enumerate() {
            let phase = i32::try_from(idx % 128).expect("phase range");
            let centered = phase - 64;
            let value = centered * 512;
            *sample = i16::try_from(value).expect("value fits i16");
        }
        let frame = encoder.encode(&pcm, 0).expect("encode");
        assert!(frame.payload().len() < 200);
        assert_eq!(frame.codec, AudioCodec::Opus);
        assert_eq!(frame.source, MediaSourceMode::Encoded);
        let decoded_pcm = voice_decoder
            .decode(frame.codec, frame.payload(), false)
            .expect("decode");
        assert_eq!(decoded_pcm.len(), pcm.len());
    }

    #[test]
    fn voice_roundtrip_raw_pcm() {
        let mut encoder = VoiceEncoder::new(VoiceEncoderConfig {
            codec: AudioCodec::RawPcm,
            ..VoiceEncoderConfig::default()
        })
        .expect("raw encoder");
        let mut raw_decoder = VoiceDecoder::new(VoiceDecoderConfig {
            codec: AudioCodec::RawPcm,
            source: MediaSourceMode::Raw,
            ..VoiceDecoderConfig::default()
        })
        .expect("raw decoder");
        let samples = encoder.frame_samples();
        let pcm: Vec<i16> = (0..samples)
            .map(|v| {
                let bounded = i32::try_from(v % i16::MAX as usize).expect("bounded fits i32");
                let scaled = (bounded * 3) % i32::from(i16::MAX);
                i16::try_from(scaled).expect("scaled fits i16")
            })
            .collect();
        let frame = encoder.encode(&pcm, 42).expect("encode");
        assert_eq!(frame.codec, AudioCodec::RawPcm);
        assert_eq!(frame.source, MediaSourceMode::Raw);
        let decoded_pcm = raw_decoder
            .decode(frame.codec, frame.payload(), false)
            .expect("decode");
        assert_eq!(decoded_pcm, pcm);
    }
}
