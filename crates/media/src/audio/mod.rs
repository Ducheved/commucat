use crate::{MediaError, MediaResult};
use audiopus::coder::{Decoder as OpusDecoder, Encoder as OpusEncoder};
use audiopus::{packet::Packet, Application, Bitrate, Channels, MutSignals, SampleRate};
use std::convert::TryFrom;
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct AudioLevel {
    pub peak: f32,
    pub rms: f32,
}

impl AudioLevel {
    pub const SILENT: Self = Self { peak: 0.0, rms: 0.0 };
}

#[derive(Debug, Clone)]
pub struct VoiceFrame {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub duration_ms: u16,
    pub payload: Vec<u8>,
    pub level: AudioLevel,
}

impl VoiceFrame {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn duration(&self) -> Duration {
        Duration::from_millis(self.duration_ms as u64)
    }
}

#[derive(Debug, Clone)]
pub struct VoiceEncoderConfig {
    pub sample_rate: u32,
    pub channels: u8,
    pub frame_duration_ms: u16,
    pub bitrate: u32,
    pub use_vbr: bool,
    pub enable_fec: bool,
    pub enable_dtx: bool,
    pub complexity: u8,
    pub max_packet_size: usize,
}

impl Default for VoiceEncoderConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48_000,
            channels: 1,
            frame_duration_ms: 20,
            bitrate: 16_000,
            use_vbr: true,
            enable_fec: true,
            enable_dtx: true,
            complexity: 9,
            max_packet_size: 4_096,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VoiceDecoderConfig {
    pub sample_rate: u32,
    pub channels: u8,
    pub frame_duration_ms: u16,
}

impl Default for VoiceDecoderConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48_000,
            channels: 1,
            frame_duration_ms: 20,
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

pub(crate) fn frame_samples_per_channel(sample_rate: u32, frame_duration_ms: u16) -> MediaResult<usize> {
    if frame_duration_ms == 0 {
        return Err(MediaError::InvalidConfig("frame duration must be positive"));
    }
    let numer = sample_rate as u64 * frame_duration_ms as u64;
    if numer % 1_000 != 0 {
        return Err(MediaError::InvalidConfig(
            "frame duration does not align with sample rate",
        ));
    }
    Ok((numer / 1_000) as usize)
}

fn audio_level_from_pcm(pcm: &[i16]) -> AudioLevel {
    if pcm.is_empty() {
        return AudioLevel::SILENT;
    }
    let mut peak = 0.0_f32;
    let mut square_sum = 0.0_f32;
    for &sample in pcm {
        let value = (sample as f32) / (i16::MAX as f32);
        let abs = value.abs();
        if abs > peak {
            peak = abs;
        }
        square_sum += value * value;
    }
    let rms = (square_sum / pcm.len() as f32).sqrt();
    AudioLevel { peak, rms }
}

pub struct VoiceEncoder {
    encoder: OpusEncoder,
    frame_samples_per_channel: usize,
    channels: Channels,
    max_packet_size: usize,
    sequence: u64,
    duration_ms: u16,
    bitrate: u32,
}

impl VoiceEncoder {
    pub fn new(config: VoiceEncoderConfig) -> MediaResult<Self> {
        if config.max_packet_size == 0 {
            return Err(MediaError::InvalidConfig("max_packet_size must be > 0"));
        }
        if config.bitrate == 0 || config.bitrate > i32::MAX as u32 {
            return Err(MediaError::InvalidConfig("bitrate out of range"));
        }
        let sample_rate = opus_sample_rate(config.sample_rate)?;
        let channels = opus_channels(config.channels)?;
        let frame_samples_per_channel = frame_samples_per_channel(config.sample_rate, config.frame_duration_ms)?;
        let mut encoder = OpusEncoder::new(sample_rate, channels, Application::Voip)?;
        encoder.set_complexity(config.complexity.min(10))?;
        encoder.set_bitrate(Bitrate::BitsPerSecond(config.bitrate as i32))?;
        encoder.set_vbr(config.use_vbr)?;
        encoder.set_inband_fec(config.enable_fec)?;
        encoder.set_dtx(config.enable_dtx)?;
        Ok(Self {
            encoder,
            frame_samples_per_channel,
            channels,
            max_packet_size: config.max_packet_size,
            sequence: 0,
            duration_ms: config.frame_duration_ms,
            bitrate: config.bitrate,
        })
    }

    pub fn encode(&mut self, pcm: &[i16], timestamp_ms: u64) -> MediaResult<VoiceFrame> {
        let expected = self.frame_samples_per_channel * channel_count(self.channels);
        if pcm.len() != expected {
            return Err(MediaError::InvalidConfig("pcm frame length mismatch"));
        }
        let mut buffer = vec![0u8; self.max_packet_size];
        let encoded_len = self.encoder.encode(pcm, &mut buffer)?;
        buffer.truncate(encoded_len);
        let level = audio_level_from_pcm(pcm);
        let frame = VoiceFrame {
            sequence: self.sequence,
            timestamp_ms,
            duration_ms: self.duration_ms,
            payload: buffer,
            level,
        };
        self.sequence = self.sequence.wrapping_add(1);
        Ok(frame)
    }

    pub fn set_bitrate(&mut self, bitrate: u32) -> MediaResult<()> {
        if bitrate == 0 || bitrate > i32::MAX as u32 {
            return Err(MediaError::InvalidConfig("bitrate out of range"));
        }
        self.encoder
            .set_bitrate(Bitrate::BitsPerSecond(bitrate as i32))?;
        self.bitrate = bitrate;
        Ok(())
    }

    pub fn bitrate(&self) -> u32 {
        self.bitrate
    }

    pub fn frame_samples(&self) -> usize {
        self.frame_samples_per_channel * channel_count(self.channels)
    }

    pub fn duration_ms(&self) -> u16 {
        self.duration_ms
    }
}

pub struct VoiceDecoder {
    decoder: OpusDecoder,
    frame_samples_per_channel: usize,
    channels: Channels,
}

impl VoiceDecoder {
    pub fn new(config: VoiceDecoderConfig) -> MediaResult<Self> {
        let sample_rate = opus_sample_rate(config.sample_rate)?;
        let channels = opus_channels(config.channels)?;
        let frame_samples_per_channel = frame_samples_per_channel(config.sample_rate, config.frame_duration_ms)?;
        let decoder = OpusDecoder::new(sample_rate, channels)?;
        Ok(Self {
            decoder,
            frame_samples_per_channel,
            channels,
        })
    }

    pub fn decode(&mut self, payload: &[u8], fec: bool) -> MediaResult<Vec<i16>> {
        if payload.is_empty() {
            return self.conceal_loss();
        }
        let packet = Packet::try_from(payload).map_err(|err| MediaError::Codec(err.to_string()))?;
        self.decode_packet(Some(packet), fec)
    }

    pub fn conceal_loss(&mut self) -> MediaResult<Vec<i16>> {
        self.decode_packet(None, false)
    }

    fn decode_packet(&mut self, packet: Option<Packet<'_>>, fec: bool) -> MediaResult<Vec<i16>> {
        let mut buffer = vec![0i16; self.frame_samples_per_channel * channel_count(self.channels)];
        let mut signals = MutSignals::try_from(buffer.as_mut_slice())
            .map_err(|err| MediaError::Codec(err.to_string()))?;
        let decoded = self
            .decoder
            .decode(packet, signals, fec)
            .map_err(|err| MediaError::Codec(err.to_string()))?;
        let channels = channel_count(self.channels);
        buffer.truncate(decoded * channels);
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_roundtrip() {
        let mut encoder = VoiceEncoder::new(VoiceEncoderConfig::default()).expect("encoder");
        let mut decoder = VoiceDecoder::new(VoiceDecoderConfig::default()).expect("decoder");
        let samples = encoder.frame_samples();
        let mut pcm = vec![0i16; samples];
        for (idx, sample) in pcm.iter_mut().enumerate() {
            let phase = (idx as f32 / samples as f32) * std::f32::consts::TAU;
            *sample = (phase.sin() * i16::MAX as f32 * 0.2) as i16;
        }
        let frame = encoder.encode(&pcm, 0).expect("encode");
        assert!(frame.payload.len() < 200);
        let decoded = decoder.decode(&frame.payload, false).expect("decode");
        assert_eq!(decoded.len(), pcm.len());
    }
}
