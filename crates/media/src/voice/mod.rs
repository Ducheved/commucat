use crate::audio::{VoiceDecoder, VoiceDecoderConfig, VoiceEncoder, VoiceEncoderConfig};
use crate::{MediaError, MediaResult};
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct VoiceMessage {
    pub codec: &'static str,
    pub frames: Vec<Vec<u8>>,
    pub frame_duration_ms: u16,
    pub sample_rate: u32,
    pub channels: u8,
    pub total_duration_ms: u32,
}

impl VoiceMessage {
    /// Encodes raw PCM data into an Opus-framed voice message.
    ///
    /// # Errors
    /// Returns `MediaError::InvalidConfig` or `MediaError::Codec` when encoding fails.
    pub fn encode_pcm(pcm: &[i16], config: VoiceEncoderConfig) -> MediaResult<Self> {
        let mut encoder = VoiceEncoder::new(config)?;
        let frame_samples = encoder.frame_samples();
        let mut frames = Vec::new();
        let mut timestamp = 0u64;
        let mut processed_samples = 0usize;
        while processed_samples < pcm.len() {
            let remaining = &pcm[processed_samples..];
            let frame_pcm = if remaining.len() >= frame_samples {
                remaining[..frame_samples].to_vec()
            } else {
                let mut padded = vec![0i16; frame_samples];
                padded[..remaining.len()].copy_from_slice(remaining);
                padded
            };
            let frame = encoder.encode(&frame_pcm, timestamp)?;
            frames.push(frame.payload().to_vec());
            processed_samples += frame_samples.min(remaining.len());
            timestamp += u64::from(config.frame_duration_ms);
        }
        if frames.is_empty() {
            let silence = vec![0i16; frame_samples];
            frames.push(encoder.encode(&silence, 0)?.payload().to_vec());
        }
        let total_duration_ms = u32::try_from(timestamp)
            .map_err(|_| MediaError::InvalidConfig("voice message duration overflow"))?;
        Ok(Self {
            codec: "audio/opus",
            frames,
            frame_duration_ms: config.frame_duration_ms,
            sample_rate: config.sample_rate,
            channels: config.channels,
            total_duration_ms,
        })
    }

    /// Decodes the stored Opus frames back into PCM.
    ///
    /// # Errors
    /// Propagates decoder failures from the Opus backend.
    pub fn decode_pcm(&self) -> MediaResult<Vec<i16>> {
        let mut voice_decoder = VoiceDecoder::new(VoiceDecoderConfig {
            sample_rate: self.sample_rate,
            channels: self.channels,
            frame_duration_ms: self.frame_duration_ms,
        })?;
        let mut output = Vec::new();
        for frame in &self.frames {
            let mut decoded_chunk = voice_decoder.decode(frame, false)?;
            output.append(&mut decoded_chunk);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voice_message_roundtrip() {
        let config = VoiceEncoderConfig::default();
        let rate = usize::try_from(config.sample_rate).expect("rate fits usize");
        let channels = usize::from(config.channels);
        let samples = rate / 10 * channels;
        let pcm = vec![123i16; samples];
        let message = VoiceMessage::encode_pcm(&pcm, config).expect("encode");
        let decoded_pcm = message.decode_pcm().expect("decode");
        assert!(!message.frames.is_empty());
        assert!(decoded_pcm.len() >= pcm.len());
    }
}
