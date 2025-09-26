use crate::audio::{VoiceDecoder, VoiceDecoderConfig, VoiceEncoder, VoiceEncoderConfig};
use crate::{MediaError, MediaResult};
use commucat_media_types::{AudioCodec, MediaSourceMode};
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct VoiceMessage {
    pub codec: AudioCodec,
    pub source: MediaSourceMode,
    pub frames: Vec<Vec<u8>>,
    pub frame_duration_ms: u16,
    pub sample_rate: u32,
    pub channels: u8,
    pub total_duration_ms: u32,
}

impl VoiceMessage {
    /// Encodes raw PCM data into a voice message comprised of transport frames.
    ///
    /// # Errors
    /// Returns `MediaError::InvalidConfig` or `MediaError::Codec` when encoding fails.
    pub fn encode_pcm(pcm: &[i16], config: VoiceEncoderConfig) -> MediaResult<Self> {
        let mut encoder = VoiceEncoder::new(config)?;
        let frame_samples = encoder.frame_samples();
        let mut frames = Vec::new();
        let mut timestamp = 0u64;
        let mut processed_samples = 0usize;
        let mut detected_source = MediaSourceMode::Encoded;
        let mut detected_codec = config.codec;
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
            detected_source = frame.source;
            detected_codec = frame.codec;
            frames.push(frame.payload().to_vec());
            processed_samples += frame_samples.min(remaining.len());
            timestamp += u64::from(config.frame_duration_ms);
        }
        if frames.is_empty() {
            let silence = vec![0i16; frame_samples];
            let frame = encoder.encode(&silence, 0)?;
            detected_source = frame.source;
            detected_codec = frame.codec;
            frames.push(frame.payload().to_vec());
        }
        let total_duration_ms = u32::try_from(timestamp)
            .map_err(|_| MediaError::InvalidConfig("voice message duration overflow"))?;
        Ok(Self {
            codec: detected_codec,
            source: detected_source,
            frames,
            frame_duration_ms: config.frame_duration_ms,
            sample_rate: config.sample_rate,
            channels: config.channels,
            total_duration_ms,
        })
    }

    /// Decodes the stored frames back into PCM.
    ///
    /// # Errors
    /// Propagates decoder failures from the codec backend.
    pub fn decode_pcm(&self) -> MediaResult<Vec<i16>> {
        let mut voice_decoder = VoiceDecoder::new(VoiceDecoderConfig {
            codec: self.codec,
            sample_rate: self.sample_rate,
            channels: self.channels,
            frame_duration_ms: self.frame_duration_ms,
            source: self.source,
        })?;
        let mut output = Vec::new();
        for frame in &self.frames {
            let mut decoded_chunk = voice_decoder.decode(self.codec, frame, false)?;
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
        assert_eq!(message.codec, AudioCodec::Opus);
        assert_eq!(message.source, MediaSourceMode::Encoded);
    }

    #[test]
    fn voice_message_roundtrip_raw_pcm() {
        let config = VoiceEncoderConfig {
            codec: AudioCodec::RawPcm,
            ..VoiceEncoderConfig::default()
        };
        let rate = usize::try_from(config.sample_rate).expect("rate fits usize");
        let samples = rate / 20 * usize::from(config.channels);
        let pcm: Vec<i16> = (0..samples)
            .map(|idx| {
                let bounded = i32::try_from(idx % i16::MAX as usize).expect("bounded fits i32");
                let scaled = (bounded * 11) % i32::from(i16::MAX);
                i16::try_from(scaled).expect("scaled fits i16")
            })
            .collect();
        let message = VoiceMessage::encode_pcm(&pcm, config).expect("encode");
        let decoded_pcm = message.decode_pcm().expect("decode");
        assert_eq!(message.codec, AudioCodec::RawPcm);
        assert_eq!(message.source, MediaSourceMode::Raw);
        assert!(decoded_pcm.len() >= pcm.len());
        assert_eq!(&decoded_pcm[..pcm.len()], pcm.as_slice());
    }
}
