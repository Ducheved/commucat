use crate::audio::{
    VoiceDecoder, VoiceDecoderConfig, VoiceEncoder, VoiceEncoderConfig, VoiceFrame,
};
use crate::{MediaError, MediaResult};

#[derive(Debug, Clone, Copy, Default)]
pub struct PipelineConfig {
    pub voice: VoiceEncoderConfig,
}

pub struct CallMediaPipeline {
    encoder: VoiceEncoder,
    decoder: VoiceDecoder,
}

impl CallMediaPipeline {
    /// Prepares encoder and decoder pipelines for a call.
    ///
    /// # Errors
    /// Returns `MediaError` if either codec backend fails to initialise.
    pub fn new(config: PipelineConfig) -> MediaResult<Self> {
        let decoder_cfg = VoiceDecoderConfig {
            sample_rate: config.voice.sample_rate,
            channels: config.voice.channels,
            frame_duration_ms: config.voice.frame_duration_ms,
        };
        Ok(Self {
            encoder: VoiceEncoder::new(config.voice)?,
            decoder: VoiceDecoder::new(decoder_cfg)?,
        })
    }

    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.encoder.frame_samples()
    }

    /// Encodes a PCM chunk into an Opus frame ready for transport.
    ///
    /// # Errors
    /// Returns `MediaError::InvalidConfig` when the supplied PCM length is unexpected or
    /// `MediaError::Codec` when encoding fails.
    pub fn encode_audio(&mut self, pcm: &[i16], timestamp_ms: u64) -> MediaResult<VoiceFrame> {
        if pcm.len() != self.encoder.frame_samples() {
            return Err(MediaError::InvalidConfig("pcm chunk length mismatch"));
        }
        self.encoder.encode(pcm, timestamp_ms)
    }

    /// Decodes a received Opus frame, optionally requesting FEC data.
    ///
    /// # Errors
    /// Forwards decoding failures from the Opus backend.
    pub fn decode_audio(&mut self, frame: &[u8], fec: bool) -> MediaResult<Vec<i16>> {
        self.decoder.decode(frame, fec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn pipeline_roundtrip() {
        let mut pipeline = CallMediaPipeline::new(PipelineConfig::default()).expect("pipeline");
        let mut pcm = vec![0i16; pipeline.frame_samples()];
        for (idx, sample) in pcm.iter_mut().enumerate() {
            let phase = i16::try_from(idx % 128).expect("phase fits i16");
            *sample = phase.wrapping_mul(23);
        }
        let voice_frame = pipeline.encode_audio(&pcm, 0).expect("encode");
        let decoded_pcm = pipeline
            .decode_audio(voice_frame.payload(), false)
            .expect("decode");
        assert_eq!(decoded_pcm.len(), pcm.len());
    }
}
