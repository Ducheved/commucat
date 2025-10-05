use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

#[derive(Debug, Clone)]
pub struct FecProfile {
    pub mtu: u16,
    pub repair_overhead: f32,
}

impl FecProfile {
    pub const fn new(mtu: u16, repair_overhead: f32) -> Self {
        Self {
            mtu,
            repair_overhead,
        }
    }

    pub fn default_low_latency() -> Self {
        Self {
            mtu: 1200,
            repair_overhead: 0.25,
        }
    }

    pub fn repair_packets(&self, source_symbol_count: usize) -> u32 {
        if source_symbol_count == 0 {
            return 0;
        }
        if self.repair_overhead <= 0.0 {
            return 0;
        }
        let overhead = (source_symbol_count as f32 * self.repair_overhead).ceil() as u32;
        overhead.max(1)
    }
}

pub struct RaptorqEncoder {
    profile: FecProfile,
}

impl RaptorqEncoder {
    pub fn new(profile: FecProfile) -> Self {
        Self { profile }
    }

    pub fn encode(&self, payload: &[u8]) -> FecBatch {
        if payload.is_empty() {
            return FecBatch {
                oti: ObjectTransmissionInformation::with_defaults(0, self.profile.mtu),
                systematic: Vec::new(),
                repair: Vec::new(),
            };
        }
        let encoder = Encoder::with_defaults(payload, self.profile.mtu);
        let oti = encoder.get_config();
        let mut systematic = Vec::new();
        let mut repair = Vec::new();
        for block in encoder.get_block_encoders() {
            let systematic_packets: Vec<Vec<u8>> = block
                .source_packets()
                .into_iter()
                .map(|packet| packet.serialize())
                .collect();
            let repair_needed = self.profile.repair_packets(systematic_packets.len());
            let repair_packets: Vec<Vec<u8>> = if repair_needed > 0 {
                block
                    .repair_packets(0, repair_needed)
                    .into_iter()
                    .map(|packet| packet.serialize())
                    .collect()
            } else {
                Vec::new()
            };
            systematic.extend(systematic_packets);
            repair.extend(repair_packets);
        }
        FecBatch {
            oti,
            systematic,
            repair,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FecBatch {
    pub oti: ObjectTransmissionInformation,
    pub systematic: Vec<Vec<u8>>,
    pub repair: Vec<Vec<u8>>,
}

#[allow(dead_code)]
pub struct RaptorqDecoder {
    decoder: Decoder,
}

#[allow(dead_code)]
impl RaptorqDecoder {
    pub fn new(oti: ObjectTransmissionInformation) -> Self {
        Self {
            decoder: Decoder::new(oti),
        }
    }

    pub fn absorb(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 4 {
            return None;
        }
        let encoding = EncodingPacket::deserialize(packet);
        self.decoder.decode(encoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raptorq_roundtrip_with_repair() {
        let profile = FecProfile::new(1024, 0.5);
        let encoder = RaptorqEncoder::new(profile.clone());
        let payload = b"hello secure world".repeat(32);
        let batch = encoder.encode(&payload);
        assert!(!batch.systematic.is_empty());
        assert!(!batch.repair.is_empty());
        let mut decoder = RaptorqDecoder::new(batch.oti);
        let mut recovered = None;
        for packet in batch.systematic.iter().chain(batch.repair.iter()).skip(1) {
            recovered = decoder.absorb(packet);
            if recovered.is_some() {
                break;
            }
        }
        assert_eq!(recovered.unwrap(), payload);
    }
}
