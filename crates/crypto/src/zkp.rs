use crate::hex::{decode_hex_array, encode_hex};
use crate::{CryptoError, DeviceKeyPair};
use blake3::Hasher;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

const HANDSHAKE_DOMAIN: &[u8] = b"commucat:zkp:handshake:v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeProof {
    pub commitment: [u8; 32],
    pub response: [u8; 32],
}

impl Serialize for KnowledgeProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("KnowledgeProof", 2)?;
        state.serialize_field("commitment", &encode_hex(&self.commitment))?;
        state.serialize_field("response", &encode_hex(&self.response))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for KnowledgeProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ProofWire {
            commitment: String,
            response: String,
        }

        let wire = ProofWire::deserialize(deserializer)?;
        let commitment = decode_hex_array(&wire.commitment).map_err(serde::de::Error::custom)?;
        let response = decode_hex_array(&wire.response).map_err(serde::de::Error::custom)?;
        Ok(Self {
            commitment,
            response,
        })
    }
}

impl fmt::Display for KnowledgeProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KnowledgeProof(commitment={}, response={})",
            encode_hex(&self.commitment),
            encode_hex(&self.response)
        )
    }
}

pub fn derive_handshake_context(
    domain: &str,
    device_id: &str,
    device_public: &[u8; 32],
    client_static: &[u8; 32],
) -> Vec<u8> {
    let mut context =
        Vec::with_capacity(HANDSHAKE_DOMAIN.len() + domain.len() + device_id.len() + 2 + 64);
    context.extend_from_slice(HANDSHAKE_DOMAIN);
    context.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    context.extend_from_slice(domain.as_bytes());
    context.extend_from_slice(&(device_id.len() as u32).to_le_bytes());
    context.extend_from_slice(device_id.as_bytes());
    context.extend_from_slice(device_public);
    context.extend_from_slice(client_static);
    context
}

pub fn prove_handshake(
    keys: &DeviceKeyPair,
    context: &[u8],
) -> Result<KnowledgeProof, CryptoError> {
    prove_with_rng(keys, context, &mut OsRng)
}

pub fn prove_with_rng(
    keys: &DeviceKeyPair,
    context: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<KnowledgeProof, CryptoError> {
    let signing = SigningKey::from_bytes(&keys.private);
    let derived_public = signing.verifying_key().to_bytes();
    if derived_public != keys.public {
        return Err(CryptoError::InvalidKey);
    }
    let secret_scalar = signing.to_scalar();
    let mut randomness = [0u8; 64];
    rng.fill_bytes(&mut randomness);
    let commitment_scalar = Scalar::from_bytes_mod_order_wide(&randomness);
    let commitment_point = EdwardsPoint::mul_base(&commitment_scalar);
    let commitment = commitment_point.compress().to_bytes();
    let challenge = derive_challenge(context, &keys.public, &commitment);
    let response = (commitment_scalar + challenge * secret_scalar).to_bytes();
    Ok(KnowledgeProof {
        commitment,
        response,
    })
}

pub fn verify_handshake(
    device_public: &[u8; 32],
    context: &[u8],
    proof: &KnowledgeProof,
) -> Result<(), CryptoError> {
    let compressed_public = CompressedEdwardsY(*device_public);
    let public_point = compressed_public
        .decompress()
        .ok_or(CryptoError::ZeroKnowledgeProof)?;
    let compressed_commitment = CompressedEdwardsY(proof.commitment);
    let commitment_point = compressed_commitment
        .decompress()
        .ok_or(CryptoError::ZeroKnowledgeProof)?;
    let challenge = derive_challenge(context, device_public, &proof.commitment);
    let response_scalar_opt = Scalar::from_canonical_bytes(proof.response);
    if bool::from(response_scalar_opt.is_none()) {
        return Err(CryptoError::ZeroKnowledgeProof);
    }
    let response_scalar = response_scalar_opt.unwrap();
    let lhs = EdwardsPoint::mul_base(&response_scalar);
    let rhs = commitment_point + public_point * challenge;
    if lhs == rhs {
        Ok(())
    } else {
        Err(CryptoError::ZeroKnowledgeProof)
    }
}

fn derive_challenge(context: &[u8], public_key: &[u8; 32], commitment: &[u8; 32]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(HANDSHAKE_DOMAIN);
    hasher.update(&(context.len() as u64).to_le_bytes());
    hasher.update(context);
    hasher.update(public_key);
    hasher.update(commitment);
    let mut output = [0u8; 64];
    hasher.finalize_xof().fill(&mut output);
    Scalar::from_bytes_mod_order_wide(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_roundtrip() {
        let keys =
            DeviceKeyPair::from_seed(b"seed-seed-seed-seed-seed-seed-seed-seed").expect("keys");
        let client_static = [1u8; 32];
        let context =
            derive_handshake_context("example.org", "device-1", &keys.public, &client_static);
        let proof = prove_handshake(&keys, &context).expect("prove");
        verify_handshake(&keys.public, &context, &proof).expect("verify");
    }

    #[test]
    fn proof_rejects_tampered_response() {
        let keys =
            DeviceKeyPair::from_seed(b"seed-seed-seed-seed-seed-seed-seed-seed").expect("keys");
        let client_static = [2u8; 32];
        let context =
            derive_handshake_context("example.org", "device-1", &keys.public, &client_static);
        let mut proof = prove_handshake(&keys, &context).expect("prove");
        proof.response[0] ^= 0x01;
        assert!(verify_handshake(&keys.public, &context, &proof).is_err());
    }
}
