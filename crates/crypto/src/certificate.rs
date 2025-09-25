use crate::{CryptoError, EventSigner};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::Write as FmtWrite;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificateData {
    pub serial: u64,
    pub user_id: String,
    pub device_id: String,
    #[serde(with = "serde_hex32")]
    pub public_key: [u8; 32],
    #[serde(with = "serde_hex32")]
    pub issuer: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificate {
    #[serde(flatten)]
    pub data: DeviceCertificateData,
    #[serde(with = "serde_hex64")]
    pub signature: [u8; 64],
}

impl DeviceCertificateData {
    pub fn new(
        serial: u64,
        user_id: impl Into<String>,
        device_id: impl Into<String>,
        public_key: [u8; 32],
        issuer: [u8; 32],
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            serial,
            user_id: user_id.into(),
            device_id: device_id.into(),
            public_key,
            issuer,
            issued_at,
            expires_at,
        }
    }

    pub fn sign(&self, signer: &EventSigner) -> DeviceCertificate {
        let signature = signer.sign(&self.canonical_message());
        DeviceCertificate {
            data: self.clone(),
            signature,
        }
    }

    pub fn canonical_message(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("device certificate serialize")
    }
}

impl DeviceCertificate {
    pub fn verify(&self, authority_public: &[u8; 32]) -> Result<(), CryptoError> {
        if &self.data.issuer != authority_public {
            return Err(CryptoError::Signature);
        }
        let verifying =
            VerifyingKey::from_bytes(authority_public).map_err(|_| CryptoError::InvalidKey)?;
        let signature =
            Signature::try_from(self.signature.as_slice()).map_err(|_| CryptoError::Signature)?;
        verifying
            .verify(&self.data.canonical_message(), &signature)
            .map_err(|_| CryptoError::Signature)
    }

    pub fn data(&self) -> &DeviceCertificateData {
        &self.data
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{:02x}", byte);
    }
    output
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let expected_len = N * 2;
    if value.len() != expected_len {
        return Err(format!(
            "invalid hex length {}; expected {}",
            value.len(),
            expected_len
        ));
    }
    let mut output = [0u8; N];
    let bytes = value.as_bytes();
    for idx in 0..N {
        let hi = parse_nibble(bytes[idx * 2])?;
        let lo = parse_nibble(bytes[idx * 2 + 1])?;
        output[idx] = (hi << 4) | lo;
    }
    Ok(output)
}

fn parse_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", value as char)),
    }
}

mod serde_hex32 {
    use super::{decode_hex_array, encode_hex};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        decode_hex_array(&value).map_err(serde::de::Error::custom)
    }
}

mod serde_hex64 {
    use super::{decode_hex_array, encode_hex};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_hex(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        decode_hex_array(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceKeyPair;

    #[test]
    fn certificate_roundtrip() {
        let seed = b"seed-seed-seed-seed-seed-seed-seed-seed";
        let keys = DeviceKeyPair::from_seed(seed).expect("keys");
        let signer = EventSigner::new(&keys);
        let data =
            DeviceCertificateData::new(42, "user-1", "device-1", keys.public, keys.public, 1, 2);
        let certificate = data.sign(&signer);
        certificate.verify(&keys.public).expect("verify");
        assert_eq!(certificate.data.user_id, "user-1");
    }

    #[test]
    fn certificate_rejects_wrong_signature() {
        let seed = b"seed-seed-seed-seed-seed-seed-seed-seed";
        let keys = DeviceKeyPair::from_seed(seed).expect("keys");
        let signer = EventSigner::new(&keys);
        let mut data =
            DeviceCertificateData::new(1, "user", "device", keys.public, keys.public, 1, 2);
        let mut certificate = data.sign(&signer);
        certificate.signature[0] ^= 0x01;
        assert!(certificate.verify(&keys.public).is_err());
        data.issuer = [0u8; 32];
        let tampered = DeviceCertificate {
            data,
            signature: certificate.signature,
        };
        assert!(tampered.verify(&keys.public).is_err());
    }
}
