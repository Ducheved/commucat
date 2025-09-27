use crate::util::{decode_hex, decode_hex32};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration as StdDuration;

pub const ROTATION_PROOF_CONTEXT: &[u8] = b"commucat:device-rotation:v1";
const MIN_NONCE_LENGTH: usize = 8;

#[derive(Debug, Deserialize)]
pub struct DeviceRotationRequest {
    pub public_key: String,
    pub signature: String,
    pub expires_at: String,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DecodedRotationRequest {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
    pub expires_at: DateTime<Utc>,
    pub nonce: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum RotationRequestError {
    InvalidPublicKey,
    InvalidSignature,
    InvalidExpiresAt,
    Expired,
    ExpiresTooFar,
    InvalidNonce,
}

#[derive(Debug, Serialize)]
pub struct RotationNotification<'a> {
    pub r#type: &'a str,
    pub device_id: &'a str,
    pub user_id: &'a str,
    pub public_key: &'a str,
    pub old_public_key: &'a str,
    pub rotation_id: &'a str,
    pub event_id: &'a str,
    pub certificate: &'a serde_json::Value,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl DeviceRotationRequest {
    pub fn decode(
        self,
        now: DateTime<Utc>,
        proof_ttl: StdDuration,
    ) -> Result<DecodedRotationRequest, RotationRequestError> {
        let public_key =
            decode_hex32(&self.public_key).map_err(|_| RotationRequestError::InvalidPublicKey)?;
        let signature_bytes =
            decode_hex(&self.signature).map_err(|_| RotationRequestError::InvalidSignature)?;
        if signature_bytes.len() != 64 {
            return Err(RotationRequestError::InvalidSignature);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&signature_bytes);
        let expires_at = DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| RotationRequestError::InvalidExpiresAt)?
            .with_timezone(&Utc);
        if expires_at <= now {
            return Err(RotationRequestError::Expired);
        }
        let ttl =
            ChronoDuration::from_std(proof_ttl).map_err(|_| RotationRequestError::ExpiresTooFar)?;
        if expires_at - now > ttl {
            return Err(RotationRequestError::ExpiresTooFar);
        }
        let nonce = match self.nonce {
            Some(value) => {
                let decoded = decode_hex(&value).map_err(|_| RotationRequestError::InvalidNonce)?;
                if decoded.len() < MIN_NONCE_LENGTH {
                    return Err(RotationRequestError::InvalidNonce);
                }
                Some(decoded)
            }
            None => None,
        };
        Ok(DecodedRotationRequest {
            public_key,
            signature,
            expires_at,
            nonce,
        })
    }
}

pub fn rotation_proof_message(
    device_id: &str,
    public_key: &[u8; 32],
    expires_at: DateTime<Utc>,
    nonce: Option<&[u8]>,
) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROTATION_PROOF_CONTEXT);
    hasher.update(device_id.as_bytes());
    hasher.update(public_key);
    hasher.update(&expires_at.timestamp().to_be_bytes());
    if let Some(value) = nonce {
        hasher.update(value);
    }
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_message_changes_with_inputs() {
        let device = "device-1";
        let key = [1u8; 32];
        let expires = Utc::now() + ChronoDuration::seconds(60);
        let digest_without_nonce = rotation_proof_message(device, &key, expires, None);
        let digest_with_nonce = rotation_proof_message(device, &key, expires, Some(&[5u8; 8]));
        assert_ne!(
            digest_without_nonce.as_bytes(),
            digest_with_nonce.as_bytes()
        );
    }

    #[test]
    fn decode_rejects_short_nonce() {
        let request = DeviceRotationRequest {
            public_key: "00".repeat(32),
            signature: "11".repeat(64),
            expires_at: (Utc::now() + ChronoDuration::seconds(30)).to_rfc3339(),
            nonce: Some("aa".to_string()),
        };
        let result = request.decode(Utc::now(), StdDuration::from_secs(60));
        assert!(matches!(result, Err(RotationRequestError::InvalidNonce)));
    }
}
