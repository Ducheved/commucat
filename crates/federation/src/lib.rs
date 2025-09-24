use blake3::Hasher;
use chrono::{DateTime, Utc};
use commucat_crypto::{EventSigner, EventVerifier};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum FederationError {
    Signature,
    DigestMismatch,
}

impl Display for FederationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Signature => write!(f, "signature validation failed"),
            Self::DigestMismatch => write!(f, "digest mismatch"),
        }
    }
}

impl Error for FederationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationEvent {
    pub event_id: String,
    pub origin: String,
    pub created_at: DateTime<Utc>,
    pub payload: serde_json::Value,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    pub event: FederationEvent,
    pub signature: [u8; 64],
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub domain: String,
    pub endpoint: String,
    pub public_key: [u8; 32],
    pub last_seen: Option<DateTime<Utc>>,
}

/// Computes a BLAKE3 digest for a federation event.
pub fn digest_event(event: &FederationEvent) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(event.event_id.as_bytes());
    hasher.update(event.origin.as_bytes());
    hasher.update(event.scope.as_bytes());
    let timestamp = event.created_at.timestamp_nanos_opt().unwrap_or_default();
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(event.payload.to_string().as_bytes());
    let hash = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(hash.as_bytes());
    digest
}

/// Produces a signed event envelope suitable for federation transport.
pub fn sign_event(event: FederationEvent, signer: &EventSigner) -> SignedEvent {
    let digest = digest_event(&event);
    let signature = signer.sign(&digest);
    SignedEvent {
        event,
        signature,
        digest,
    }
}

/// Validates a signed event against a known peer descriptor.
pub fn verify_event(signed: &SignedEvent, verifier: &EventVerifier) -> Result<(), FederationError> {
    let digest = digest_event(&signed.event);
    if digest != signed.digest {
        return Err(FederationError::DigestMismatch);
    }
    verifier
        .verify(&signed.digest, &signed.signature)
        .map_err(|_| FederationError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commucat_crypto::DeviceKeyPair;

    #[test]
    fn sign_verify_roundtrip() {
        let keys = DeviceKeyPair::from_seed(b"federation-federation-federation-seed").unwrap();
        let signer = EventSigner::new(&keys);
        let verifier = EventVerifier {
            public: keys.public,
        };
        let event = FederationEvent {
            event_id: "evt-1".to_string(),
            origin: "example.org".to_string(),
            created_at: Utc::now(),
            payload: serde_json::json!({"channel": "123", "payload": "cipher"}),
            scope: "relay".to_string(),
        };
        let signed = sign_event(event, &signer);
        verify_event(&signed, &verifier).unwrap();
    }

    #[test]
    fn verify_event_rejects_tampered_payload() {
        let keys = DeviceKeyPair::from_seed(b"tamper-detection-seed-tamper-detect").unwrap();
        let signer = EventSigner::new(&keys);
        let verifier = EventVerifier {
            public: keys.public,
        };
        let event = FederationEvent {
            event_id: "evt-2".to_string(),
            origin: "example.org".to_string(),
            created_at: Utc::now(),
            payload: serde_json::json!({"channel": "1337", "payload": "cipher"}),
            scope: "relay".to_string(),
        };
        let mut signed = sign_event(event, &signer);
        signed.event.payload = serde_json::json!({"channel": "1337", "payload": "altered"});
        assert!(verify_event(&signed, &verifier).is_err());
    }
}
