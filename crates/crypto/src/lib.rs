use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, TransportState};
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

mod certificate;
mod hex;
pub mod zkp;

#[cfg(feature = "pq")]
mod pq;

pub use certificate::{DeviceCertificate, DeviceCertificateData};

#[cfg(feature = "pq")]
pub use pq::{
    HybridInitiatorResult, HybridKeyMaterial, HybridRatchet, HybridResponderResult, HybridSettings,
    PqKemKeyPair, PqSignatureKeyPair, PqSignaturePublicKey, PqxdhBundle, SessionKeys, SessionRole,
    decapsulate_hybrid, encapsulate_hybrid,
};

#[derive(Debug)]
pub enum CryptoError {
    NoiseConfig,
    NoiseFailure,
    InvalidKey,
    Signature,
    KeyDerivation,
    PostQuantumSignature,
    PostQuantumEncapsulation,
    PostQuantumDecapsulation,
    ZeroKnowledgeProof,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoiseConfig => write!(f, "invalid noise configuration"),
            Self::NoiseFailure => write!(f, "noise handshake failure"),
            Self::InvalidKey => write!(f, "invalid key material"),
            Self::Signature => write!(f, "signature error"),
            Self::KeyDerivation => write!(f, "key derivation failure"),
            Self::PostQuantumSignature => write!(f, "ml-dsa signature failure"),
            Self::PostQuantumEncapsulation => write!(f, "ml-kem encapsulation failure"),
            Self::PostQuantumDecapsulation => write!(f, "ml-kem decapsulation failure"),
            Self::ZeroKnowledgeProof => write!(f, "zero-knowledge proof verification failed"),
        }
    }
}

impl Error for CryptoError {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HandshakePattern {
    Xk,
    Ik,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseConfig {
    pub pattern: HandshakePattern,
    pub prologue: Vec<u8>,
    pub local_private: [u8; 32],
    pub local_static_public: Option<[u8; 32]>,
    pub remote_static_public: Option<[u8; 32]>,
}

/// Initializes Noise handshakes for CommuCat tunnels.
pub fn build_handshake(
    config: &NoiseConfig,
    initiator: bool,
) -> Result<NoiseHandshake, CryptoError> {
    let params = match config.pattern {
        HandshakePattern::Xk => "Noise_XK_25519_ChaChaPoly_BLAKE2s",
        HandshakePattern::Ik => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
    };
    let params: NoiseParams = params.parse().map_err(|_| CryptoError::NoiseConfig)?;
    let mut builder = Builder::new(params);
    builder = builder
        .prologue(&config.prologue)
        .map_err(|_| CryptoError::NoiseConfig)?;
    builder = builder
        .local_private_key(&config.local_private)
        .map_err(|_| CryptoError::NoiseConfig)?;
    if let Some(remote) = config.remote_static_public.as_ref() {
        builder = builder
            .remote_public_key(remote)
            .map_err(|_| CryptoError::NoiseConfig)?;
    }
    #[cfg(test)]
    {
        builder = builder.fixed_ephemeral_key_for_testing_only(&config.local_private);
    }
    let state = if initiator {
        builder
            .build_initiator()
            .map_err(|_| CryptoError::NoiseConfig)?
    } else {
        builder
            .build_responder()
            .map_err(|_| CryptoError::NoiseConfig)?
    };
    Ok(NoiseHandshake { state })
}

pub struct NoiseHandshake {
    state: HandshakeState,
}

impl NoiseHandshake {
    /// Processes an outbound handshake message and returns the serialized payload.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; payload.len() + 256];
        let len = self
            .state
            .write_message(payload, &mut buffer)
            .map_err(|_| CryptoError::NoiseFailure)?;
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Consumes an inbound handshake message and returns the decrypted payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; message.len()];
        let len = self
            .state
            .read_message(message, &mut buffer)
            .map_err(|_| CryptoError::NoiseFailure)?;
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Finalizes the handshake and returns a transport object.
    pub fn into_transport(self) -> Result<NoiseTransport, CryptoError> {
        let state = self
            .state
            .into_transport_mode()
            .map_err(|_| CryptoError::NoiseFailure)?;
        Ok(NoiseTransport { state })
    }
}

pub struct NoiseTransport {
    state: TransportState,
}

impl NoiseTransport {
    /// Encrypts payload into a Noise transport message.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; payload.len() + 32];
        let len = self
            .state
            .write_message(payload, &mut buffer)
            .map_err(|_| CryptoError::NoiseFailure)?;
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Decrypts a Noise transport message.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = vec![0u8; message.len()];
        let len = self
            .state
            .read_message(message, &mut buffer)
            .map_err(|_| CryptoError::NoiseFailure)?;
        buffer.truncate(len);
        Ok(buffer)
    }
}

/// Generates a fresh Noise static key pair for the server.
pub fn generate_noise_static_keypair() -> ([u8; 32], [u8; 32]) {
    let mut rng = OsRng;
    let private = StaticSecret::random_from_rng(&mut rng);
    let public = X25519PublicKey::from(&private);
    (private.to_bytes(), public.to_bytes())
}

/// Derives the Noise static public key from a private scalar.
pub fn derive_noise_public_key(private: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    let public = X25519PublicKey::from(&secret);
    public.to_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceKeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

impl DeviceKeyPair {
    /// Derives a deterministic device key pair from seed material.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() < 32 {
            return Err(CryptoError::InvalidKey);
        }
        let mut hasher = Hasher::new();
        hasher.update(seed);
        let derived = hasher.finalize();
        let mut private = [0u8; 32];
        private.copy_from_slice(&derived.as_bytes()[..32]);
        let signing = SigningKey::from_bytes(&private);
        let public: [u8; 32] = signing.verifying_key().to_bytes();
        Ok(Self { public, private })
    }

    /// Signs a message using the device key pair.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        let signing = SigningKey::from_bytes(&self.private);
        let signature = signing.sign(message);
        Ok(signature.to_bytes())
    }
}

pub struct EventSigner {
    signing: SigningKey,
}

impl EventSigner {
    /// Creates an event signer from a device key pair.
    pub fn new(keys: &DeviceKeyPair) -> Self {
        let signing = SigningKey::from_bytes(&keys.private);
        Self { signing }
    }

    /// Returns the Ed25519 public key of the signer.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Signs arbitrary payloads with Ed25519.
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing.sign(payload).to_bytes()
    }

    /// Signs a device certificate dataset.
    pub fn sign_certificate(&self, data: &DeviceCertificateData) -> DeviceCertificate {
        data.sign(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventVerifier {
    pub public: [u8; 32],
}

impl EventVerifier {
    /// Verifies a signed payload originating from federation.
    pub fn verify(&self, payload: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let verifying =
            VerifyingKey::from_bytes(&self.public).map_err(|_| CryptoError::InvalidKey)?;
        let sig = Signature::try_from(signature.as_slice()).map_err(|_| CryptoError::Signature)?;
        verifying
            .verify(payload, &sig)
            .map_err(|_| CryptoError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn derive_noise_keys(seed: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut hasher = Hasher::new();
        hasher.update(seed);
        let digest = hasher.finalize();
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(digest.as_bytes());
        let secret = StaticSecret::from(scalar);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    #[test]
    fn noise_roundtrip() {
        let seed_a = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let seed_b = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let prologue = b"commucat".to_vec();
        let (initiator_private, initiator_public) = derive_noise_keys(seed_a);
        let (responder_private, responder_public) = derive_noise_keys(seed_b);
        let initiator_config = NoiseConfig {
            pattern: HandshakePattern::Xk,
            prologue: prologue.clone(),
            local_private: initiator_private,
            local_static_public: Some(initiator_public),
            remote_static_public: Some(responder_public),
        };
        let responder_config = NoiseConfig {
            pattern: HandshakePattern::Xk,
            prologue,
            local_private: responder_private,
            local_static_public: Some(responder_public),
            remote_static_public: None,
        };
        let mut initiator = build_handshake(&initiator_config, true).unwrap();
        let mut responder = build_handshake(&responder_config, false).unwrap();
        let msg1 = initiator.write_message(&[]).unwrap();
        responder.read_message(&msg1).unwrap();
        let msg2 = responder.write_message(&[]).unwrap();
        initiator.read_message(&msg2).unwrap();
        let msg3 = initiator.write_message(b"ok").unwrap();
        let payload = responder.read_message(&msg3).unwrap();
        assert_eq!(payload, b"ok");
        let mut initiator_transport = initiator.into_transport().unwrap();
        let mut responder_transport = responder.into_transport().unwrap();
        let encrypted = initiator_transport.write_message(b"hello").unwrap();
        let clear = responder_transport.read_message(&encrypted).unwrap();
        assert_eq!(clear, b"hello");
    }

    #[test]
    fn signature_roundtrip() {
        let keys = DeviceKeyPair::from_seed(b"seed-seed-seed-seed-seed-seed-seed-seed").unwrap();
        let signer = EventSigner::new(&keys);
        let signature = signer.sign(b"payload");
        let verifier = EventVerifier {
            public: keys.public,
        };
        verifier.verify(b"payload", &signature).unwrap();
    }

    #[test]
    fn generated_noise_keypair_has_entropy() {
        let (private, public) = generate_noise_static_keypair();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        assert_ne!(private, [0u8; 32]);
        assert_ne!(public, [0u8; 32]);
    }

    #[test]
    fn derive_noise_public_matches_generation() {
        let (private, public) = generate_noise_static_keypair();
        let derived = derive_noise_public_key(&private);
        assert_eq!(derived, public);
    }
}
