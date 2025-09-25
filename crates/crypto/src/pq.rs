use crate::CryptoError;
use blake3::keyed_hash;
use core::convert::TryFrom;
use core::fmt;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_dsa::{
    B32, EncodedSignature, KeyGen, KeyPair as MlDsaKeyPair, MlDsa65, Signature as MlDsaSignature,
    VerifyingKey,
    signature::{Signer, Verifier},
};
use ml_kem::{KemCore, MlKem768, array::typenum::Unsigned};
use rand::{CryptoRng, RngCore, rngs::OsRng};
use sha3::Sha3_512;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const CLASSICAL_SECRET_LEN: usize = 32;
const PQ_SECRET_LEN: usize = <<MlKem768 as KemCore>::SharedKeySize as Unsigned>::USIZE;
const HYBRID_SECRET_LEN: usize = CLASSICAL_SECRET_LEN + PQ_SECRET_LEN;
const SESSION_KEY_LEN: usize = 32;

fn generate_signing_key<R: CryptoRng + RngCore>(rng: &mut R) -> SigningKey {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn static_secret_from_rng<R: RngCore>(rng: &mut R) -> StaticSecret {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    StaticSecret::from(seed)
}

const SESSION_KDF_INFO: &[u8] = b"commucat.hybrid.session.v1";
const RATCHET_KDF_INFO: &[u8] = b"commucat.hybrid.ratchet.v1";

type KemCiphertext = ml_kem::Ciphertext<MlKem768>;
type KemSharedKey = ml_kem::SharedKey<MlKem768>;
type EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;
type DecapsulationKey = <MlKem768 as KemCore>::DecapsulationKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub role: SessionRole,
    pub root_key: [u8; SESSION_KEY_LEN],
    pub sending_chain: [u8; SESSION_KEY_LEN],
    pub receiving_chain: [u8; SESSION_KEY_LEN],
}

impl SessionKeys {
    pub fn derive_from(
        material: &[u8],
        settings: &HybridSettings<'_>,
        role: SessionRole,
    ) -> Result<Self, CryptoError> {
        if material.len() != HYBRID_SECRET_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let hkdf = Hkdf::<Sha3_512>::new(settings.kdf_salt, material);
        let mut okm = [0u8; SESSION_KEY_LEN * 3];
        hkdf.expand(settings.kdf_info, &mut okm)
            .map_err(|_| CryptoError::KeyDerivation)?;
        let mut root_key = [0u8; SESSION_KEY_LEN];
        root_key.copy_from_slice(&okm[0..SESSION_KEY_LEN]);
        let mut first_chain = [0u8; SESSION_KEY_LEN];
        first_chain.copy_from_slice(&okm[SESSION_KEY_LEN..SESSION_KEY_LEN * 2]);
        let mut second_chain = [0u8; SESSION_KEY_LEN];
        second_chain.copy_from_slice(&okm[SESSION_KEY_LEN * 2..]);
        let (sending_chain, receiving_chain) = match role {
            SessionRole::Initiator => (first_chain, second_chain),
            SessionRole::Responder => (second_chain, first_chain),
        };
        Ok(SessionKeys {
            role,
            root_key,
            sending_chain,
            receiving_chain,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HybridSettings<'a> {
    pub kdf_info: &'a [u8],
    pub kdf_salt: Option<&'a [u8]>,
}

impl<'a> HybridSettings<'a> {
    pub const fn new(kdf_info: &'a [u8]) -> Self {
        Self {
            kdf_info,
            kdf_salt: None,
        }
    }

    pub fn with_salt(mut self, salt: &'a [u8]) -> Self {
        self.kdf_salt = Some(salt);
        self
    }
}

impl Default for HybridSettings<'static> {
    fn default() -> Self {
        Self {
            kdf_info: SESSION_KDF_INFO,
            kdf_salt: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKeyMaterial {
    classical: [u8; CLASSICAL_SECRET_LEN],
    post_quantum: [u8; PQ_SECRET_LEN],
}

impl HybridKeyMaterial {
    pub fn new(classical: &[u8], post_quantum: &[u8]) -> Result<Self, CryptoError> {
        if classical.len() != CLASSICAL_SECRET_LEN || post_quantum.len() != PQ_SECRET_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let mut classical_buf = [0u8; CLASSICAL_SECRET_LEN];
        classical_buf.copy_from_slice(classical);
        let mut pq_buf = [0u8; PQ_SECRET_LEN];
        pq_buf.copy_from_slice(post_quantum);
        Ok(Self {
            classical: classical_buf,
            post_quantum: pq_buf,
        })
    }

    pub fn combined(&self) -> [u8; HYBRID_SECRET_LEN] {
        let mut output = [0u8; HYBRID_SECRET_LEN];
        output[..CLASSICAL_SECRET_LEN].copy_from_slice(&self.classical);
        output[CLASSICAL_SECRET_LEN..].copy_from_slice(&self.post_quantum);
        output
    }

    pub fn classical(&self) -> &[u8; CLASSICAL_SECRET_LEN] {
        &self.classical
    }

    pub fn post_quantum(&self) -> &[u8; PQ_SECRET_LEN] {
        &self.post_quantum
    }
}

impl Drop for HybridKeyMaterial {
    fn drop(&mut self) {
        self.classical.fill(0);
        self.post_quantum.fill(0);
    }
}

#[derive(Debug, Clone)]
pub struct HybridInitiatorResult {
    pub ciphertext: KemCiphertext,
    pub material: HybridKeyMaterial,
    pub session: SessionKeys,
}

#[derive(Debug, Clone)]
pub struct HybridResponderResult {
    pub material: HybridKeyMaterial,
    pub session: SessionKeys,
}

pub fn encapsulate_hybrid<R: CryptoRng + RngCore>(
    classical_secret: &[u8],
    pq_public_key: &EncapsulationKey,
    rng: &mut R,
    settings: &HybridSettings<'_>,
) -> Result<HybridInitiatorResult, CryptoError> {
    let (ciphertext, shared_secret): (KemCiphertext, KemSharedKey) = pq_public_key
        .encapsulate(rng)
        .map_err(|_| CryptoError::PostQuantumEncapsulation)?;
    let material = HybridKeyMaterial::new(classical_secret, shared_secret.as_slice())?;
    let combined = material.combined();
    let session = SessionKeys::derive_from(&combined, settings, SessionRole::Initiator)?;
    Ok(HybridInitiatorResult {
        ciphertext,
        material,
        session,
    })
}

pub fn decapsulate_hybrid(
    classical_secret: &[u8],
    pq_secret_key: &DecapsulationKey,
    ciphertext: &KemCiphertext,
    settings: &HybridSettings<'_>,
) -> Result<HybridResponderResult, CryptoError> {
    let shared_secret = pq_secret_key
        .decapsulate(ciphertext)
        .map_err(|_| CryptoError::PostQuantumDecapsulation)?;
    let material = HybridKeyMaterial::new(classical_secret, shared_secret.as_slice())?;
    let combined = material.combined();
    let session = SessionKeys::derive_from(&combined, settings, SessionRole::Responder)?;
    Ok(HybridResponderResult { material, session })
}

#[derive(Debug, Clone)]
pub struct HybridRatchet {
    role: SessionRole,
    root_key: [u8; SESSION_KEY_LEN],
    sending_chain: [u8; SESSION_KEY_LEN],
    receiving_chain: [u8; SESSION_KEY_LEN],
    sending_counter: u32,
    receiving_counter: u32,
}

impl HybridRatchet {
    pub fn new(session: SessionKeys) -> Self {
        Self {
            role: session.role,
            root_key: session.root_key,
            sending_chain: session.sending_chain,
            receiving_chain: session.receiving_chain,
            sending_counter: 0,
            receiving_counter: 0,
        }
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn root_key(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.root_key
    }

    pub fn next_sending_key(&mut self) -> [u8; SESSION_KEY_LEN] {
        let mut counter = [0u8; 4];
        counter.copy_from_slice(&self.sending_counter.to_be_bytes());
        let digest = keyed_hash(&self.sending_chain, &counter);
        self.sending_counter = self.sending_counter.wrapping_add(1);
        let mut output = [0u8; SESSION_KEY_LEN];
        output.copy_from_slice(digest.as_bytes());
        output
    }

    pub fn next_receiving_key(&mut self) -> [u8; SESSION_KEY_LEN] {
        let mut counter = [0u8; 4];
        counter.copy_from_slice(&self.receiving_counter.to_be_bytes());
        let digest = keyed_hash(&self.receiving_chain, &counter);
        self.receiving_counter = self.receiving_counter.wrapping_add(1);
        let mut output = [0u8; SESSION_KEY_LEN];
        output.copy_from_slice(digest.as_bytes());
        output
    }

    pub fn ratchet_with_material(
        &mut self,
        material: &HybridKeyMaterial,
        role: SessionRole,
    ) -> Result<(), CryptoError> {
        let combined = material.combined();
        let previous_root = self.root_key;
        let ratchet_settings = HybridSettings {
            kdf_info: RATCHET_KDF_INFO,
            kdf_salt: Some(&previous_root),
        };
        let session = SessionKeys::derive_from(&combined, &ratchet_settings, role)?;
        self.role = role;
        self.root_key = session.root_key;
        self.sending_chain = session.sending_chain;
        self.receiving_chain = session.receiving_chain;
        self.sending_counter = 0;
        self.receiving_counter = 0;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PqKemKeyPair {
    public: EncapsulationKey,
    secret: DecapsulationKey,
}

impl PqKemKeyPair {
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let (secret, public) = MlKem768::generate(rng);
        Self { public, secret }
    }

    pub fn generate_osrng() -> Self {
        let mut rng = OsRng;
        Self::generate(&mut rng)
    }

    pub fn public(&self) -> &EncapsulationKey {
        &self.public
    }

    pub fn secret(&self) -> &DecapsulationKey {
        &self.secret
    }
}

#[derive(Clone)]
pub struct PqSignaturePublicKey {
    inner: VerifyingKey<MlDsa65>,
}

impl PqSignaturePublicKey {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let encoded = EncodedSignature::<MlDsa65>::try_from(signature)
            .map_err(|_| CryptoError::PostQuantumSignature)?;
        let decoded =
            MlDsaSignature::<MlDsa65>::decode(&encoded).ok_or(CryptoError::PostQuantumSignature)?;
        self.inner
            .verify(message, &decoded)
            .map_err(|_| CryptoError::PostQuantumSignature)
    }

    pub fn inner(&self) -> &VerifyingKey<MlDsa65> {
        &self.inner
    }
}

pub struct PqSignatureKeyPair {
    keypair: MlDsaKeyPair<MlDsa65>,
}

impl PqSignatureKeyPair {
    pub fn generate_with_rng<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self, CryptoError> {
        let mut seed = B32::default();
        rng.fill_bytes(seed.as_mut_slice());
        let keypair = MlDsa65::from_seed(&seed);
        Ok(Self { keypair })
    }

    pub fn generate_osrng() -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        Self::generate_with_rng(&mut rng)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.keypair.signing_key().sign(message);
        let encoded = signature.encode();
        encoded.as_slice().to_vec()
    }

    pub fn verifying_key(&self) -> PqSignaturePublicKey {
        PqSignaturePublicKey {
            inner: self.keypair.verifying_key().clone(),
        }
    }
}

pub struct PqxdhBundle {
    pub identity_key: SigningKey,
    pub signed_prekey: StaticSecret,
    pub one_time_prekeys: Vec<StaticSecret>,
    pub pq_identity: PqKemKeyPair,
    pub pq_one_time: Vec<PqKemKeyPair>,
    pub pq_signature: PqSignatureKeyPair,
}

impl fmt::Debug for PqxdhBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqxdhBundle")
            .field("one_time_prekeys", &self.one_time_prekeys.len())
            .field("pq_one_time", &self.pq_one_time.len())
            .finish()
    }
}

impl PqxdhBundle {
    pub fn attach_post_quantum<R: CryptoRng + RngCore>(
        identity_key: SigningKey,
        signed_prekey: StaticSecret,
        one_time_prekeys: Vec<StaticSecret>,
        pq_one_time_count: usize,
        rng: &mut R,
    ) -> Result<Self, CryptoError> {
        let pq_identity = PqKemKeyPair::generate(rng);
        let pq_signature = PqSignatureKeyPair::generate_with_rng(rng)?;
        let mut pq_one_time = Vec::with_capacity(pq_one_time_count);
        for _ in 0..pq_one_time_count {
            pq_one_time.push(PqKemKeyPair::generate(rng));
        }
        Ok(Self {
            identity_key,
            signed_prekey,
            one_time_prekeys,
            pq_identity,
            pq_one_time,
            pq_signature,
        })
    }

    pub fn generate<R: CryptoRng + RngCore>(
        classical_one_time_count: usize,
        pq_one_time_count: usize,
        rng: &mut R,
    ) -> Result<Self, CryptoError> {
        let identity_key = generate_signing_key(rng);
        let signed_prekey = static_secret_from_rng(rng);
        let mut one_time_prekeys = Vec::with_capacity(classical_one_time_count);
        for _ in 0..classical_one_time_count {
            one_time_prekeys.push(static_secret_from_rng(rng));
        }
        Self::attach_post_quantum(
            identity_key,
            signed_prekey,
            one_time_prekeys,
            pq_one_time_count,
            rng,
        )
    }

    pub fn generate_osrng(
        classical_one_time_count: usize,
        pq_one_time_count: usize,
    ) -> Result<Self, CryptoError> {
        let mut rng = OsRng;
        Self::generate(classical_one_time_count, pq_one_time_count, &mut rng)
    }

    pub fn signed_prekey_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.signed_prekey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn random_classical_secret(rng: &mut StdRng) -> [u8; CLASSICAL_SECRET_LEN] {
        let mut buffer = [0u8; CLASSICAL_SECRET_LEN];
        rng.fill_bytes(&mut buffer);
        buffer
    }

    #[test]
    fn hybrid_handshake_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0x5eed);
        let classical = random_classical_secret(&mut rng);
        let kem = PqKemKeyPair::generate(&mut rng);
        let settings = HybridSettings::default();
        let initiator = encapsulate_hybrid(&classical, kem.public(), &mut rng, &settings).unwrap();
        let responder =
            decapsulate_hybrid(&classical, kem.secret(), &initiator.ciphertext, &settings).unwrap();
        assert_eq!(initiator.material, responder.material);
        assert_eq!(initiator.session.role, SessionRole::Initiator);
        assert_eq!(responder.session.role, SessionRole::Responder);
        assert_eq!(
            initiator.session.sending_chain,
            responder.session.receiving_chain
        );
        assert_eq!(
            initiator.session.receiving_chain,
            responder.session.sending_chain
        );
    }

    #[test]
    fn ratchet_alignment_across_steps() {
        let mut rng = StdRng::seed_from_u64(0xdecafbad);
        let kem = PqKemKeyPair::generate(&mut rng);
        let settings = HybridSettings::default();
        let classical_a = random_classical_secret(&mut rng);
        let init = encapsulate_hybrid(&classical_a, kem.public(), &mut rng, &settings).unwrap();
        let resp =
            decapsulate_hybrid(&classical_a, kem.secret(), &init.ciphertext, &settings).unwrap();
        let mut ratchet_a = HybridRatchet::new(init.session.clone());
        let mut ratchet_b = HybridRatchet::new(resp.session.clone());
        let key_a1 = ratchet_a.next_sending_key();
        let key_b1 = ratchet_b.next_receiving_key();
        assert_eq!(key_a1, key_b1);

        let classical_b = random_classical_secret(&mut rng);
        let next_init =
            encapsulate_hybrid(&classical_b, kem.public(), &mut rng, &settings).unwrap();
        let next_resp =
            decapsulate_hybrid(&classical_b, kem.secret(), &next_init.ciphertext, &settings)
                .unwrap();
        ratchet_a
            .ratchet_with_material(&next_resp.material, SessionRole::Responder)
            .unwrap();
        ratchet_b
            .ratchet_with_material(&next_init.material, SessionRole::Initiator)
            .unwrap();
        let key_a2 = ratchet_a.next_sending_key();
        let key_b2 = ratchet_b.next_receiving_key();
        assert_eq!(key_a2, key_b2);
    }

    #[test]
    fn ml_dsa_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let keypair = PqSignatureKeyPair::generate_with_rng(&mut rng).unwrap();
        let public = keypair.verifying_key();
        let message = b"pq-signature";
        let signature = keypair.sign(message);
        public.verify(message, &signature).unwrap();
    }

    #[test]
    fn pq_bundle_generation() {
        let mut rng = StdRng::seed_from_u64(7);
        let bundle = PqxdhBundle::generate(4, 3, &mut rng).unwrap();
        assert_eq!(bundle.one_time_prekeys.len(), 4);
        assert_eq!(bundle.pq_one_time.len(), 3);
        let _pub = bundle.signed_prekey_public();
    }
}
