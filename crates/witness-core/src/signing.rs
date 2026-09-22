//! Tamper-evidence for evidence bundles: ML-DSA-87 (FIPS 204).
//!
//! What this is for: a helpline or forensic analyst receiving a bundle can
//! check it was not altered after Witness wrote it (USB stick in transit,
//! well-meaning relative "tidying up", etc.), and that it was produced by the
//! same install as earlier bundles.
//!
//! What this is NOT for: proving the machine was not compromised. An attacker
//! who already runs code as the user can read the seed and forge signatures.
//! Say so in the UI. See `THREAT_MODEL.md`.
//!
//! Key material is a 32-byte seed (FIPS 204 Algorithm 6, `KeyGen_internal`);
//! the key pair is re-derived from it deterministically. The seed is the only
//! secret to protect, and the OS crate decides how (DPAPI on Windows).
//!
//! Signatures use the *deterministic* ML-DSA variant (FIPS 204 §3.4, empty
//! context string), so signing needs no randomness and the same manifest
//! always yields the same signature. That makes a bundle reproducible and
//! removes an RNG from the trust base at signing time.

use ml_dsa::{
    signature::{Keypair, Signer, Verifier},
    EncodedVerifyingKey, MlDsa87, Seed, Signature, SigningKey, VerifyingKey,
};
use std::fmt;

/// Length of the seed in bytes.
pub const SEED_LEN: usize = 32;

/// Name of the signature scheme, written into every manifest so a verifier
/// never has to guess the parameter set.
pub const ALGORITHM: &str = "ML-DSA-87";

/// Signing errors.
#[derive(Debug, PartialEq, Eq)]
pub enum SignError {
    /// OS randomness unavailable.
    Random,
    /// Bad seed length.
    SeedLength(usize),
    /// Signature or key bytes did not decode.
    Decode,
    /// Signature did not verify.
    Verify,
}
impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Random => f.write_str("could not obtain OS randomness"),
            SignError::SeedLength(n) => write!(f, "seed must be {SEED_LEN} bytes, got {n}"),
            SignError::Decode => f.write_str("could not decode signature or key"),
            SignError::Verify => f.write_str("signature does not verify"),
        }
    }
}
impl std::error::Error for SignError {}

/// A signing identity derived from a seed. The seed and expanded key inside
/// are zeroized on drop (ml-dsa `zeroize` feature).
pub struct Identity {
    sk: SigningKey<MlDsa87>,
}

impl Identity {
    /// Generate a fresh random seed. Store it; everything else derives from it.
    ///
    /// # Errors
    /// The OS refused to give us randomness. Do not fall back to anything; fail.
    pub fn new_seed() -> Result<[u8; SEED_LEN], SignError> {
        let mut seed = [0u8; SEED_LEN];
        getrandom::fill(&mut seed).map_err(|_| SignError::Random)?;
        Ok(seed)
    }

    /// Derive the key pair from a seed.
    ///
    /// # Errors
    /// The seed is not exactly [`SEED_LEN`] bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, SignError> {
        let xi = Seed::try_from(seed).map_err(|_| SignError::SeedLength(seed.len()))?;
        Ok(Identity { sk: SigningKey::from_seed(&xi) })
    }

    /// Sign a message (deterministic ML-DSA-87); returns the encoded signature bytes.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature<MlDsa87> = self.sk.sign(msg);
        sig.encode().to_vec()
    }

    /// Encoded public key bytes, to be written alongside every bundle.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.sk.verifying_key().encode().to_vec()
    }

    /// Short, human-checkable fingerprint of the public key (BLAKE3, first 16 bytes, hex).
    /// Shown on first run so the user can write it down somewhere the computer can't reach.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.public_key())
    }
}

/// Fingerprint of an encoded public key.
#[must_use]
pub fn fingerprint_of(public_key: &[u8]) -> String {
    let h = blake3::hash(public_key);
    let hex = hex::encode(&h.as_bytes()[..16]);
    // Group into 4s for reading aloud over a phone.
    hex.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-")
}

/// Verify `sig` over `msg` with an encoded public key. Anyone can run this
/// without Witness installed; it is also what `witness verify` calls.
///
/// # Errors
/// [`SignError::Decode`] if the key or signature bytes are malformed, [`SignError::Verify`] otherwise.
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), SignError> {
    let enc_vk = EncodedVerifyingKey::<MlDsa87>::try_from(public_key).map_err(|_| SignError::Decode)?;
    let vk = VerifyingKey::<MlDsa87>::decode(&enc_vk);
    let sig = Signature::<MlDsa87>::try_from(sig).map_err(|_| SignError::Decode)?;
    vk.verify(msg, &sig).map_err(|_| SignError::Verify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_determinism() {
        let seed = Identity::new_seed().expect("OS randomness");
        let a = Identity::from_seed(&seed).expect("derive");
        let b = Identity::from_seed(&seed).expect("derive");
        assert_eq!(a.public_key(), b.public_key(), "same seed must give same key");
        let msg = b"manifest bytes";
        let sig = a.sign(msg);
        assert_eq!(sig, b.sign(msg), "deterministic variant: same key+message, same signature");
        assert_eq!(sig.len(), 4627, "ML-DSA-87 signature size (FIPS 204 Table 2)");
        assert_eq!(a.public_key().len(), 2592, "ML-DSA-87 public key size (FIPS 204 Table 2)");
        assert_eq!(verify(&a.public_key(), msg, &sig), Ok(()));
        assert_eq!(verify(&a.public_key(), b"tampered", &sig), Err(SignError::Verify));
        let other = Identity::from_seed(&[9u8; SEED_LEN]).expect("derive");
        assert_eq!(verify(&other.public_key(), msg, &sig), Err(SignError::Verify));
    }

    #[test]
    fn rejects_malformed_keys_and_signatures() {
        let id = Identity::from_seed(&[1u8; SEED_LEN]).expect("derive");
        let sig = id.sign(b"m");
        assert_eq!(verify(&[0u8; 10], b"m", &sig), Err(SignError::Decode));
        assert_eq!(verify(&id.public_key(), b"m", &sig[..sig.len() - 1]), Err(SignError::Decode));
        let mut flipped = sig.clone();
        flipped[100] ^= 1;
        assert!(verify(&id.public_key(), b"m", &flipped).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_readable() {
        let id = Identity::from_seed(&[1u8; SEED_LEN]).expect("derive");
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 32 + 7, "8 groups of 4 hex chars joined by dashes");
        assert_eq!(fp, fingerprint_of(&id.public_key()));
        assert_eq!(fp, Identity::from_seed(&[1u8; SEED_LEN]).expect("derive").fingerprint());
    }

    #[test]
    fn rejects_wrong_seed_length() {
        assert_eq!(Identity::from_seed(&[0u8; 31]).err(), Some(SignError::SeedLength(31)));
        assert!(Identity::from_seed(&[0u8; 33]).is_err());
    }
}
