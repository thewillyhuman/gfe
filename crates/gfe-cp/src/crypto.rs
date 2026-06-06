//! Content hashing and envelope encryption for the control plane.
//!
//! Two concerns live here:
//!
//! * **Content addressing** — certificates are keyed by `sha256(cert || key)`
//!   (spec §3.4) so a given cert/key pair always maps to the same on-node path,
//!   making rotation an additive operation that can never tear a cert/key pair.
//! * **Encryption at rest** — private keys are envelope-encrypted (spec §6, §9):
//!   each blob gets a fresh random data key that encrypts the plaintext, and the
//!   data key is itself wrapped by a long-lived master key. The store only ever
//!   holds [`Sealed`] blobs; plaintext exists transiently in memory.
//!
//! The [`Sealer`] trait is the seam where a real KMS (CERN's, AWS KMS, …) would
//! replace [`AeadSealer`]: the wrap/unwrap of the per-row data key becomes a KMS
//! `Encrypt`/`Decrypt` call while the bulk AEAD stays local.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Length of the symmetric keys used (AES-256).
const KEY_LEN: usize = 32;

/// Errors from hashing / sealing operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("master key must be {KEY_LEN} bytes, got {0}")]
    BadMasterKey(usize),
    #[error("entropy source failed")]
    Rng,
    #[error("AEAD operation failed")]
    Aead,
}

/// Lowercase hex encoding (no external `hex` crate; keeps the dep surface small).
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// SHA-256 of `bytes`, hex-encoded.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest(&SHA256, bytes).as_ref())
}

/// The content hash that identifies a certificate: `sha256(cert_pem || key_pem)`.
/// Drives the content-addressed on-node path so identical material reuses files.
pub fn cert_content_sha(cert_pem: &[u8], key_pem: &[u8]) -> String {
    let mut buf = Vec::with_capacity(cert_pem.len() + key_pem.len());
    buf.extend_from_slice(cert_pem);
    buf.extend_from_slice(key_pem);
    sha256_hex(&buf)
}

/// An envelope-encrypted blob: the ciphertext plus the wrapped per-row data key
/// and both nonces. Self-contained — decryptable with only the master key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// Data key encrypted (wrapped) under the master key.
    wrapped_key: Vec<u8>,
    /// Nonce used to wrap the data key.
    key_nonce: Vec<u8>,
    /// Plaintext encrypted under the data key.
    ciphertext: Vec<u8>,
    /// Nonce used to encrypt the plaintext.
    data_nonce: Vec<u8>,
}

/// Seals and opens secret material. Implemented locally by [`AeadSealer`];
/// a KMS-backed implementation would wrap the data key remotely.
pub trait Sealer: Send + Sync {
    /// Encrypt `plaintext` into a self-contained [`Sealed`] blob.
    fn seal(&self, plaintext: &[u8]) -> Result<Sealed, CryptoError>;
    /// Decrypt a [`Sealed`] blob back to plaintext.
    fn open(&self, sealed: &Sealed) -> Result<Vec<u8>, CryptoError>;
}

/// Local AES-256-GCM envelope encryption keyed by an in-process master key.
pub struct AeadSealer {
    master: [u8; KEY_LEN],
    rng: SystemRandom,
}

impl AeadSealer {
    /// Build a sealer from a 32-byte master key (e.g. read from a secret file
    /// or a KMS-decrypted bootstrap key).
    pub fn new(master_key: &[u8]) -> Result<Self, CryptoError> {
        if master_key.len() != KEY_LEN {
            return Err(CryptoError::BadMasterKey(master_key.len()));
        }
        let mut master = [0u8; KEY_LEN];
        master.copy_from_slice(master_key);
        Ok(AeadSealer {
            master,
            rng: SystemRandom::new(),
        })
    }

    /// Generate a fresh random master key, hex-encoded for storage. Operators
    /// persist this once and supply it on every controller start.
    pub fn generate_master_key_hex() -> Result<String, CryptoError> {
        let rng = SystemRandom::new();
        let mut key = [0u8; KEY_LEN];
        rng.fill(&mut key).map_err(|_| CryptoError::Rng)?;
        Ok(hex(&key))
    }

    fn random<const N: usize>(&self) -> Result<[u8; N], CryptoError> {
        let mut buf = [0u8; N];
        self.rng.fill(&mut buf).map_err(|_| CryptoError::Rng)?;
        Ok(buf)
    }

    /// AEAD-encrypt `plaintext` under `key` with a random nonce; returns
    /// `(nonce, ciphertext||tag)`.
    fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::Aead)?;
        let sealing = LessSafeKey::new(unbound);
        let nonce_bytes: [u8; NONCE_LEN] = self.random()?;
        let mut buf = plaintext.to_vec();
        sealing
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::empty(),
                &mut buf,
            )
            .map_err(|_| CryptoError::Aead)?;
        Ok((nonce_bytes.to_vec(), buf))
    }

    /// AEAD-decrypt `ciphertext` (with appended tag) under `key` and `nonce`.
    fn decrypt(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| CryptoError::Aead)?;
        let opening = LessSafeKey::new(unbound);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Aead)?;
        let mut buf = ciphertext.to_vec();
        let plain = opening
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
            .map_err(|_| CryptoError::Aead)?;
        Ok(plain.to_vec())
    }
}

impl Sealer for AeadSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let data_key: [u8; KEY_LEN] = self.random()?;
        let (data_nonce, ciphertext) = self.encrypt(&data_key, plaintext)?;
        let (key_nonce, wrapped_key) = self.encrypt(&self.master, &data_key)?;
        Ok(Sealed {
            wrapped_key,
            key_nonce,
            ciphertext,
            data_nonce,
        })
    }

    fn open(&self, sealed: &Sealed) -> Result<Vec<u8>, CryptoError> {
        let data_key = self.decrypt(&self.master, &sealed.key_nonce, &sealed.wrapped_key)?;
        self.decrypt(&data_key, &sealed.data_nonce, &sealed.ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer() -> AeadSealer {
        AeadSealer::new(&[7u8; KEY_LEN]).unwrap()
    }

    #[test]
    fn sha256_is_stable_and_hex() {
        let h = sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn cert_sha_concatenates_cert_then_key() {
        let a = cert_content_sha(b"CERT", b"KEY");
        let b = sha256_hex(b"CERTKEY");
        assert_eq!(a, b);
    }

    #[test]
    fn seal_open_round_trips() {
        let s = sealer();
        let secret = b"-----BEGIN PRIVATE KEY-----\nsensitive\n-----END PRIVATE KEY-----";
        let sealed = s.seal(secret).unwrap();
        assert_ne!(sealed.ciphertext, secret);
        let opened = s.open(&sealed).unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn seal_uses_fresh_keys_each_time() {
        let s = sealer();
        let a = s.seal(b"same").unwrap();
        let b = s.seal(b"same").unwrap();
        // Different data key + nonce ⇒ different ciphertext for identical input.
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.wrapped_key, b.wrapped_key);
    }

    #[test]
    fn wrong_master_key_fails_to_open() {
        let sealed = sealer().seal(b"secret").unwrap();
        let other = AeadSealer::new(&[9u8; KEY_LEN]).unwrap();
        assert!(other.open(&sealed).is_err());
    }

    #[test]
    fn rejects_short_master_key() {
        assert!(AeadSealer::new(&[0u8; 16]).is_err());
    }

    #[test]
    fn generated_master_key_is_usable() {
        let hexkey = AeadSealer::generate_master_key_hex().unwrap();
        assert_eq!(hexkey.len(), KEY_LEN * 2);
    }
}
