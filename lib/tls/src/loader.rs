//! PEM certificate / key loading and not-after extraction.

use crate::TlsError;
use rustls::InconsistentKeys;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use std::path::Path;
use std::sync::Arc;

/// A loaded certificate: the rustls signing material plus the not-after time
/// (Unix seconds) of the leaf, for expiry metrics.
#[derive(Debug)]
pub struct LoadedCert {
    pub certified_key: Arc<CertifiedKey>,
    pub not_after_unix: i64,
}

/// Load a certificate chain + private key from PEM files on disk.
pub fn load_cert_files(cert_path: &Path, key_path: &Path) -> Result<LoadedCert, TlsError> {
    let read = |path: &Path| {
        std::fs::read(path).map_err(|error| TlsError::Read {
            path: path.to_path_buf(),
            error,
        })
    };
    let cert_pem = read(cert_path)?;
    let key_pem = read(key_path)?;
    load_cert_pem(&cert_pem, &key_pem).map_err(|error| TlsError::InvalidFiles {
        cert_file: cert_path.to_path_buf(),
        key_file: key_path.to_path_buf(),
        reason: error.to_string(),
    })
}

/// Load a certificate chain + private key from in-memory PEM bytes. The
/// first certificate is the leaf. A key that does not match the leaf is
/// refused: serving it would fail every handshake.
pub fn load_cert_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<LoadedCert, TlsError> {
    let certs = read_certs(cert_pem)?;
    let Some(leaf) = certs.first() else {
        return Err(TlsError::InvalidPem("no certificate in PEM".into()));
    };
    let not_after_unix = leaf_not_after(leaf)?;
    let key = read_key(key_pem)?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| TlsError::InvalidPem(format!("unsupported key type: {e}")))?;

    let certified_key = CertifiedKey::new(certs, signing_key);
    match certified_key.keys_match() {
        // `Unknown` means the key type cannot report its public half; that is
        // not evidence of a mismatch.
        Ok(()) | Err(rustls::Error::InconsistentKeys(InconsistentKeys::Unknown)) => {}
        Err(e) => {
            return Err(TlsError::InvalidPem(format!(
                "private key does not match certificate: {e}"
            )));
        }
    }
    Ok(LoadedCert {
        certified_key: Arc::new(certified_key),
        not_after_unix,
    })
}

fn read_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::InvalidPem(format!("parsing certificates: {e}")))
}

fn read_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    // `private_key` skips PEM blocks that are not keys and returns the first
    // key.
    match rustls_pemfile::private_key(&mut &pem[..]) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(TlsError::InvalidPem("no private key in PEM".into())),
        Err(e) => Err(TlsError::InvalidPem(format!("parsing private key: {e}"))),
    }
}

/// The leaf certificate's not-after time, as Unix seconds.
fn leaf_not_after(cert: &CertificateDer<'_>) -> Result<i64, TlsError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| TlsError::InvalidPem(format!("parsing x509 certificate: {e}")))?;
    Ok(parsed.validity().not_after.timestamp())
}

#[cfg(test)]
#[path = "loader_test.rs"]
mod tests;
