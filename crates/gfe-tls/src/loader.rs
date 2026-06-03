//! PEM certificate/key loading and not-after extraction.

use gfe_types::GfeError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use std::io::BufRead;
use std::path::Path;
use std::sync::Arc;

/// A loaded certificate: the rustls signing material plus the not-after time
/// (Unix seconds) for expiry metrics.
pub struct LoadedCert {
    pub certified_key: Arc<CertifiedKey>,
    pub not_after_unix: i64,
}

/// Load a certificate chain + private key from PEM files on disk.
pub fn load_cert_files(cert_path: &Path, key_path: &Path) -> Result<LoadedCert, GfeError> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| GfeError::Certificate(format!("reading {}: {e}", cert_path.display())))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| GfeError::Certificate(format!("reading {}: {e}", key_path.display())))?;
    load_cert_pem(&cert_pem, &key_pem).map_err(|e| {
        GfeError::Certificate(format!(
            "{} / {}: {e}",
            cert_path.display(),
            key_path.display()
        ))
    })
}

/// Load a certificate chain + private key from in-memory PEM bytes. Shared by
/// [`load_cert_files`] and unit tests.
pub fn load_cert_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<LoadedCert, GfeError> {
    let certs = read_certs(cert_pem)?;
    if certs.is_empty() {
        return Err(GfeError::Certificate("no certificates in PEM".into()));
    }
    let key = read_key(key_pem)?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| GfeError::Certificate(format!("unsupported key type: {e}")))?;

    let not_after_unix = leaf_not_after(&certs[0])?;
    let certified_key = Arc::new(CertifiedKey::new(certs, signing_key));
    Ok(LoadedCert {
        certified_key,
        not_after_unix,
    })
}

fn read_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, GfeError> {
    let mut reader = std::io::BufReader::new(pem);
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        out.push(item.map_err(|e| GfeError::Certificate(format!("parsing certs: {e}")))?);
    }
    Ok(out)
}

fn read_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, GfeError> {
    let mut reader = std::io::BufReader::new(pem);
    // Tolerate leading non-key PEM blocks; private_key() scans for the first key.
    match rustls_pemfile::private_key(&mut reader) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => {
            // Ensure we consumed the whole reader (guards against odd input).
            let _ = reader.fill_buf();
            Err(GfeError::Certificate("no private key in PEM".into()))
        }
        Err(e) => Err(GfeError::Certificate(format!("parsing key: {e}"))),
    }
}

/// Extract the leaf certificate's not-after time as Unix seconds.
fn leaf_not_after(cert: &CertificateDer<'_>) -> Result<i64, GfeError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| GfeError::Certificate(format!("parsing x509: {e}")))?;
    Ok(parsed.validity().not_after.timestamp())
}

#[cfg(test)]
pub(crate) fn self_signed(names: Vec<String>) -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(names).unwrap();
    (
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_self_signed() {
        let (cert, key) = self_signed(vec!["example.org".into()]);
        let loaded = load_cert_pem(&cert, &key).unwrap();
        assert!(loaded.not_after_unix > 0);
        assert!(!loaded.certified_key.cert.is_empty());
    }

    #[test]
    fn rejects_missing_key() {
        let (cert, _) = self_signed(vec!["example.org".into()]);
        assert!(load_cert_pem(&cert, b"not a key").is_err());
    }
}
