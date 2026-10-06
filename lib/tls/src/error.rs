//! What setting up TLS termination can fail at.

use std::path::PathBuf;
use thiserror::Error;

/// Why certificates or the TLS policy could not be loaded. Each message names
/// the file or the SNI names at fault, so that the problem can be fixed from
/// the message alone; a wrapping variant repeats the message it wraps for the
/// same reason.
#[derive(Debug, Error)]
pub enum TlsError {
    /// A certificate or key file could not be read.
    #[error("reading {}: {error}", path.display())]
    Read {
        path: PathBuf,
        error: std::io::Error,
    },
    /// PEM bytes that are not a usable certificate chain and private key: no
    /// certificate, no key, an unsupported key type, a key that does not
    /// match the certificate, an unparsable certificate.
    #[error("{0}")]
    InvalidPem(String),
    /// A certificate / key file pair whose content is not usable.
    #[error("{} / {}: {reason}", cert_file.display(), key_file.display())]
    InvalidFiles {
        cert_file: PathBuf,
        key_file: PathBuf,
        reason: String,
    },
    /// The certificate entry serving these SNI names (`<default>` for the
    /// default certificate) could not be loaded.
    #[error("certificate for {}: {error}", names.join(", "))]
    Entry {
        names: Vec<String>,
        error: Box<TlsError>,
    },
    /// Two certificate entries both claim to be the default.
    #[error(
        "more than one default certificate configured: {} and {}",
        first.display(),
        second.display()
    )]
    TwoDefaults { first: PathBuf, second: PathBuf },
    /// rustls refused the TLS policy (versions, session tickets).
    #[error("invalid TLS policy: {0}")]
    Policy(rustls::Error),
}
