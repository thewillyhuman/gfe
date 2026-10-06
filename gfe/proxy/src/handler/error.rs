//! What setting up request handling can fail at.

use std::path::PathBuf;
use thiserror::Error;

/// Why request handling could not be set up from the bootstrap config. Each
/// message names the file or setting at fault.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// A file of the upstream TLS settings (`[upstream] extra_ca_file`,
    /// `client_cert_file`, `client_key_file`) could not be read, or the CA
    /// bundle holds nothing usable.
    #[error("[upstream] {setting} {}: {reason}", file.display())]
    UpstreamTls {
        setting: &'static str,
        file: PathBuf,
        reason: String,
    },
    /// Only one of `client_cert_file` and `client_key_file` is set.
    #[error("[upstream] client_cert_file and client_key_file must be set together")]
    IncompleteClientCertificate,
    /// The client certificate and key could be read, but are not a usable
    /// identity: no certificate, no key, an unsupported key type.
    #[error(
        "[upstream] client_cert_file {} and client_key_file {}: {reason}",
        cert_file.display(),
        key_file.display()
    )]
    ClientIdentity {
        cert_file: PathBuf,
        key_file: PathBuf,
        reason: String,
    },
    /// TLS towards backends could not be set up at all.
    #[error("[upstream] TLS: {0}")]
    Tls(#[from] netkit_tls::TlsError),
}
