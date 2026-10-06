//! What setting the proxy up can fail at.

use std::path::PathBuf;
use thiserror::Error;

/// Why the proxy could not be set up from the bootstrap config. Each message
/// names the file or setting at fault.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// A file of the upstream TLS settings (`[upstream] extra_ca_file`,
    /// `client_cert_file`, `client_key_file`) could not be used.
    #[error("[upstream] {setting} {}: {reason}", file.display())]
    UpstreamTls {
        setting: &'static str,
        file: PathBuf,
        reason: String,
    },
    /// Only one of `client_cert_file` and `client_key_file` is set.
    #[error("[upstream] client_cert_file and client_key_file must be set together")]
    IncompleteClientCertificate,
}
