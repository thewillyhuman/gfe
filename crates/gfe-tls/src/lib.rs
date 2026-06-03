//! TLS termination support: certificate loading, an SNI-keyed certificate
//! store, a rustls cert resolver, and the fleet TLS policy.

pub mod acme;
pub mod cert_store;
pub mod loader;
pub mod policy;
pub mod resolver;

pub use acme::{ChallengeStore, ACME_CHALLENGE_PREFIX};
pub use cert_store::CertStore;
pub use loader::{load_cert_files, load_cert_pem, LoadedCert};
pub use policy::{server_config, ALPN_PROTOCOLS};
pub use resolver::SniResolver;
