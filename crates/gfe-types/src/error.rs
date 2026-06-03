use thiserror::Error;

/// Errors surfaced by the GFE domain and the crates built on top of it.
#[derive(Debug, Error)]
pub enum GfeError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("no route matched host={host} path={path}")]
    NoRoute { host: String, path: String },

    #[error("upstream pool not found: {0}")]
    PoolNotFound(String),

    #[error("no healthy upstream in pool {0}")]
    NoHealthyUpstream(String),

    #[error("certificate error: {0}")]
    Certificate(String),
}
