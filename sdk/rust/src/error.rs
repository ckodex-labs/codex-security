use thiserror::Error;

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("Scan request failed: {0}")]
    ScanError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Proof generation failed: {0}")]
    ProofError(String),
    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}