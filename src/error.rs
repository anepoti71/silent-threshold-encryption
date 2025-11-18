/// Error types for the silent threshold encryption library
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum SteError {
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Network or communication error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Invalid threshold parameter
    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Decryption operation failed
    #[error("Decryption failure: {0}")]
    DecryptionFailure(String),

    /// Invalid signature detected
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid parameter provided (e.g., tau is zero, n is not a power of 2)
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// KZG commitment or operation failed
    #[error("KZG error: {0}")]
    KzgError(String),

    /// Domain creation failed (e.g., n is not a power of 2)
    #[error("Domain error: {0}")]
    DomainError(String),

    /// Input validation failed
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// MSM (Multi-Scalar Multiplication) operation failed
    #[error("MSM error: {0}")]
    MsmError(String),

    /// Field inverse computation failed
    #[error("Field inverse error: {0}")]
    FieldInverseError(String),

    /// Random number generation failed
    #[error("Randomness error: {0}")]
    RandomnessError(String),

    /// TLS/Certificate error
    #[error("TLS error: {0}")]
    TlsError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),
}

// Convert from KZG errors
impl From<crate::kzg::Error> for SteError {
    fn from(err: crate::kzg::Error) -> Self {
        SteError::KzgError(format!("{:?}", err))
    }
}

// Convert from std::io::Error
impl From<std::io::Error> for SteError {
    fn from(err: std::io::Error) -> Self {
        SteError::IoError(err.to_string())
    }
}

// Convert from bincode errors (when serialization feature is enabled)
#[cfg(feature = "distributed")]
impl From<bincode::Error> for SteError {
    fn from(err: bincode::Error) -> Self {
        SteError::SerializationError(err.to_string())
    }
}

// Convert from Box<dyn Error> for compatibility
impl From<Box<dyn std::error::Error>> for SteError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        SteError::CryptoError(err.to_string())
    }
}

