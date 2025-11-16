/// Error types for the silent threshold encryption library
use std::fmt;

#[derive(Debug, Clone)]
pub enum SteError {
    /// Invalid parameter provided (e.g., tau is zero, n is not a power of 2)
    InvalidParameter(String),
    /// KZG commitment or operation failed
    KzgError(String),
    /// Domain creation failed (e.g., n is not a power of 2)
    DomainError(String),
    /// Input validation failed
    ValidationError(String),
    /// MSM (Multi-Scalar Multiplication) operation failed
    MsmError(String),
    /// Serialization/deserialization error
    SerializationError(String),
}

impl fmt::Display for SteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SteError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            SteError::KzgError(msg) => write!(f, "KZG error: {}", msg),
            SteError::DomainError(msg) => write!(f, "Domain error: {}", msg),
            SteError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            SteError::MsmError(msg) => write!(f, "MSM error: {}", msg),
            SteError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for SteError {}

// Convert from KZG errors
impl From<crate::kzg::Error> for SteError {
    fn from(err: crate::kzg::Error) -> Self {
        SteError::KzgError(format!("{:?}", err))
    }
}

