/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use thiserror::Error;

/// Errors in lamport signing scheme.
#[derive(Error, Debug)]
pub enum LamportError {
    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// Vsss error.
    #[error("Vsss error: {0}")]
    VsssError(vsss_rs::Error),
    /// Private key was reused.
    #[error("Private key was reused.")]
    PrivateKeyReuseError,
    /// Invalid private key bytes.
    #[error("Invalid private key bytes.")]
    InvalidPrivateKeyBytes,
    /// Invalid signature bytes.
    #[error("Invalid signature bytes.")]
    InvalidSignatureBytes,
    /// General Purpose errors
    #[error("General error: {0}")]
    General(String),
}

impl From<vsss_rs::Error> for LamportError {
    fn from(err: vsss_rs::Error) -> Self {
        LamportError::VsssError(err)
    }
}

impl From<&vsss_rs::Error> for LamportError {
    fn from(err: &vsss_rs::Error) -> Self {
        LamportError::VsssError(*err)
    }
}

/// Result type for Lamport errors.
pub type LamportResult<T> = Result<T, LamportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_have_useful_messages_and_conversions() {
        let io = LamportError::from(std::io::Error::other("disk"));
        assert_eq!(io.to_string(), "I/O error: disk");
        assert_eq!(
            LamportError::PrivateKeyReuseError.to_string(),
            "Private key was reused."
        );
        assert_eq!(
            LamportError::InvalidPrivateKeyBytes.to_string(),
            "Invalid private key bytes."
        );
        assert_eq!(
            LamportError::InvalidSignatureBytes.to_string(),
            "Invalid signature bytes."
        );
        assert_eq!(
            LamportError::General("details".into()).to_string(),
            "General error: details"
        );

        let source = vsss_rs::Error::SharingMinThreshold;
        assert!(matches!(
            LamportError::from(source),
            LamportError::VsssError(vsss_rs::Error::SharingMinThreshold)
        ));
        assert!(matches!(
            LamportError::from(&source),
            LamportError::VsssError(vsss_rs::Error::SharingMinThreshold)
        ));
    }
}
