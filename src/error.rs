/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use thiserror::Error;

/// Errors produced by the Lamport signature scheme.
#[derive(Error, Debug)]
pub enum LamportError {
    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    /// VSSS error.
    #[error("VSSS error: {0}")]
    VsssError(vsss_rs::Error),
    /// Private key was reused.
    #[error("Private key was reused.")]
    PrivateKeyReuseError,
    /// The Merkle tree depth is not supported.
    #[error("Merkle tree depth must be between 1 and 3.")]
    InvalidTreeDepth,
    /// All one-time keys in the Merkle tree have been used.
    #[error("All Merkle tree signing keys have been used.")]
    NoUnusedSigningKeys,
    /// The Merkle authentication path is invalid.
    #[error("Invalid Merkle authentication path.")]
    InvalidMerkleProof,
    /// Invalid private key bytes.
    #[error("Invalid private key bytes.")]
    InvalidPrivateKeyBytes,
    /// Invalid signature bytes.
    #[error("Invalid signature bytes.")]
    InvalidSignatureBytes,
    /// General-purpose error.
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
            LamportError::InvalidTreeDepth.to_string(),
            "Merkle tree depth must be between 1 and 3."
        );
        assert_eq!(
            LamportError::NoUnusedSigningKeys.to_string(),
            "All Merkle tree signing keys have been used."
        );
        assert_eq!(
            LamportError::InvalidMerkleProof.to_string(),
            "Invalid Merkle authentication path."
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
