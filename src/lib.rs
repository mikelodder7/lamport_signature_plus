/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#![cfg_attr(coverage_nightly, allow(unstable_features))]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Implementation of [Lamport's one-time signature scheme](https://en.wikipedia.org/wiki/Lamport_signature).
//!
//! # Usage
//!
//! ```
//! use lamport_signature_plus::{VerifyingKey, SigningKey, LamportFixedDigest};
//! use sha2::Sha256;
//! use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
//!
//! let mut rng = ChaChaRng::from_rng(&mut rand::rng());
//! let mut signing_key = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
//! let verifying_key = VerifyingKey::from(&signing_key);
//! let signature = signing_key.sign(b"Hello, World!").expect("signing failed");
//! assert!(verifying_key.verify(&signature, b"Hello, World!").is_ok());
//! ```
//!
//! # Digest algorithms
//!
//! [`SigningKey`] and [`VerifyingKey`] accept hash functions provided by
//! [RustCrypto/hashes](https://github.com/RustCrypto/hashes). Use
//! [`LamportFixedDigest`] for fixed-output functions or
//! [`LamportExtendableDigest`] for extendable-output functions. Extendable-output
//! functions use a 64-byte output.
//!
//! # Extendable-output example
//!
//! ```
//! use lamport_signature_plus::{VerifyingKey, SigningKey, LamportExtendableDigest};
//! use shake::Shake128;
//! use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
//!
//! let mut rng = ChaChaRng::from_rng(&mut rand::rng());
//! let mut signing = SigningKey::<LamportExtendableDigest<Shake128>>::random(rng);
//! let verifying = VerifyingKey::from(&signing);
//! let signature = signing.sign(b"Hello, World!").expect("signing failed");
//! assert!(verifying.verify(&signature, b"Hello, World!").is_ok());
//! ```
//!
//! # Random number generators
//!
//! [`SigningKey`] requires a cryptographically secure random number generator
//! that implements `CryptoRng`.
//!
//! # Note
//!
//! A [`SigningKey`] can securely sign only one message. Attempting to sign with
//! a used key returns an error.
//!
//! # Merkle-tree Lamport signatures
//!
//! [`MtSigningKey`] commits 2, 4, or 8 one-time Lamport public keys in a
//! Merkle tree. Its compact [`MtVerifyingKey`] is only the tree depth and root.
//! Each [`MtSignature`] carries its leaf public key and authentication path.
//!
//! ```
//! use lamport_signature_plus::{LamportFixedDigest, generate_mt_keys};
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha8Rng;
//! use sha2::Sha256;
//!
//! let mut rng = ChaCha8Rng::from_seed([7; 32]);
//! let (mut signing_key, verifying_key) =
//!     generate_mt_keys::<LamportFixedDigest<Sha256>, _>(2, &mut rng)?;
//!
//! let signature = signing_key.sign(b"first message")?;
//! assert_eq!(signature.index(), 0);
//! verifying_key.verify(&signature, b"first message")?;
//! # Ok::<(), lamport_signature_plus::LamportError>(())
//! ```
//!
//! The MT signing key is stateful. Persist its updated state after every
//! signature; restoring an older copy can reuse a Lamport leaf and destroy
//! security. Each signing operation destroys the consumed leaf secret, so the
//! canonical signing-key state becomes smaller as indices are consumed.

#[macro_use]
mod utils;
mod error;
mod hash;
mod merkle;
mod multi_vec;
mod signature;
mod signing;
mod verifying;

pub use error::{LamportError, LamportResult};
pub use hash::{LamportDigest, LamportExtendableDigest, LamportFixedDigest};
pub use merkle::{MtSignature, MtSignatureShare, MtSigningKey, MtSigningKeyShare, MtVerifyingKey};
pub use multi_vec::MultiVec;
pub use signature::{Signature, SignatureShare};
pub use signing::{SigningKey, SigningKeyShare};
pub use verifying::VerifyingKey;

use rand_core::CryptoRng;

/// Generate a new key pair.
pub fn generate_keys<T: LamportDigest, R: CryptoRng>(rng: R) -> (SigningKey<T>, VerifyingKey<T>) {
    let sk = SigningKey::<T>::random(rng);
    let pk = VerifyingKey::from(&sk);
    (sk, pk)
}

/// Generate a stateful Merkle-tree Lamport key pair.
///
/// `depth` must be 1, 2, or 3, providing 2, 4, or 8 one-time signatures.
/// The caller must persist the updated signing key after each signature to
/// prevent state rollback and one-time-key reuse.
pub fn generate_mt_keys<T: LamportDigest, R: CryptoRng>(
    depth: u8,
    rng: R,
) -> LamportResult<(MtSigningKey<T>, MtVerifyingKey<T>)> {
    let sk = MtSigningKey::<T>::random(depth, rng)?;
    let pk = MtVerifyingKey::from(&sk);
    Ok((sk, pk))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use sha2::Sha256;
    use sha3::{Sha3_256, Sha3_512};
    use shake::Shake128;
    const SEED: [u8; 32] = [3u8; 32];
    type Digest = LamportFixedDigest<Sha3_256>;

    #[test]
    fn key_bytes_round_trip() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (mut sk, original_public_key) = generate_keys::<LamportFixedDigest<Sha3_256>, _>(rng);

        let bytes = original_public_key.to_bytes();
        let res = VerifyingKey::<LamportFixedDigest<Sha3_256>>::from_bytes(&bytes);
        assert!(res.is_ok());
        let restored_public_key = res.expect("operation should succeed");
        assert_eq!(
            restored_public_key.to_bytes(),
            original_public_key.to_bytes()
        );

        let bytes = sk.to_bytes();
        let res = SigningKey::<LamportFixedDigest<Sha3_256>>::from_bytes(&bytes);
        assert!(res.is_ok());
        let restored_private_key = res.expect("operation should succeed");
        assert_eq!(restored_private_key.to_bytes(), sk.to_bytes());

        let signature = sk.sign(b"hello, world!").expect("operation should succeed");
        let bytes = signature.to_bytes();
        let res = Signature::<LamportFixedDigest<Sha3_256>>::from_bytes(&bytes);
        assert!(res.is_ok());
        let restored_signature = res.expect("operation should succeed");
        assert_eq!(restored_signature.to_bytes(), signature.to_bytes());
    }

    #[test]
    fn generate_sha3_256_private_key() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let private_key = SigningKey::<LamportFixedDigest<Sha3_256>>::random(rng);

        assert!(!private_key.used());
        assert_eq!(private_key.zero_values.len(), 256 * 32);
        assert_eq!(private_key.one_values.len(), 256 * 32);
    }

    #[test]
    fn generate_sha3_512_private_key() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let private_key = SigningKey::<LamportFixedDigest<Sha3_512>>::random(rng);

        assert!(!private_key.used());
        assert_eq!(private_key.zero_values.len(), 512 * 64);
        assert_eq!(private_key.one_values.len(), 512 * 64);
    }

    #[test]
    fn sign_fixed() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (mut sk, pk) = generate_keys::<LamportFixedDigest<Sha3_256>, _>(rng);

        let message = b"hello, world!";
        let signature = sk.sign(message).expect("operation should succeed");
        assert!(pk.verify(&signature, message).is_ok());
        assert!(pk.verify(&signature, b"hello, world").is_err());
    }

    #[test]
    fn sign_xof() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (mut sk, pk) = generate_keys::<LamportExtendableDigest<Shake128>, _>(rng);

        let message = b"hello, world!";
        let signature = sk.sign(message).expect("operation should succeed");
        assert!(pk.verify(&signature, message).is_ok());
        assert!(pk.verify(&signature, b"hello, world").is_err());
    }

    #[test]
    fn vsss_key_round_trip() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let sk = SigningKey::<LamportFixedDigest<Sha256>>::random(&mut rng);
        let res = sk.split(3, 5, &mut rng);
        assert!(res.is_ok());
        let shares = res.expect("operation should succeed");

        let res = SigningKey::<LamportFixedDigest<Sha256>>::combine(&shares[0..3]);
        assert!(res.is_ok());
        let restored_key = res.expect("operation should succeed");
        assert_eq!(restored_key.to_bytes(), sk.to_bytes());

        let res = SigningKey::<LamportFixedDigest<Sha256>>::combine(&shares[2..5]);
        assert!(res.is_ok());
        let restored_key = res.expect("operation should succeed");
        assert_eq!(restored_key.to_bytes(), sk.to_bytes());

        let res = SigningKey::<LamportFixedDigest<Sha256>>::combine(&shares[0..2]);
        assert!(res.is_err());
    }

    #[test]
    fn partial_sign() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (sk, pk) = generate_keys::<LamportFixedDigest<Sha256>, _>(&mut rng);
        let message = b"hello, world!";
        let mut shares = sk.split(3, 5, &mut rng).expect("operation should succeed");
        let signatures = shares
            .iter_mut()
            .map(|share| share.sign(message).expect("operation should succeed"))
            .collect::<Vec<_>>();

        let res = Signature::combine(&signatures[..3]);
        assert!(res.is_ok());
        let signature = res.expect("operation should succeed");
        assert!(pk.verify(&signature, message).is_ok());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_postcard_round_trip() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (mut sk, pk) = generate_keys::<Digest, _>(rng);
        let message = b"hello, world!";
        let signature = sk.sign(message).expect("sign");

        let pk_bytes = postcard::to_stdvec(&pk).expect("postcard serialize pk");
        println!("pk_bytes: {}", pk_bytes.len());
        let pk_restored: VerifyingKey<Digest> =
            postcard::from_bytes(&pk_bytes).expect("postcard deserialize pk");
        assert_eq!(pk.to_bytes(), pk_restored.to_bytes());

        let sk_bytes = postcard::to_stdvec(&sk).expect("postcard serialize sk");
        println!("sk_bytes: {}", sk_bytes.len());
        let sk_restored: SigningKey<Digest> =
            postcard::from_bytes(&sk_bytes).expect("postcard deserialize sk");
        assert_eq!(sk.to_bytes(), sk_restored.to_bytes());

        let sig_bytes = postcard::to_stdvec(&signature).expect("postcard serialize sig");
        println!("sig_bytes: {}", sig_bytes.len());
        let sig_restored: Signature<Digest> =
            postcard::from_bytes(&sig_bytes).expect("postcard deserialize sig");
        assert_eq!(signature.to_bytes(), sig_restored.to_bytes());
        assert!(pk_restored.verify(&sig_restored, message).is_ok());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_json_round_trip() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (mut sk, pk) = generate_keys::<Digest, _>(rng);
        let message = b"hello, world!";
        let signature = sk.sign(message).expect("sign");

        let pk_json = serde_json::to_string(&pk).expect("serde_json serialize pk");
        let pk_restored: VerifyingKey<Digest> =
            serde_json::from_str(&pk_json).expect("serde_json deserialize pk");
        assert_eq!(pk.to_bytes(), pk_restored.to_bytes());

        let sk_json = serde_json::to_string(&sk).expect("serde_json serialize sk");
        let sk_restored: SigningKey<Digest> =
            serde_json::from_str(&sk_json).expect("serde_json deserialize sk");
        assert_eq!(sk.to_bytes(), sk_restored.to_bytes());

        let sig_json = serde_json::to_string(&signature).expect("serde_json serialize sig");
        let sig_restored: Signature<Digest> =
            serde_json::from_str(&sig_json).expect("serde_json deserialize sig");
        assert_eq!(signature.to_bytes(), sig_restored.to_bytes());
        assert!(pk_restored.verify(&sig_restored, message).is_ok());
    }
}
