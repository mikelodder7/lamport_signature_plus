/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
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
//! # Digest Algorithm
//!
//! [`SigningKey`] and [`VerifyingKey`] can use any digest algorithm types that provided by [RustCrypto/hashes](https://github.com/RustCrypto/hashes) as a type argument to construct.
//! Algorithms can be either fixed output size or extendable output size.
//! Extendable Output Size algorithms default to 32 byte lengths.
//!
//! # Example of Extendable Output Size
//! ```
//! use lamport_signature_plus::{VerifyingKey, SigningKey, LamportExtendableDigest};
//! use sha3::Shake128;
//! use rand_chacha::{ChaChaRng, rand_core::SeedableRng};
//!
//! let mut rng = ChaChaRng::from_rng(&mut rand::rng());
//! let mut signing = SigningKey::<LamportExtendableDigest<Shake128>>::random(rng);
//! let verifying = VerifyingKey::from(&signing);
//! let signature = signing.sign(b"Hello, World!").expect("signing failed");
//! assert!(verifying.verify(&signature, b"Hello, World!").is_ok());
//! ```
//!
//! # RNG Algorithm
//!
//! [`SigningKey`] takes the cryptographically secure RNG implemented in [rust-lang-nursery/rand](https://github.com/rust-lang-nursery/rand) as an argument to construct,
//! i.e. RNG must implement the `RngCore` and `CryptoRng` traits.
//!
//! # Note
//! [`SigningKey`] can only be used once to securely sign a message. If an attempt is made to sign a message with a used key, an error returns.

#[macro_use]
mod utils;
mod error;
mod hash;
mod multi_vec;
mod signature;
mod signing;
mod verifying;

pub use error::{LamportError, LamportResult};
pub use hash::{LamportDigest, LamportExtendableDigest, LamportFixedDigest};
pub use multi_vec::MultiVec;
pub use signature::{Signature, SignatureShare};
pub use signing::{SigningKey, SigningKeyShare};
pub use utils::{Rand, SplitRng, TryRand};
pub use verifying::VerifyingKey;

use rand::CryptoRng;

/// Generate a new pair of keys.
pub fn generate_keys<T: LamportDigest, R: CryptoRng>(rng: R) -> (SigningKey<T>, VerifyingKey<T>) {
    let sk = SigningKey::<T>::random(rng);
    let pk = VerifyingKey::from(&sk);
    (sk, pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use sha2::Sha256;
    use sha3::{Sha3_256, Sha3_512, Shake128};
    const SEED: [u8; 32] = [3u8; 32];
    type Digest = LamportFixedDigest<Sha3_256>;

    #[test]
    fn key_bytes_round_trip() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (mut sk, original_public_key) = generate_keys::<LamportFixedDigest<Sha3_256>, _>(rng);

        let bytes = original_public_key.to_bytes();
        let res = VerifyingKey::<LamportFixedDigest<Sha3_256>>::from_bytes(&bytes);
        assert!(res.is_ok());
        let restored_public_key = res.unwrap();
        assert_eq!(
            restored_public_key.to_bytes(),
            original_public_key.to_bytes()
        );

        let bytes = sk.to_bytes();
        let res = SigningKey::<LamportFixedDigest<Sha3_256>>::from_bytes(&bytes);
        assert!(res.is_ok());
        let restored_private_key = res.unwrap();
        assert_eq!(restored_private_key.to_bytes(), sk.to_bytes());

        let signature = sk.sign(b"hello, world!").unwrap();
        let bytes = signature.to_bytes();
        let res = Signature::<LamportFixedDigest<Sha3_256>>::from_bytes(&bytes);
        assert!(res.is_ok());
        let restored_signature = res.unwrap();
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
        let signature = sk.sign(message).unwrap();
        assert!(pk.verify(&signature, message).is_ok());
        assert!(!pk.verify(&signature, b"hello, world").is_ok());
    }

    #[test]
    fn sign_xof() {
        let rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (mut sk, pk) = generate_keys::<LamportExtendableDigest<Shake128>, _>(rng);

        let message = b"hello, world!";
        let signature = sk.sign(message).unwrap();
        assert!(pk.verify(&signature, message).is_ok());
        assert!(!pk.verify(&signature, b"hello, world").is_ok());
    }

    #[test]
    fn vsss_key_round_trip() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let sk = SigningKey::<LamportFixedDigest<Sha256>>::random(&mut rng);
        let res = sk.split(3, 5, Rand::new(&mut rng));
        assert!(res.is_ok());
        let shares = res.unwrap();

        let res = SigningKey::<LamportFixedDigest<Sha256>>::combine(&shares[0..3]);
        assert!(res.is_ok());
        let restored_key = res.unwrap();
        assert_eq!(restored_key.to_bytes(), sk.to_bytes());

        let res = SigningKey::<LamportFixedDigest<Sha256>>::combine(&shares[2..5]);
        assert!(res.is_ok());
        let restored_key = res.unwrap();
        assert_eq!(restored_key.to_bytes(), sk.to_bytes());

        let res = SigningKey::<LamportFixedDigest<Sha256>>::combine(&shares[0..2]);
        assert!(res.is_err());
    }

    #[test]
    fn partial_sign() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
        let (sk, pk) = generate_keys::<LamportFixedDigest<Sha256>, _>(&mut rng);
        let message = b"hello, world!";
        let mut shares = sk.split(3, 5, Rand::new(&mut rng)).unwrap();
        let signatures = shares
            .iter_mut()
            .map(|share| share.sign(message).unwrap())
            .collect::<Vec<_>>();

        let res = Signature::combine(&signatures[..3]);
        assert!(res.is_ok());
        let signature = res.unwrap();
        assert!(pk.verify(&signature, message).is_ok());
    }

    #[test]
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
