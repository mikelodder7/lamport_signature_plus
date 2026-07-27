/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::MultiVec;
use digest::{
    Digest, ExtendableOutput, FixedOutput, HashMarker, Update, XofReader, block_api::BlockSizeUser,
    typenum::Unsigned,
};
use rand_core::CryptoRng;
use std::marker::PhantomData;

/// A trait for providing Lamport supported digest functions.
pub trait LamportDigest {
    /// The size of the digest in bits.
    fn digest_size_in_bits() -> usize;
    /// The size of the digest in bytes.
    fn digest_size_in_bytes() -> usize {
        let bits = Self::digest_size_in_bits();
        assert_eq!(bits % 8, 0, "digest size must be a whole number of bytes");
        bits / 8
    }
    /// Compute the digest on the provided data.
    fn digest(data: &[u8]) -> Vec<u8>;

    /// Compute the digest directly into a caller-provided output buffer.
    fn digest_into(data: &[u8], output: &mut [u8]) {
        let digest = Self::digest(data);
        assert_eq!(digest.len(), output.len());
        output.copy_from_slice(&digest);
    }

    /// Hash the input [`MultiVec`] data to output another [`MultiVec`].
    fn hash(data: &MultiVec<u8, 2>) -> MultiVec<u8, 2> {
        let bits = Self::digest_size_in_bits();
        let bytes = Self::digest_size_in_bytes();
        assert_eq!(data.axes[0], bits);
        assert_eq!(data.axes[1], bytes);
        let mut outer = MultiVec::fill([bits, bytes], 0);
        for (row, output) in data
            .data
            .chunks_exact(bytes)
            .zip(outer.data.chunks_exact_mut(bytes))
        {
            Self::digest_into(row, output);
        }
        outer
    }

    /// Generate a random [`MultiVec`] data.
    fn random(mut rng: impl CryptoRng) -> MultiVec<u8, 2> {
        let bits = Self::digest_size_in_bits();
        let bytes = Self::digest_size_in_bytes();
        let mut data = vec![0u8; bits * bytes];
        rng.fill_bytes(&mut data);
        MultiVec {
            data,
            axes: [bits, bytes],
        }
    }
}

/// Lamport signature scheme than uses fixed output functions.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct LamportFixedDigest<T>(PhantomData<T>)
where
    T: BlockSizeUser + Default + FixedOutput + HashMarker;

impl<T> LamportDigest for LamportFixedDigest<T>
where
    T: BlockSizeUser + Default + FixedOutput + HashMarker,
{
    fn digest_size_in_bits() -> usize {
        T::OutputSize::to_usize() * 8
    }

    fn digest(data: &[u8]) -> Vec<u8> {
        T::digest(data).to_vec()
    }

    fn digest_into(data: &[u8], output: &mut [u8]) {
        assert_eq!(output.len(), T::OutputSize::to_usize());
        output.copy_from_slice(&T::digest(data));
    }
}

/// Lamport signature scheme than uses extendable output functions.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct LamportExtendableDigest<T>(PhantomData<T>)
where
    T: Default + ExtendableOutput + Update;

impl<T> LamportDigest for LamportExtendableDigest<T>
where
    T: Default + ExtendableOutput + Update,
{
    fn digest_size_in_bits() -> usize {
        512
    }

    fn digest(data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; 64];
        Self::digest_into(data, &mut output);
        output
    }

    fn digest_into(data: &[u8], output: &mut [u8]) {
        assert_eq!(output.len(), 64);
        let mut hasher = T::default();
        hasher.update(data);
        hasher.finalize_xof().read(output);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use sha2::Sha256;
    use shake::Shake128;

    struct FallbackDigest;

    impl LamportDigest for FallbackDigest {
        fn digest_size_in_bits() -> usize {
            8
        }

        fn digest(data: &[u8]) -> Vec<u8> {
            vec![u8::try_from(data.len()).expect("test input length fits in u8")]
        }
    }

    struct InvalidSizeDigest;

    impl LamportDigest for InvalidSizeDigest {
        fn digest_size_in_bits() -> usize {
            7
        }

        fn digest(_data: &[u8]) -> Vec<u8> {
            vec![0]
        }
    }

    #[test]
    fn fallback_digest_writes_into_caller_buffer() {
        let mut output = [0u8; 1];
        FallbackDigest::digest_into(b"abc", &mut output);
        assert_eq!(output, [3]);
        assert_eq!(FallbackDigest::digest_size_in_bytes(), 1);
    }

    #[test]
    fn concrete_digest_helpers_return_expected_lengths() {
        assert_eq!(LamportFixedDigest::<Sha256>::digest(b"message").len(), 32);
        assert_eq!(
            LamportExtendableDigest::<Shake128>::digest(b"message").len(),
            64
        );
    }

    #[test]
    #[should_panic(expected = "digest size must be a whole number of bytes")]
    fn digest_size_rejects_partial_bytes() {
        assert_eq!(InvalidSizeDigest::digest(b"message"), [0]);
        let _ = InvalidSizeDigest::digest_size_in_bytes();
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn fallback_digest_rejects_wrong_output_size() {
        FallbackDigest::digest_into(b"abc", &mut [0u8; 2]);
    }
}
