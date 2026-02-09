/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::MultiVec;
use digest::core_api::BlockSizeUser;
use digest::{
    generic_array::typenum::Unsigned, Digest, ExtendableOutput, FixedOutput, HashMarker, Update,
    XofReader,
};
use rand::CryptoRng;
use std::marker::PhantomData;

/// A trait for providing Lamport supported digest functions.
pub trait LamportDigest {
    /// The size of the digest in bits.
    fn digest_size_in_bits() -> usize;
    /// Compute the digest on the provided data.
    fn digest(data: &[u8]) -> Vec<u8>;

    /// Hash the input [`MultiVec`] data to output another [`MultiVec`].
    fn hash(data: &MultiVec<u8, 2>) -> MultiVec<u8, 2> {
        let bits = Self::digest_size_in_bits();
        let bytes = bits / 8;
        assert_eq!(data.axes[0], bits);
        assert_eq!(data.axes[1], bytes);
        let mut outer = MultiVec::fill([bits, bytes], 0);
        {
            let mut outer_iter = outer.iter_mut();

            for row in data.data.chunks_exact(bytes) {
                let hashed = Self::digest(row);
                for byte in hashed.iter() {
                    *outer_iter.next().expect("another value") = *byte;
                }
            }
        }
        outer
    }

    /// Generate a random [`MultiVec`] data.
    fn random(mut rng: impl CryptoRng) -> MultiVec<u8, 2> {
        let bits = Self::digest_size_in_bits();
        let bytes = bits / 8;
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
        let mut hasher = T::default();
        hasher.update(data);
        let mut reader = hasher.finalize_xof();
        let mut output = vec![0u8; 64];
        reader.read(&mut output);
        output
    }
}
