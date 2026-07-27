/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::signature::SignatureShare;
use crate::utils::{CanonicalBytes, encode_slices, prefixed_share, separate_one_and_zero_values};
use crate::{LamportDigest, LamportError, LamportResult, MultiVec, Signature};
use std::marker::PhantomData;
use subtle::{Choice, ConditionallySelectable};
use vsss_rs::Gf256;
use zeroize::Zeroize;

fn sign_with_values<T: LamportDigest>(
    zero_values: &MultiVec<u8, 2>,
    one_values: &MultiVec<u8, 2>,
    data: &[u8],
) -> Signature<T> {
    let bits = T::digest_size_in_bits();
    let bytes = T::digest_size_in_bytes();
    let mut data_hash = vec![0u8; bytes];
    T::digest_into(data, &mut data_hash);
    let mut signature = MultiVec::fill([bits, bytes], 0);

    for (((zero, one), output), bit) in zero_values
        .data
        .chunks_exact(bytes)
        .zip(one_values.data.chunks_exact(bytes))
        .zip(signature.data.chunks_exact_mut(bytes))
        .zip(
            data_hash
                .iter()
                .flat_map(|byte| (0..8).map(move |shift| (byte >> shift) & 1)),
        )
    {
        let choice = Choice::from(bit);
        for ((zero_byte, one_byte), output_byte) in zero.iter().zip(one).zip(output.iter_mut()) {
            *output_byte = u8::conditional_select(zero_byte, one_byte, choice);
        }
    }

    Signature {
        data: signature,
        algorithm: PhantomData,
    }
}

fn signing_key_share_from_parts<T: LamportDigest>(
    mut zero_share: Vec<u8>,
    mut one_share: Vec<u8>,
    axes: [usize; 2],
    used: bool,
    threshold: u8,
) -> SigningKeyShare<T> {
    let identifier = zero_share[0];
    // `Gf256::split_array` deterministically emits the same identifiers for equal share counts.
    zero_share.remove(0);
    one_share.remove(0);
    SigningKeyShare {
        identifier,
        zero_values: MultiVec {
            data: zero_share,
            axes,
        },
        one_values: MultiVec {
            data: one_share,
            axes,
        },
        used,
        threshold,
        algorithm: PhantomData,
    }
}

fn signing_key_shares_from_parts<T: LamportDigest>(
    zero_shares: Vec<Vec<u8>>,
    one_shares: Vec<Vec<u8>>,
    axes: [usize; 2],
    used: bool,
    threshold: u8,
) -> Vec<SigningKeyShare<T>> {
    zero_shares
        .into_iter()
        .zip(one_shares)
        .map(|(zero_share, one_share)| {
            signing_key_share_from_parts(zero_share, one_share, axes, used, threshold)
        })
        .collect()
}

#[derive(Copy, Clone)]
enum SharePart {
    Zero,
    One,
}

fn combine_share_values<T: LamportDigest>(
    shares: &[SigningKeyShare<T>],
    part: SharePart,
) -> LamportResult<Vec<u8>> {
    let encoded = shares
        .iter()
        .map(|share| {
            let values = match part {
                SharePart::Zero => &share.zero_values.data,
                SharePart::One => &share.one_values.data,
            };
            prefixed_share(share.identifier, values)
        })
        .collect::<Vec<_>>();
    Ok(Gf256::combine_array(&encoded)?)
}

fn split_values(
    threshold: usize,
    shares: usize,
    values: &[u8],
    rng: &mut impl rand::CryptoRng,
) -> LamportResult<Vec<Vec<u8>>> {
    Ok(Gf256::split_array(threshold, shares, values, rng)?)
}

/// A one-time signing private key.
#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SigningKey<T: LamportDigest> {
    pub(crate) zero_values: MultiVec<u8, 2>,
    pub(crate) one_values: MultiVec<u8, 2>,
    pub(crate) used: bool,
    pub(crate) algorithm: PhantomData<T>,
}

serde_impl!(SigningKey);
vec_impl!(SigningKey);

#[cfg_attr(coverage_nightly, coverage(off))]
impl<T: LamportDigest> CanonicalBytes for SigningKey<T> {
    fn canonical_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Owned(self.to_bytes())
    }
}

impl<T: LamportDigest> Zeroize for SigningKey<T> {
    fn zeroize(&mut self) {
        self.zero_values.zeroize();
        self.one_values.zeroize();
    }
}

impl<T: LamportDigest> Drop for SigningKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: LamportDigest> SigningKey<T> {
    /// Has this key been used.
    pub fn used(&self) -> bool {
        self.used
    }

    /// Constructs a [`SigningKey`] with Digest algorithm type and the specified RNG.
    pub fn random(mut rng: impl rand::CryptoRng) -> SigningKey<T> {
        SigningKey {
            zero_values: T::random(&mut rng),
            one_values: T::random(&mut rng),
            used: false,
            algorithm: PhantomData,
        }
    }

    /// Signs the data.
    ///
    /// # Example
    ///
    /// ```
    /// use sha2::Sha256;
    /// use rand::SeedableRng;
    /// use rand_chacha::ChaCha12Rng;
    /// use lamport_signature_plus::{LamportFixedDigest, SigningKey};
    ///
    /// const SEED: [u8; 32] = [0; 32];
    /// let rng = ChaCha12Rng::from_seed(SEED);
    /// let mut private_key = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// assert!(private_key.sign(MESSAGE).is_ok());
    /// ```
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn sign<B: AsRef<[u8]>>(&mut self, data: B) -> LamportResult<Signature<T>> {
        if self.used {
            return Err(LamportError::PrivateKeyReuseError);
        }
        let signature = sign_with_values::<T>(&self.zero_values, &self.one_values, data.as_ref());
        self.used = true;
        Ok(signature)
    }

    /// Converts the [`SigningKey`] to canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_slices(
            &[self.used as u8],
            &[self.zero_values.as_ref(), self.one_values.as_ref()],
        )
    }

    /// Constructs a [`SigningKey`] from canonical bytes.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        let bits = T::digest_size_in_bits();
        let bytes = T::digest_size_in_bytes();

        if input.len() != bits * bytes * 2 + 1 {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let used = match input[0] {
            0 => false,
            1 => true,
            _ => return Err(LamportError::InvalidPrivateKeyBytes),
        };
        let (zero_values, one_values) = separate_one_and_zero_values(&input[1..], bytes);
        Ok(Self {
            used,
            zero_values,
            one_values,
            algorithm: PhantomData,
        })
    }

    /// Create secret shares of the signing key where `threshold` are required
    /// to combine back into this secret.
    ///
    /// The random number generator must be cryptographically secure.
    pub fn split(
        &self,
        threshold: usize,
        shares: usize,
        mut rng: impl rand::CryptoRng,
    ) -> LamportResult<Vec<SigningKeyShare<T>>> {
        let threshold_u8 = u8::try_from(threshold)
            .map_err(|_| LamportError::General("threshold out of range".into()))?;

        let mut split_shares = [
            self.zero_values.data.as_slice(),
            self.one_values.data.as_slice(),
        ]
        .into_iter()
        .map(|values| split_values(threshold, shares, values, &mut rng))
        .collect::<LamportResult<Vec<_>>>()?;
        let zero_shares = split_shares.remove(0);
        let one_shares = split_shares.remove(0);

        let output = signing_key_shares_from_parts(
            zero_shares,
            one_shares,
            self.zero_values.axes,
            self.used,
            threshold_u8,
        );

        Ok(output)
    }

    /// Reconstruct the signing key from the secret shares created by `split`
    pub fn combine(shares: &[SigningKeyShare<T>]) -> LamportResult<Self> {
        if shares.is_empty() {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let first = &shares[0];
        if first.identifier == 0
            || first.threshold < 2
            || shares.iter().any(|share| {
                share.identifier == 0
                    || share.threshold != first.threshold
                    || share.zero_values.axes != first.zero_values.axes
                    || share.one_values.axes != first.one_values.axes
                    || share.zero_values.len() != first.zero_values.len()
                    || share.one_values.len() != first.one_values.len()
            })
        {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        if shares.len() < first.threshold as usize {
            return Err(LamportError::VsssError(vsss_rs::Error::SharingMinThreshold));
        }

        let mut combined = [SharePart::Zero, SharePart::One]
            .into_iter()
            .map(|part| combine_share_values(shares, part))
            .collect::<LamportResult<Vec<_>>>()?;
        let zero_data = combined.remove(0);
        let one_data = combined.remove(0);

        let used = shares.iter().any(|s| s.used);

        Ok(Self {
            zero_values: MultiVec {
                data: zero_data,
                axes: shares[0].zero_values.axes,
            },
            one_values: MultiVec {
                data: one_data,
                axes: shares[0].one_values.axes,
            },
            used,
            algorithm: PhantomData,
        })
    }
}

/// A key share that must be combined with other secret key shares to produce the signing key,
/// or used for creating partial signatures.
#[derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SigningKeyShare<T: LamportDigest> {
    pub(crate) identifier: u8,
    pub(crate) zero_values: MultiVec<u8, 2>,
    pub(crate) one_values: MultiVec<u8, 2>,
    pub(crate) used: bool,
    pub(crate) threshold: u8,
    pub(crate) algorithm: PhantomData<T>,
}

serde_impl!(SigningKeyShare);
vec_impl!(SigningKeyShare);

#[cfg_attr(coverage_nightly, coverage(off))]
impl<T: LamportDigest> CanonicalBytes for SigningKeyShare<T> {
    fn canonical_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Owned(self.to_bytes())
    }
}

impl<T: LamportDigest> Zeroize for SigningKeyShare<T> {
    fn zeroize(&mut self) {
        self.zero_values.zeroize();
        self.one_values.zeroize();
    }
}

impl<T: LamportDigest> Drop for SigningKeyShare<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: LamportDigest> SigningKeyShare<T> {
    /// Signs the data to create a [`SignatureShare`].
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn sign<B: AsRef<[u8]>>(&mut self, data: B) -> LamportResult<SignatureShare<T>> {
        if self.used {
            return Err(LamportError::PrivateKeyReuseError);
        }
        let signature = sign_with_values::<T>(&self.zero_values, &self.one_values, data.as_ref());
        self.used = true;
        Ok(SignatureShare {
            identifier: self.identifier,
            threshold: self.threshold,
            data: signature.data,
            algorithm: PhantomData,
        })
    }

    /// Converts the [`SigningKeyShare`] to canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_slices(
            &[self.identifier, self.threshold, self.used as u8],
            &[self.zero_values.as_ref(), self.one_values.as_ref()],
        )
    }

    /// Constructs a [`SigningKeyShare`] from canonical bytes.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        let bits = T::digest_size_in_bits();
        let bytes = T::digest_size_in_bytes();

        if input.len() != bits * bytes * 2 + 3 {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let identifier = input[0];
        let threshold = input[1];
        if identifier == 0 {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        if threshold < 2 {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let used = match input[2] {
            0 => false,
            1 => true,
            _ => return Err(LamportError::InvalidPrivateKeyBytes),
        };
        let (zero_values, one_values) = separate_one_and_zero_values(&input[3..], bytes);
        Ok(Self {
            identifier,
            used,
            threshold,
            zero_values,
            one_values,
            algorithm: PhantomData,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::LamportFixedDigest;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sha2::Sha256;

    type Digest = LamportFixedDigest<Sha256>;

    fn key_and_shares() -> (SigningKey<Digest>, Vec<SigningKeyShare<Digest>>) {
        let mut rng = ChaCha8Rng::from_seed([9; 32]);
        let key = SigningKey::<Digest>::random(&mut rng);
        let shares = key
            .split(2, 3, &mut rng)
            .expect("key splitting should succeed");
        (key, shares)
    }

    #[test]
    fn signing_key_state_and_bytes_round_trip() {
        let (mut key, _) = key_and_shares();
        assert!(!key.used());
        let bytes = key.to_bytes();
        assert_eq!(
            SigningKey::<Digest>::from_bytes(&bytes)
                .expect("key decoding should succeed")
                .to_bytes(),
            bytes
        );

        key.sign(b"message").expect("signing should succeed");
        assert!(key.used());
        assert!(matches!(
            key.sign(b"again"),
            Err(LamportError::PrivateKeyReuseError)
        ));

        let used_bytes = key.to_bytes();
        assert!(
            SigningKey::<Digest>::from_bytes(used_bytes)
                .expect("used key decoding should succeed")
                .used()
        );

        let mut noncanonical_flag = bytes;
        noncanonical_flag[0] = 2;
        assert!(matches!(
            SigningKey::<Digest>::from_bytes(noncanonical_flag),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        assert!(matches!(
            SigningKey::<Digest>::from_bytes([]),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        assert!(serde_json::from_str::<SigningKey<Digest>>("\"not-hex\"").is_err());
        assert!(serde_json::from_str::<SigningKey<Digest>>("\"00\"").is_err());
        assert!(serde_json::from_str::<SigningKey<Digest>>("123").is_err());
        assert!(postcard::from_bytes::<SigningKey<Digest>>(&[0xff]).is_err());
    }

    #[test]
    fn split_and_combine_validate_thresholds() {
        let (key, mut shares) = key_and_shares();
        let mut rng = ChaCha8Rng::from_seed([10; 32]);
        assert!(matches!(
            key.split(usize::from(u8::MAX) + 1, usize::from(u8::MAX) + 1, &mut rng),
            Err(LamportError::General(_))
        ));
        assert!(key.split(0, 2, &mut rng).is_err());
        assert!(matches!(
            SigningKey::<Digest>::combine(&[]),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        assert!(matches!(
            SigningKey::<Digest>::combine(&shares[..1]),
            Err(LamportError::VsssError(vsss_rs::Error::SharingMinThreshold))
        ));

        shares[1].threshold = 3;
        assert!(matches!(
            SigningKey::<Digest>::combine(&shares[..2]),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        shares[1].threshold = 2;
        shares[1].zero_values.axes = [1, shares[1].zero_values.len()];
        assert!(matches!(
            SigningKey::<Digest>::combine(&shares[..2]),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));

        let (_, mut duplicate_identifier_shares) = key_and_shares();
        duplicate_identifier_shares[1].identifier = duplicate_identifier_shares[0].identifier;
        assert!(SigningKey::<Digest>::combine(&duplicate_identifier_shares[..2]).is_err());
    }

    #[test]
    fn signing_key_share_round_trip_validation_and_reuse() {
        let (_, mut shares) = key_and_shares();
        let share = &mut shares[0];
        let bytes = share.to_bytes();
        assert_eq!(
            SigningKeyShare::<Digest>::from_bytes(&bytes)
                .expect("key share decoding should succeed")
                .to_bytes(),
            bytes
        );

        assert!(matches!(
            SigningKeyShare::<Digest>::from_bytes([]),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        let mut invalid_identifier = bytes.clone();
        invalid_identifier[0] = 0;
        assert!(matches!(
            SigningKeyShare::<Digest>::from_bytes(invalid_identifier),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        let mut invalid_threshold = bytes;
        invalid_threshold[1] = 1;
        assert!(matches!(
            SigningKeyShare::<Digest>::from_bytes(invalid_threshold),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        let mut invalid_used = share.to_bytes();
        invalid_used[2] = 2;
        assert!(matches!(
            SigningKeyShare::<Digest>::from_bytes(invalid_used),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));

        let json = serde_json::to_string(share).expect("share JSON serialization should succeed");
        let decoded: SigningKeyShare<Digest> =
            serde_json::from_str(&json).expect("share JSON deserialization should succeed");
        assert_eq!(decoded.to_bytes(), share.to_bytes());

        let postcard =
            postcard::to_stdvec(share).expect("share postcard serialization should succeed");
        let decoded: SigningKeyShare<Digest> =
            postcard::from_bytes(&postcard).expect("share postcard deserialization should succeed");
        assert_eq!(decoded.to_bytes(), share.to_bytes());

        share
            .sign(b"message")
            .expect("share signing should succeed");
        let used_share = SigningKeyShare::<Digest>::from_bytes(share.to_bytes())
            .expect("used share decoding should succeed");
        assert!(used_share.used);
        assert!(matches!(
            share.sign(b"again"),
            Err(LamportError::PrivateKeyReuseError)
        ));

        assert!(serde_json::from_str::<SigningKeyShare<Digest>>("\"not-hex\"").is_err());
        assert!(serde_json::from_str::<SigningKeyShare<Digest>>("\"00\"").is_err());
        assert!(serde_json::from_str::<SigningKeyShare<Digest>>("123").is_err());
        assert!(postcard::from_bytes::<SigningKeyShare<Digest>>(&[0xff]).is_err());
    }

    #[test]
    fn zeroize_clears_private_material() {
        let (mut key, mut shares) = key_and_shares();
        key.zeroize();
        shares[0].zeroize();
        assert!(key.zero_values.is_empty());
        assert!(key.one_values.is_empty());
        assert!(shares[0].zero_values.is_empty());
        assert!(shares[0].one_values.is_empty());
    }
}
