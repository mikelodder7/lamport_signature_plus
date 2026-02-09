/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::signature::SignatureShare;
use crate::utils::{separate_one_and_zero_values, SplitRng};
use crate::{LamportDigest, LamportError, LamportResult, MultiVec, Signature};
use std::marker::PhantomData;
use subtle::{Choice, ConditionallySelectable};
use vsss_rs::Gf256;
use zeroize::Zeroize;

/// A one-time signing private key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SigningKey<T: LamportDigest> {
    pub(crate) zero_values: MultiVec<u8, 2>,
    pub(crate) one_values: MultiVec<u8, 2>,
    pub(crate) used: bool,
    pub(crate) algorithm: PhantomData<T>,
}

serde_impl!(SigningKey);
vec_impl!(SigningKey);

impl<T: LamportDigest> Zeroize for SigningKey<T> {
    fn zeroize(&mut self) {
        self.zero_values.zeroize();
        self.one_values.zeroize();
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
    pub fn sign<B: AsRef<[u8]>>(&mut self, data: B) -> LamportResult<Signature<T>> {
        if self.used {
            return Err(LamportError::PrivateKeyReuseError);
        }
        let data = data.as_ref();

        let data_hash = T::digest(data);

        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;
        let mut data = MultiVec::fill([bits, bytes], 0);
        // Ensure runtime is independent of secret keys
        // Ensure code access patterns are independent of secret keys
        // Ensure data access patterns are independent of secret keys
        {
            let mut signature_iter = data.iter_mut();
            let mut zero_iter = self.zero_values.iter();
            let mut one_iter = self.one_values.iter();
            for byte in data_hash.iter() {
                for j in 0..8 {
                    let b = (*byte >> j) & 1;
                    let choice = Choice::from(b);
                    for _ in 0..bytes {
                        *signature_iter.next().expect("more values") = u8::conditional_select(
                            zero_iter.next().expect("more values"),
                            one_iter.next().expect("more values"),
                            choice,
                        );
                    }
                }
            }
        }

        self.used = true;
        Ok(Signature {
            data,
            algorithm: PhantomData,
        })
    }

    /// Converts the [`SigningKey`] to canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;
        let mut bytes = vec![0u8; 1 + bytes * bits * 2];
        bytes[0] = self.used as u8;
        let iter = bytes[1..].iter_mut();
        for (i, z) in iter.zip(self.zero_values.iter().chain(self.one_values.iter())) {
            *i = *z;
        }
        bytes
    }

    /// Constructs a [`SigningKey`] from canonical bytes.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;

        if input.len() != bits * bytes * 2 + 1 {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let used = input[0] == 1;
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
    /// Pass an adapter that implements [`SplitRng`]: use [`Rand::new`] for infallible
    /// RNGs ([`rand::CryptoRng`]) or [`TryRand::new`] for fallible RNGs
    /// ([`rand::TryRng`] + [`rand::TryCryptoRng`]). For fallible RNGs, any error from the RNG
    /// is returned as [`LamportError::General`].
    pub fn split<R: SplitRng>(
        &self,
        threshold: usize,
        shares: usize,
        mut rng: R,
    ) -> LamportResult<Vec<SigningKeyShare<T>>> {
        let threshold_u8 = u8::try_from(threshold)
            .map_err(|_| LamportError::General("threshold out of range".into()))?;

        let zero_shares = Gf256::split_array(
            threshold,
            shares,
            self.zero_values.data.as_slice(),
            rng.adapter(),
        )?;
        let one_shares = Gf256::split_array(
            threshold,
            shares,
            self.one_values.data.as_slice(),
            rng.adapter(),
        )?;

        if let Some(e) = rng.take_error() {
            return Err(LamportError::General(e.to_string()));
        }

        let output = zero_shares
            .into_iter()
            .zip(one_shares)
            .map(|(zero_share, one_share)| {
                let identifier = zero_share[0];
                SigningKeyShare {
                    identifier,
                    zero_values: MultiVec {
                        data: zero_share[1..].to_vec(),
                        axes: self.zero_values.axes,
                    },
                    one_values: MultiVec {
                        data: one_share[1..].to_vec(),
                        axes: self.one_values.axes,
                    },
                    used: self.used,
                    threshold: threshold_u8,
                    algorithm: PhantomData,
                }
            })
            .collect::<Vec<_>>();

        Ok(output)
    }

    /// Reconstruct the signing key from the secret shares created by `split`
    pub fn combine(shares: &[SigningKeyShare<T>]) -> LamportResult<Self> {
        if shares.is_empty() {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        if shares.len() < shares[0].threshold as usize {
            return Err(LamportError::VsssError(vsss_rs::Error::SharingMinThreshold));
        }

        let zero_share_vecs: Vec<Vec<u8>> = shares
            .iter()
            .map(|s| {
                let mut v = vec![s.identifier];
                v.extend(&s.zero_values.data);
                v
            })
            .collect();
        let one_share_vecs: Vec<Vec<u8>> = shares
            .iter()
            .map(|s| {
                let mut v = vec![s.identifier];
                v.extend(&s.one_values.data);
                v
            })
            .collect();

        let zero_data = Gf256::combine_array(&zero_share_vecs)?;
        let one_data = Gf256::combine_array(&one_share_vecs)?;

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
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

impl<T: LamportDigest> Zeroize for SigningKeyShare<T> {
    fn zeroize(&mut self) {
        self.zero_values.zeroize();
        self.one_values.zeroize();
    }
}

impl<T: LamportDigest> SigningKeyShare<T> {
    /// Signs the data to create a [`SignatureShare`].
    pub fn sign<B: AsRef<[u8]>>(&mut self, data: B) -> LamportResult<SignatureShare<T>> {
        let mut s = SigningKey::<T> {
            zero_values: self.zero_values.clone(),
            one_values: self.one_values.clone(),
            used: self.used,
            algorithm: PhantomData,
        };
        let signature = s.sign(data)?;

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
        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;
        let mut bytes = vec![0u8; 3 + bytes * bits * 2];
        bytes[0] = self.identifier;
        bytes[1] = self.threshold;
        bytes[2] = self.used as u8;
        let iter = bytes[3..].iter_mut();
        for (i, z) in iter.zip(self.zero_values.iter().chain(self.one_values.iter())) {
            *i = *z;
        }
        bytes
    }

    /// Constructs a [`SigningKeyShare`] from canonical bytes.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        let bits = T::digest_size_in_bits();
        let bytes = bits / 8;

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
        let used = input[2] == 1;
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
