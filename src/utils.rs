/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::MultiVec;

macro_rules! serde_impl {
    ($name:ident) => {
        impl<T: LamportDigest> serde::Serialize for $name<T> {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                let bytes = self.to_bytes();
                if s.is_human_readable() {
                    hex::encode(&bytes).serialize(s)
                } else {
                    s.serialize_bytes(&bytes)
                }
            }
        }

        impl<'de, T: LamportDigest> serde::Deserialize<'de> for $name<T> {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                let bytes = if d.is_human_readable() {
                    let hex_str = String::deserialize(d)?;
                    hex::decode(hex_str).map_err(serde::de::Error::custom)?
                } else {
                    Vec::<u8>::deserialize(d)?
                };
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! vec_impl {
    ($name:ident) => {
        impl<T: LamportDigest> From<$name<T>> for Vec<u8> {
            fn from(value: $name<T>) -> Vec<u8> {
                Self::from(&value)
            }
        }

        impl<T: LamportDigest> From<&$name<T>> for Vec<u8> {
            fn from(value: &$name<T>) -> Vec<u8> {
                value.to_bytes()
            }
        }

        impl<T: LamportDigest> TryFrom<Vec<u8>> for $name<T> {
            type Error = LamportError;

            fn try_from(value: Vec<u8>) -> LamportResult<Self> {
                Self::try_from(value.as_slice())
            }
        }

        impl<T: LamportDigest> TryFrom<&Vec<u8>> for $name<T> {
            type Error = LamportError;

            fn try_from(value: &Vec<u8>) -> LamportResult<Self> {
                Self::try_from(value.as_slice())
            }
        }

        impl<T: LamportDigest> TryFrom<&[u8]> for $name<T> {
            type Error = LamportError;

            fn try_from(value: &[u8]) -> LamportResult<Self> {
                Self::from_bytes(value)
            }
        }

        impl<T: LamportDigest> TryFrom<Box<[u8]>> for $name<T> {
            type Error = LamportError;

            fn try_from(value: Box<[u8]>) -> LamportResult<Self> {
                Self::try_from(value.as_ref())
            }
        }
    };
}

pub(crate) fn separate_one_and_zero_values(
    input: &[u8],
    bytes: usize,
) -> (MultiVec<u8, 2>, MultiVec<u8, 2>) {
    let bits = bytes * 8;
    let mut zero_values = MultiVec::fill([bits, bytes], 0);
    let mut one_values = MultiVec::fill([bits, bytes], 0);

    zero_values.data = input[..bits * bytes].to_vec();
    one_values.data = input[bits * bytes..].to_vec();
    (zero_values, one_values)
}

/// Wraps a rand 0.10 RNG so it implements rand 0.8's [`rand8::RngCore`] and [`rand8::CryptoRng`].
///
/// Use this when an API expects rand 0.8 (e.g. some dependencies) but you have a rand 0.10 RNG.
#[derive(Debug)]
pub struct Rand<R: rand::CryptoRng>(R);

impl<R: rand::CryptoRng> From<R> for Rand<R> {
    fn from(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: rand::CryptoRng> Rand<R> {
    /// Creates a new adapter that uses the given rand 0.10 RNG as the randomness source.
    pub fn new(rng: R) -> Self {
        Self(rng)
    }
}

impl<R: rand::CryptoRng> rand8::RngCore for Rand<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand8::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: rand::CryptoRng> rand8::CryptoRng for Rand<R> {}

/// Adapter that implements rand 0.8's [`rand8::RngCore`] for a rand 0.10 [`rand::TryRng`].
/// Errors from the inner RNG are captured and can be retrieved with [`TryRand::take_stored_error`].
#[derive(Debug)]
pub struct TryRand<R> {
    inner: R,
    error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl<R: rand::TryRng + rand::TryCryptoRng> From<R> for TryRand<R> {
    fn from(rng: R) -> Self {
        Self {
            inner: rng,
            error: None,
        }
    }
}

impl<R: rand::TryRng + rand::TryCryptoRng> TryRand<R> {
    /// Creates a new adapter that uses the given fallible RNG as the randomness source.
    pub fn new(rng: R) -> Self {
        Self {
            inner: rng,
            error: None,
        }
    }

    /// Returns the first error that occurred during random generation, if any.
    pub fn take_stored_error(&mut self) -> Option<Box<dyn std::error::Error + Send + Sync>> {
        self.error.take()
    }
}

impl<R: rand::TryRng + rand::TryCryptoRng> rand8::RngCore for TryRand<R>
where
    R::Error: std::error::Error + Send + Sync + 'static,
{
    fn next_u32(&mut self) -> u32 {
        match self.inner.try_next_u32() {
            Ok(x) => x,
            Err(e) => {
                self.error.get_or_insert(Box::new(e));
                0
            }
        }
    }

    fn next_u64(&mut self) -> u64 {
        match self.inner.try_next_u64() {
            Ok(x) => x,
            Err(e) => {
                self.error.get_or_insert(Box::new(e));
                0
            }
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.inner.try_fill_bytes(dest) {
            self.error.get_or_insert(Box::new(e));
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand8::Error> {
        if let Some(e) = &self.error {
            return Err(rand8::Error::new(std::io::Error::other(e.to_string())));
        }
        self.inner.try_fill_bytes(dest).map_err(|e| {
            self.error = Some(Box::new(e));
            rand8::Error::new(std::io::Error::other("RNG failed"))
        })
    }
}

impl<R: rand::TryRng + rand::TryCryptoRng> rand8::CryptoRng for TryRand<R> {}

/// Trait for RNG adapters that can be used with [`SigningKey::split`](crate::SigningKey::split).
///
/// Implemented for [`Rand`] (infallible RNG) and [`TryRand`] (fallible RNG).
/// Use [`Rand::new`](crate::Rand::new) for infallible RNGs or [`TryRand::new`](crate::TryRand::new) for fallible
/// RNGs, then pass the adapter to `split`.
pub trait SplitRng {
    /// The adapter type that implements rand 0.8's RNG traits.
    type Adapter: rand8::RngCore + rand8::CryptoRng;

    /// Returns a mutable reference to the underlying rand 0.8 adapter.
    fn adapter(&mut self) -> &mut Self::Adapter;

    /// If this adapter can fail (e.g. [`TryRand`]), returns the first error that occurred.
    fn take_error(&mut self) -> Option<Box<dyn std::error::Error + Send + Sync>>;
}

impl<R: rand::CryptoRng> SplitRng for Rand<R> {
    type Adapter = Self;

    fn adapter(&mut self) -> &mut Self::Adapter {
        self
    }

    fn take_error(&mut self) -> Option<Box<dyn std::error::Error + Send + Sync>> {
        None
    }
}

impl<R: rand::TryRng + rand::TryCryptoRng> SplitRng for TryRand<R>
where
    R::Error: std::error::Error + Send + Sync + 'static,
{
    type Adapter = Self;

    fn adapter(&mut self) -> &mut Self::Adapter {
        self
    }

    fn take_error(&mut self) -> Option<Box<dyn std::error::Error + Send + Sync>> {
        self.take_stored_error()
    }
}
