/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::MultiVec;
#[cfg(feature = "serde")]
use std::borrow::Cow;

#[cfg(feature = "serde")]
pub(crate) trait CanonicalBytes {
    fn canonical_bytes(&self) -> Cow<'_, [u8]>;
}

#[cfg(feature = "serde")]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn serialize_canonical<S>(bytes: Cow<'_, [u8]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if serializer.is_human_readable() {
        serde::Serialize::serialize(&hex::encode(bytes.as_ref()), serializer)
    } else {
        serializer.serialize_bytes(bytes.as_ref())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn deserialize_canonical<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    if deserializer.is_human_readable() {
        let hex: String = serde::Deserialize::deserialize(deserializer)?;
        hex::decode(hex).map_err(serde::de::Error::custom)
    } else {
        serde::Deserialize::deserialize(deserializer)
    }
}

macro_rules! serde_impl {
    ($name:ident) => {
        #[cfg(feature = "serde")]
        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<T: LamportDigest> serde::Serialize for $name<T> {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                crate::utils::serialize_canonical(
                    crate::utils::CanonicalBytes::canonical_bytes(self),
                    s,
                )
            }
        }

        #[cfg(feature = "serde")]
        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<'de, T: LamportDigest> serde::Deserialize<'de> for $name<T> {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                let bytes = crate::utils::deserialize_canonical(d)?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    };
}

macro_rules! vec_impl {
    ($name:ident) => {
        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<T: LamportDigest> From<$name<T>> for Vec<u8> {
            fn from(value: $name<T>) -> Vec<u8> {
                Self::from(&value)
            }
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<T: LamportDigest> From<&$name<T>> for Vec<u8> {
            fn from(value: &$name<T>) -> Vec<u8> {
                value.to_bytes()
            }
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<T: LamportDigest> TryFrom<Vec<u8>> for $name<T> {
            type Error = LamportError;

            fn try_from(value: Vec<u8>) -> LamportResult<Self> {
                Self::try_from(value.as_slice())
            }
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<T: LamportDigest> TryFrom<&Vec<u8>> for $name<T> {
            type Error = LamportError;

            fn try_from(value: &Vec<u8>) -> LamportResult<Self> {
                Self::try_from(value.as_slice())
            }
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<T: LamportDigest> TryFrom<&[u8]> for $name<T> {
            type Error = LamportError;

            fn try_from(value: &[u8]) -> LamportResult<Self> {
                Self::from_bytes(value)
            }
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        impl<T: LamportDigest> TryFrom<Box<[u8]>> for $name<T> {
            type Error = LamportError;

            fn try_from(value: Box<[u8]>) -> LamportResult<Self> {
                Self::try_from(value.as_ref())
            }
        }
    };
}

pub(crate) fn encode_slices(header: &[u8], slices: &[&[u8]]) -> Vec<u8> {
    let capacity = header.len() + slices.iter().map(|slice| slice.len()).sum::<usize>();
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(header);
    for slice in slices {
        output.extend_from_slice(slice);
    }
    output
}

pub(crate) fn prefixed_share(identifier: u8, data: &[u8]) -> Vec<u8> {
    encode_slices(&[identifier], &[data])
}

pub(crate) fn separate_one_and_zero_values(
    input: &[u8],
    bytes: usize,
) -> (MultiVec<u8, 2>, MultiVec<u8, 2>) {
    let bits = bytes * 8;
    let split = bits * bytes;
    let zero_values = MultiVec {
        data: input[..split].to_vec(),
        axes: [bits, bytes],
    };
    let one_values = MultiVec {
        data: input[split..].to_vec(),
        axes: [bits, bytes],
    };
    (zero_values, one_values)
}
