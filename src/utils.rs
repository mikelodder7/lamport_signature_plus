/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::MultiVec;
use std::borrow::Cow;

pub(crate) trait CanonicalBytes {
    fn canonical_bytes(&self) -> Cow<'_, [u8]>;
}

macro_rules! serde_impl {
    ($name:ident) => {
        impl<T: LamportDigest> serde::Serialize for $name<T> {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                let bytes = crate::utils::CanonicalBytes::canonical_bytes(self);
                if s.is_human_readable() {
                    hex::encode(bytes.as_ref()).serialize(s)
                } else {
                    s.serialize_bytes(bytes.as_ref())
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
