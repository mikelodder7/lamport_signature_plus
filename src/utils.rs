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
