/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
#[cfg(feature = "serde")]
use crate::utils::CanonicalBytes;
use crate::utils::{encode_slices, separate_one_and_zero_values};
use crate::{
    LamportDigest, LamportError, LamportResult, MultiVec, Signature, SignatureShare, SigningKey,
    SigningKeyShare, VerifyingKey,
};
use std::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const MIN_DEPTH: u8 = 1;
const MAX_DEPTH: u8 = 3;
const STATE_FORMAT_VERSION: u8 = 1;
const LEAF_DOMAIN: u8 = 0;
const NODE_DOMAIN: u8 = 1;

fn validate_depth(depth: u8) -> LamportResult<usize> {
    if !(MIN_DEPTH..=MAX_DEPTH).contains(&depth) {
        return Err(LamportError::InvalidTreeDepth);
    }
    Ok(1usize << depth)
}

fn verifying_key_size<T: LamportDigest>() -> usize {
    T::digest_size_in_bits() * T::digest_size_in_bytes() * 2
}

fn signature_size<T: LamportDigest>() -> usize {
    T::digest_size_in_bits() * T::digest_size_in_bytes()
}

fn signing_key_material_size<T: LamportDigest>() -> usize {
    verifying_key_size::<T>()
}

fn signing_key_share_material_size<T: LamportDigest>() -> usize {
    verifying_key_size::<T>() + 2
}

fn signature_share_size<T: LamportDigest>() -> usize {
    signature_size::<T>() + 2
}

fn hash_leaf<T: LamportDigest>(key: &VerifyingKey<T>) -> Vec<u8> {
    let mut input = Vec::with_capacity(verifying_key_size::<T>() + 1);
    input.push(LEAF_DOMAIN);
    input.extend_from_slice(key.zero_values.as_ref());
    input.extend_from_slice(key.one_values.as_ref());
    T::digest(&input)
}

fn hash_node<T: LamportDigest>(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(left.len() + right.len() + 1);
    input.push(NODE_DOMAIN);
    input.extend_from_slice(left);
    input.extend_from_slice(right);
    T::digest(&input)
}

fn clone_verifying_key<T: LamportDigest>(key: &VerifyingKey<T>) -> VerifyingKey<T> {
    VerifyingKey {
        zero_values: key.zero_values.clone(),
        one_values: key.one_values.clone(),
        algorithm: PhantomData,
    }
}

fn public_keys<T: LamportDigest>(keys: &[SigningKey<T>]) -> Vec<VerifyingKey<T>> {
    keys.iter().map(VerifyingKey::from).collect()
}

fn tree_levels_from_leaves<T: LamportDigest>(leaves: Vec<Vec<u8>>) -> Vec<Vec<Vec<u8>>> {
    let mut levels = vec![leaves];
    while levels.last().map_or(0, Vec::len) > 1 {
        let previous = &levels[levels.len() - 1];
        let next = previous
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_node::<T>(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

fn signing_tree_levels<T: LamportDigest>(keys: &[SigningKey<T>]) -> Vec<Vec<Vec<u8>>> {
    let leaves = keys
        .iter()
        .map(|key| hash_leaf::<T>(&VerifyingKey::from(key)))
        .collect();
    tree_levels_from_leaves::<T>(leaves)
}

fn authentication_path(levels: &[Vec<Vec<u8>>], mut index: usize) -> Vec<Vec<u8>> {
    let mut path = Vec::with_capacity(levels.len().saturating_sub(1));
    for level in &levels[..levels.len() - 1] {
        path.push(level[index ^ 1].clone());
        index >>= 1;
    }
    path
}

fn proof_root<T: LamportDigest>(
    key: &VerifyingKey<T>,
    mut index: usize,
    authentication_path: &[Vec<u8>],
) -> LamportResult<Vec<u8>> {
    let bytes = T::digest_size_in_bytes();
    if authentication_path
        .iter()
        .any(|sibling| sibling.len() != bytes)
    {
        return Err(LamportError::InvalidMerkleProof);
    }

    let mut node = hash_leaf::<T>(key);
    for sibling in authentication_path {
        node = if index & 1 == 0 {
            hash_node::<T>(&node, sibling)
        } else {
            hash_node::<T>(sibling, &node)
        };
        index >>= 1;
    }
    Ok(node)
}

fn same_public_keys<T: LamportDigest>(left: &[VerifyingKey<T>], right: &[VerifyingKey<T>]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.zero_values == right.zero_values && left.one_values == right.one_values
        })
}

fn same_leaves(left: &[Vec<Vec<u8>>], right: &[Vec<Vec<u8>>]) -> bool {
    left.first() == right.first()
}

/// A stateful collection of Lamport one-time signing keys committed by a Merkle tree.
///
/// Supported depths are 1, 2, and 3, corresponding to 2, 4, and 8 signatures.
/// Each signing call consumes the compact key's authoritative next index. The
/// consumed leaf secret is then destroyed. The compact encoding retains the
/// leaf commitments needed to rebuild the derived Merkle cache.
#[derive(Debug, PartialEq, Eq)]
pub struct MtSigningKey<T: LamportDigest> {
    depth: u8,
    next_index: u8,
    keys: Vec<SigningKey<T>>,
    levels: Vec<Vec<Vec<u8>>>,
}

serde_impl!(MtSigningKey);
vec_impl!(MtSigningKey);

#[cfg(feature = "serde")]
impl<T: LamportDigest> CanonicalBytes for MtSigningKey<T> {
    fn canonical_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Owned(self.to_bytes())
    }
}

impl<T: LamportDigest> Zeroize for MtSigningKey<T> {
    fn zeroize(&mut self) {
        self.next_index.zeroize();
        self.keys.clear();
        self.levels.clear();
    }
}

impl<T: LamportDigest> Drop for MtSigningKey<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: LamportDigest> MtSigningKey<T> {
    /// Generate a key containing `2^depth` Lamport one-time keys.
    pub fn random(depth: u8, mut rng: impl rand_core::CryptoRng) -> LamportResult<Self> {
        let count = validate_depth(depth)?;
        let keys = (0..count)
            .map(|_| SigningKey::random(&mut rng))
            .collect::<Vec<_>>();
        let levels = signing_tree_levels::<T>(&keys);
        Ok(Self {
            depth,
            next_index: 0,
            keys,
            levels,
        })
    }

    /// Return the Merkle tree depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Return the total number of one-time signing keys.
    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    /// Return the next leaf index that will be consumed by [`sign`](Self::sign).
    pub fn next_index(&self) -> usize {
        usize::from(self.next_index)
    }

    /// Return the number of one-time keys that have not been used.
    pub fn remaining_signatures(&self) -> usize {
        self.keys.len()
    }

    /// Sign with the next leaf index and advance the authoritative counter.
    pub fn sign<B: AsRef<[u8]>>(&mut self, data: B) -> LamportResult<MtSignature<T>> {
        let index = self.next_index;
        if self.keys.is_empty() {
            return Err(LamportError::NoUnusedSigningKeys);
        }

        let path = authentication_path(&self.levels, usize::from(index));
        let mut key = self.keys.remove(0);
        let verifying_key = VerifyingKey::from(&key);
        self.next_index += 1;
        let signature = key.sign(data)?;

        Ok(MtSignature {
            depth: self.depth,
            index,
            verifying_key,
            authentication_path: path,
            signature,
        })
    }

    /// Split every unused one-time signing key using one threshold-sharing policy.
    pub fn split(
        &self,
        threshold: usize,
        shares: usize,
        mut rng: impl rand_core::CryptoRng,
    ) -> LamportResult<Vec<MtSigningKeyShare<T>>> {
        if self.keys.is_empty() {
            return Err(LamportError::NoUnusedSigningKeys);
        }
        let mut party_keys = (0..shares)
            .map(|_| Vec::with_capacity(self.keys.len()))
            .collect::<Vec<_>>();
        for key in &self.keys {
            let leaf_shares = key.split(threshold, shares, &mut rng)?;
            for (party, share) in party_keys.iter_mut().zip(leaf_shares) {
                party.push(share);
            }
        }

        let public_keys = public_keys(&self.keys);
        Ok(party_keys
            .into_iter()
            .map(|keys| MtSigningKeyShare {
                depth: self.depth,
                next_index: self.next_index,
                keys,
                public_keys: public_keys.iter().map(clone_verifying_key).collect(),
                levels: self.levels.clone(),
            })
            .collect())
    }

    /// Reconstruct a Merkle signing key from threshold shares.
    pub fn combine(shares: &[MtSigningKeyShare<T>]) -> LamportResult<Self> {
        let first = shares.first().ok_or(LamportError::InvalidPrivateKeyBytes)?;
        let count =
            validate_depth(first.depth).map_err(|_| LamportError::InvalidPrivateKeyBytes)?;
        if usize::from(first.next_index) > count
            || first.keys.len() != count - usize::from(first.next_index)
            || first.public_keys.len() != first.keys.len()
            || first.levels.first().map_or(0, Vec::len) != count
            || shares.iter().any(|share| {
                share.depth != first.depth
                    || share.next_index != first.next_index
                    || share.keys.len() != first.keys.len()
                    || share.public_keys.len() != share.keys.len()
                    || share.levels.first().map_or(0, Vec::len) != count
                    || !same_public_keys(&share.public_keys, &first.public_keys)
                    || !same_leaves(&share.levels, &first.levels)
            })
        {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }

        let mut keys = Vec::with_capacity(first.keys.len());
        for offset in 0..first.keys.len() {
            let leaf_shares = shares
                .iter()
                .map(|share| &share.keys[offset])
                .collect::<Vec<_>>();
            let key = SigningKey::combine_refs(&leaf_shares)?;
            let public_key = VerifyingKey::from(&key);
            if public_key.zero_values != first.public_keys[offset].zero_values
                || public_key.one_values != first.public_keys[offset].one_values
            {
                return Err(LamportError::InvalidPrivateKeyBytes);
            }
            keys.push(key);
        }
        Ok(Self {
            depth: first.depth,
            next_index: first.next_index,
            keys,
            levels: first.levels.clone(),
        })
    }

    /// Encode the tree state and remaining private key material.
    pub fn to_bytes(&self) -> Vec<u8> {
        let leaves = self.levels.first().map_or(&[][..], Vec::as_slice);
        let mut output = Vec::with_capacity(
            3 + leaves.iter().map(Vec::len).sum::<usize>()
                + self.keys.len() * signing_key_material_size::<T>(),
        );
        output.extend_from_slice(&[STATE_FORMAT_VERSION, self.depth, self.next_index]);
        for leaf in leaves {
            output.extend_from_slice(leaf);
        }
        for key in &self.keys {
            output.extend_from_slice(key.zero_values.as_ref());
            output.extend_from_slice(key.one_values.as_ref());
        }
        output
    }

    /// Decode a Merkle signing key and reconstruct its derived tree cache.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        if input.first() != Some(&STATE_FORMAT_VERSION) {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let depth = *input.get(1).ok_or(LamportError::InvalidPrivateKeyBytes)?;
        let count = validate_depth(depth).map_err(|_| LamportError::InvalidPrivateKeyBytes)?;
        let next_index = *input.get(2).ok_or(LamportError::InvalidPrivateKeyBytes)?;
        let next = usize::from(next_index);
        let remaining = count.saturating_sub(next);
        let hash_size = T::digest_size_in_bytes();
        let leaves_size = count * hash_size;
        let key_size = signing_key_material_size::<T>();
        if next > count || input.len() != 3 + leaves_size + remaining * key_size {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let leaves = input[3..3 + leaves_size]
            .chunks_exact(hash_size)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let levels = tree_levels_from_leaves::<T>(leaves);
        let keys = input[3 + leaves_size..]
            .chunks_exact(key_size)
            .map(|bytes| {
                let (zero_values, one_values) =
                    separate_one_and_zero_values(bytes, T::digest_size_in_bytes());
                SigningKey {
                    zero_values,
                    one_values,
                    used: false,
                    algorithm: PhantomData,
                }
            })
            .collect::<Vec<_>>();
        if keys.iter().enumerate().any(|(offset, key)| {
            hash_leaf::<T>(&VerifyingKey::from(key)) != levels[0][next + offset]
        }) {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        Ok(Self {
            depth,
            next_index,
            keys,
            levels,
        })
    }
}

/// A compact Merkle root that verifies up to eight Lamport one-time signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct MtVerifyingKey<T: LamportDigest> {
    depth: u8,
    root: Vec<u8>,
    algorithm: PhantomData<T>,
}

serde_impl!(MtVerifyingKey);
vec_impl!(MtVerifyingKey);

#[cfg(feature = "serde")]
impl<T: LamportDigest> CanonicalBytes for MtVerifyingKey<T> {
    fn canonical_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Owned(self.to_bytes())
    }
}

impl<T: LamportDigest> MtVerifyingKey<T> {
    /// Return the Merkle tree depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Return the Merkle root bytes.
    pub fn root(&self) -> &[u8] {
        &self.root
    }

    /// Verify both the Lamport signature and its public-key inclusion proof.
    pub fn verify<B: AsRef<[u8]>>(&self, signature: &MtSignature<T>, data: B) -> LamportResult<()> {
        if signature.depth != self.depth
            || signature.authentication_path.len() != usize::from(self.depth)
            || usize::from(signature.index) >= (1usize << self.depth)
        {
            return Err(LamportError::InvalidMerkleProof);
        }
        signature.verifying_key.verify(&signature.signature, data)?;
        let candidate = proof_root::<T>(
            &signature.verifying_key,
            usize::from(signature.index),
            &signature.authentication_path,
        )?;
        if bool::from(candidate.ct_eq(&self.root)) {
            Ok(())
        } else {
            Err(LamportError::InvalidMerkleProof)
        }
    }

    /// Encode the tree depth and Merkle root.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_slices(&[self.depth], &[&self.root])
    }

    /// Decode a Merkle verifying key.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        let depth = *input.first().ok_or(LamportError::InvalidPrivateKeyBytes)?;
        validate_depth(depth).map_err(|_| LamportError::InvalidPrivateKeyBytes)?;
        if input.len() != T::digest_size_in_bytes() + 1 {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        Ok(Self {
            depth,
            root: input[1..].to_vec(),
            algorithm: PhantomData,
        })
    }
}

impl<T: LamportDigest> From<&MtSigningKey<T>> for MtVerifyingKey<T> {
    fn from(value: &MtSigningKey<T>) -> Self {
        Self {
            depth: value.depth,
            root: value.levels[value.levels.len() - 1][0].clone(),
            algorithm: PhantomData,
        }
    }
}

/// A Lamport signature bundled with its leaf public key and Merkle authentication path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct MtSignature<T: LamportDigest> {
    depth: u8,
    index: u8,
    verifying_key: VerifyingKey<T>,
    authentication_path: Vec<Vec<u8>>,
    signature: Signature<T>,
}

serde_impl!(MtSignature);
vec_impl!(MtSignature);

#[cfg(feature = "serde")]
impl<T: LamportDigest> CanonicalBytes for MtSignature<T> {
    fn canonical_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Owned(self.to_bytes())
    }
}

impl<T: LamportDigest> MtSignature<T> {
    /// Return the consumed one-time key index.
    pub fn index(&self) -> usize {
        usize::from(self.index)
    }

    /// Return the Merkle tree depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Return the Lamport leaf verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey<T> {
        &self.verifying_key
    }

    /// Return the bottom-up Merkle authentication path.
    pub fn authentication_path(&self) -> &[Vec<u8>] {
        &self.authentication_path
    }

    /// Return the underlying Lamport signature.
    pub fn lamport_signature(&self) -> &Signature<T> {
        &self.signature
    }

    /// Combine threshold signature shares for the same tree leaf.
    pub fn combine(shares: &[MtSignatureShare<T>]) -> LamportResult<Self> {
        let first = shares.first().ok_or(LamportError::InvalidSignatureBytes)?;
        if shares.iter().any(|share| {
            share.depth != first.depth
                || share.index != first.index
                || share.verifying_key.to_bytes() != first.verifying_key.to_bytes()
                || share.authentication_path != first.authentication_path
        }) {
            return Err(LamportError::InvalidSignatureBytes);
        }
        let leaf_shares = shares
            .iter()
            .map(|share| &share.signature)
            .collect::<Vec<_>>();
        Ok(Self {
            depth: first.depth,
            index: first.index,
            verifying_key: clone_verifying_key(&first.verifying_key),
            authentication_path: first.authentication_path.clone(),
            signature: Signature::combine_refs(&leaf_shares)?,
        })
    }

    /// Encode the depth, index, leaf key, authentication path, and Lamport signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let key = self.verifying_key.to_bytes();
        let signature = self.signature.to_bytes();
        let path = self
            .authentication_path
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut slices = Vec::with_capacity(path.len() + 2);
        slices.push(key.as_slice());
        slices.extend(path);
        slices.push(signature.as_slice());
        encode_slices(&[self.depth, self.index], &slices)
    }

    /// Decode a Merkle-tree Lamport signature.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        if input.len() < 2 {
            return Err(LamportError::InvalidSignatureBytes);
        }
        let depth = input[0];
        let count = validate_depth(depth).map_err(|_| LamportError::InvalidSignatureBytes)?;
        let index = input[1];
        let key_size = verifying_key_size::<T>();
        let hash_size = T::digest_size_in_bytes();
        let signature_size = signature_size::<T>();
        if usize::from(index) >= count
            || input.len() != 2 + key_size + usize::from(depth) * hash_size + signature_size
        {
            return Err(LamportError::InvalidSignatureBytes);
        }
        let mut offset = 2;
        let (zero_values, one_values) = separate_one_and_zero_values(
            &input[offset..offset + key_size],
            T::digest_size_in_bytes(),
        );
        let verifying_key = VerifyingKey {
            zero_values,
            one_values,
            algorithm: PhantomData,
        };
        offset += key_size;
        let authentication_path = input[offset..offset + usize::from(depth) * hash_size]
            .chunks_exact(hash_size)
            .map(<[u8]>::to_vec)
            .collect();
        offset += usize::from(depth) * hash_size;
        let signature = Signature {
            data: MultiVec {
                data: input[offset..].to_vec(),
                axes: [T::digest_size_in_bits(), hash_size],
            },
            algorithm: PhantomData,
        };
        Ok(Self {
            depth,
            index,
            verifying_key,
            authentication_path,
            signature,
        })
    }
}

/// One participant's threshold shares for the unused MT-Lamport leaves.
#[derive(Debug, PartialEq, Eq)]
pub struct MtSigningKeyShare<T: LamportDigest> {
    depth: u8,
    next_index: u8,
    keys: Vec<SigningKeyShare<T>>,
    public_keys: Vec<VerifyingKey<T>>,
    levels: Vec<Vec<Vec<u8>>>,
}

serde_impl!(MtSigningKeyShare);
vec_impl!(MtSigningKeyShare);

#[cfg(feature = "serde")]
impl<T: LamportDigest> CanonicalBytes for MtSigningKeyShare<T> {
    fn canonical_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Owned(self.to_bytes())
    }
}

impl<T: LamportDigest> Zeroize for MtSigningKeyShare<T> {
    fn zeroize(&mut self) {
        self.next_index.zeroize();
        self.keys.clear();
        self.levels.clear();
    }
}

impl<T: LamportDigest> Drop for MtSigningKeyShare<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: LamportDigest> MtSigningKeyShare<T> {
    /// Return the Merkle tree depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Return the total number of one-time key shares.
    pub fn capacity(&self) -> usize {
        1usize << self.depth
    }

    /// Return the next leaf index that will be consumed by [`sign`](Self::sign).
    pub fn next_index(&self) -> usize {
        usize::from(self.next_index)
    }

    /// Return the number of one-time key shares that have not been used.
    pub fn remaining_signatures(&self) -> usize {
        self.keys.len()
    }

    /// Produce a signature share at the next index and advance the counter.
    pub fn sign<B: AsRef<[u8]>>(&mut self, data: B) -> LamportResult<MtSignatureShare<T>> {
        let index = self.next_index;
        if self.keys.is_empty() {
            return Err(LamportError::NoUnusedSigningKeys);
        }
        let mut key = self.keys.remove(0);
        let verifying_key = self.public_keys.remove(0);
        self.next_index += 1;
        let signature = key.sign(data)?;
        Ok(MtSignatureShare {
            depth: self.depth,
            index,
            verifying_key,
            authentication_path: authentication_path(&self.levels, usize::from(index)),
            signature,
        })
    }

    /// Encode the tree state and remaining private and public leaf shares.
    pub fn to_bytes(&self) -> Vec<u8> {
        let leaves = self.levels.first().map_or(&[][..], Vec::as_slice);
        let pair_size = signing_key_share_material_size::<T>() + verifying_key_size::<T>();
        let mut output = Vec::with_capacity(
            3 + leaves.iter().map(Vec::len).sum::<usize>() + self.keys.len() * pair_size,
        );
        output.extend_from_slice(&[STATE_FORMAT_VERSION, self.depth, self.next_index]);
        for leaf in leaves {
            output.extend_from_slice(leaf);
        }
        for (key, public_key) in self.keys.iter().zip(&self.public_keys) {
            output.extend_from_slice(&[key.identifier, key.threshold]);
            output.extend_from_slice(key.zero_values.as_ref());
            output.extend_from_slice(key.one_values.as_ref());
            output.extend_from_slice(public_key.zero_values.as_ref());
            output.extend_from_slice(public_key.one_values.as_ref());
        }
        output
    }

    /// Decode a participant's complete MT-Lamport signing-key share.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        if input.first() != Some(&STATE_FORMAT_VERSION) {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        let depth = *input.get(1).ok_or(LamportError::InvalidPrivateKeyBytes)?;
        let count = validate_depth(depth).map_err(|_| LamportError::InvalidPrivateKeyBytes)?;
        let next_index = *input.get(2).ok_or(LamportError::InvalidPrivateKeyBytes)?;
        let next = usize::from(next_index);
        let remaining = count.saturating_sub(next);
        let hash_size = T::digest_size_in_bytes();
        let leaves_size = count * hash_size;
        let share_size = signing_key_share_material_size::<T>();
        let public_size = verifying_key_size::<T>();
        let pair_size = share_size + public_size;
        if next > count || input.len() != 3 + leaves_size + remaining * pair_size {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }

        let leaves = input[3..3 + leaves_size]
            .chunks_exact(hash_size)
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let levels = tree_levels_from_leaves::<T>(leaves);
        let mut keys = Vec::with_capacity(remaining);
        let mut public_keys = Vec::with_capacity(remaining);
        for pair in input[3 + leaves_size..].chunks_exact(pair_size) {
            let share = &pair[..share_size];
            if share[0] == 0 || share[1] < 2 {
                return Err(LamportError::InvalidPrivateKeyBytes);
            }
            let (zero_values, one_values) =
                separate_one_and_zero_values(&share[2..], T::digest_size_in_bytes());
            keys.push(SigningKeyShare {
                identifier: share[0],
                threshold: share[1],
                zero_values,
                one_values,
                used: false,
                algorithm: PhantomData,
            });
            let (zero_values, one_values) =
                separate_one_and_zero_values(&pair[share_size..], T::digest_size_in_bytes());
            public_keys.push(VerifyingKey {
                zero_values,
                one_values,
                algorithm: PhantomData,
            });
        }
        let inconsistent_metadata = keys.first().is_some_and(|first| {
            keys.iter()
                .any(|key| key.identifier != first.identifier || key.threshold != first.threshold)
        });
        if inconsistent_metadata {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        if public_keys
            .iter()
            .enumerate()
            .any(|(offset, key)| hash_leaf::<T>(key) != levels[0][next + offset])
        {
            return Err(LamportError::InvalidPrivateKeyBytes);
        }
        Ok(Self {
            depth,
            next_index,
            keys,
            public_keys,
            levels,
        })
    }
}

impl<T: LamportDigest> From<&MtSigningKeyShare<T>> for MtVerifyingKey<T> {
    fn from(value: &MtSigningKeyShare<T>) -> Self {
        Self {
            depth: value.depth,
            root: value.levels[value.levels.len() - 1][0].clone(),
            algorithm: PhantomData,
        }
    }
}

/// A participant's threshold signature share with its Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct MtSignatureShare<T: LamportDigest> {
    depth: u8,
    index: u8,
    verifying_key: VerifyingKey<T>,
    authentication_path: Vec<Vec<u8>>,
    signature: SignatureShare<T>,
}

serde_impl!(MtSignatureShare);
vec_impl!(MtSignatureShare);

#[cfg(feature = "serde")]
impl<T: LamportDigest> CanonicalBytes for MtSignatureShare<T> {
    fn canonical_bytes(&self) -> std::borrow::Cow<'_, [u8]> {
        std::borrow::Cow::Owned(self.to_bytes())
    }
}

impl<T: LamportDigest> MtSignatureShare<T> {
    /// Return the leaf index signed by this share.
    pub fn index(&self) -> usize {
        usize::from(self.index)
    }

    /// Return the Merkle tree depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Encode this signature share and its Merkle inclusion proof.
    pub fn to_bytes(&self) -> Vec<u8> {
        let key = self.verifying_key.to_bytes();
        let signature = self.signature.to_bytes();
        let path = self
            .authentication_path
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let mut slices = Vec::with_capacity(path.len() + 2);
        slices.push(key.as_slice());
        slices.extend(path);
        slices.push(signature.as_slice());
        encode_slices(&[self.depth, self.index], &slices)
    }

    /// Decode a threshold signature share and its Merkle inclusion proof.
    pub fn from_bytes<B: AsRef<[u8]>>(input: B) -> LamportResult<Self> {
        let input = input.as_ref();
        if input.len() < 2 {
            return Err(LamportError::InvalidSignatureBytes);
        }
        let depth = input[0];
        let count = validate_depth(depth).map_err(|_| LamportError::InvalidSignatureBytes)?;
        let index = input[1];
        let key_size = verifying_key_size::<T>();
        let hash_size = T::digest_size_in_bytes();
        let share_size = signature_share_size::<T>();
        if usize::from(index) >= count
            || input.len() != 2 + key_size + usize::from(depth) * hash_size + share_size
        {
            return Err(LamportError::InvalidSignatureBytes);
        }
        let mut offset = 2;
        let (zero_values, one_values) = separate_one_and_zero_values(
            &input[offset..offset + key_size],
            T::digest_size_in_bytes(),
        );
        let verifying_key = VerifyingKey {
            zero_values,
            one_values,
            algorithm: PhantomData,
        };
        offset += key_size;
        let authentication_path = input[offset..offset + usize::from(depth) * hash_size]
            .chunks_exact(hash_size)
            .map(<[u8]>::to_vec)
            .collect();
        offset += usize::from(depth) * hash_size;
        let signature = SignatureShare::from_bytes(&input[offset..])?;
        Ok(Self {
            depth,
            index,
            verifying_key,
            authentication_path,
            signature,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{LamportFixedDigest, generate_mt_keys};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use sha2::Sha256;

    type Digest = LamportFixedDigest<Sha256>;

    #[test]
    #[cfg(feature = "serde")]
    fn all_supported_depths_sign_serialize_verify_and_exhaust() {
        for depth in MIN_DEPTH..=MAX_DEPTH {
            let mut rng = ChaCha8Rng::from_seed([depth; 32]);
            let (mut key, verifying_key) =
                generate_mt_keys::<Digest, _>(depth, &mut rng).expect("valid depth");
            let count = 1usize << depth;
            assert_eq!(key.depth(), depth);
            assert_eq!(key.capacity(), count);
            assert_eq!(key.next_index(), 0);
            assert_eq!(key.remaining_signatures(), count);
            assert_eq!(verifying_key.depth(), depth);
            assert_eq!(verifying_key.root().len(), Digest::digest_size_in_bytes());

            let verifying_bytes = verifying_key.to_bytes();
            assert_eq!(
                MtVerifyingKey::<Digest>::from_bytes(&verifying_bytes)
                    .expect("verifying key round trip")
                    .to_bytes(),
                verifying_bytes
            );
            let verifying_json =
                serde_json::to_string(&verifying_key).expect("serialize verifying key");
            let decoded_verifying_key: MtVerifyingKey<Digest> =
                serde_json::from_str(&verifying_json).expect("deserialize verifying key");
            assert_eq!(decoded_verifying_key.to_bytes(), verifying_key.to_bytes());

            for index in 0..count {
                let state = key.to_bytes();
                key = MtSigningKey::from_bytes(&state).expect("canonical state round trip");
                let json = serde_json::to_string(&key).expect("serialize signing key");
                key = serde_json::from_str(&json).expect("deserialize signing key");

                let message = [depth, u8::try_from(index).expect("small index")];
                let signature = key.sign(message).expect("unused leaf");
                assert_eq!(signature.index(), index);
                assert_eq!(signature.depth(), depth);
                assert_eq!(signature.authentication_path().len(), usize::from(depth));
                assert_eq!(
                    signature.verifying_key().to_bytes().len(),
                    verifying_key_size::<Digest>()
                );
                assert_eq!(
                    signature.lamport_signature().to_bytes().len(),
                    signature_size::<Digest>()
                );
                assert_eq!(key.next_index(), index + 1);

                let signature_bytes = signature.to_bytes();
                let decoded_signature = MtSignature::<Digest>::from_bytes(&signature_bytes)
                    .expect("signature round trip");
                assert_eq!(decoded_signature.to_bytes(), signature.to_bytes());
                let signature_json =
                    serde_json::to_string(&signature).expect("serialize signature");
                let decoded_signature: MtSignature<Digest> =
                    serde_json::from_str(&signature_json).expect("deserialize signature");
                assert_eq!(decoded_signature.to_bytes(), signature.to_bytes());

                verifying_key
                    .verify(&signature, message)
                    .expect("valid signature and proof");
                assert!(verifying_key.verify(&signature, b"wrong").is_err());
            }
            assert_eq!(key.remaining_signatures(), 0);
            let exhausted = key.to_bytes();
            key = MtSigningKey::from_bytes(exhausted).expect("exhausted state round trip");
            let exhausted_json = serde_json::to_string(&key).expect("serialize exhausted key");
            key = serde_json::from_str(&exhausted_json).expect("deserialize exhausted key");
            assert!(matches!(
                key.sign(b"exhausted"),
                Err(LamportError::NoUnusedSigningKeys)
            ));
        }
    }

    #[test]
    fn automatic_index_and_proof_are_bound_together() {
        let mut rng = ChaCha8Rng::from_seed([20; 32]);
        let (mut key, verifying_key) =
            generate_mt_keys::<Digest, _>(2, &mut rng).expect("valid depth");
        let signature = key.sign(b"message").expect("unused leaf");
        assert_eq!(signature.index(), 0);
        assert_eq!(key.next_index(), 1);

        let mut encoded = signature.to_bytes();
        encoded[1] = 1;
        let changed_index = MtSignature::<Digest>::from_bytes(encoded).expect("valid encoding");
        assert!(matches!(
            verifying_key.verify(&changed_index, b"message"),
            Err(LamportError::InvalidMerkleProof)
        ));

        let mut encoded = signature.to_bytes();
        encoded[2 + verifying_key_size::<Digest>()] ^= 1;
        let changed_path = MtSignature::<Digest>::from_bytes(encoded).expect("valid encoding");
        assert!(matches!(
            verifying_key.verify(&changed_path, b"message"),
            Err(LamportError::InvalidMerkleProof)
        ));

        let mut malformed_path = signature.clone();
        malformed_path.authentication_path[0].pop();
        assert!(matches!(
            verifying_key.verify(&malformed_path, b"message"),
            Err(LamportError::InvalidMerkleProof)
        ));

        let mut wrong_depth = signature;
        wrong_depth.depth = 1;
        assert!(matches!(
            verifying_key.verify(&wrong_depth, b"message"),
            Err(LamportError::InvalidMerkleProof)
        ));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn encodings_round_trip_and_reject_bad_depths() {
        let mut rng = ChaCha8Rng::from_seed([21; 32]);
        assert!(matches!(
            MtSigningKey::<Digest>::random(0, &mut rng),
            Err(LamportError::InvalidTreeDepth)
        ));
        assert!(matches!(
            generate_mt_keys::<Digest, _>(0, &mut rng),
            Err(LamportError::InvalidTreeDepth)
        ));
        assert!(matches!(
            MtSigningKey::<Digest>::random(4, &mut rng),
            Err(LamportError::InvalidTreeDepth)
        ));

        let (mut key, verifying_key) =
            generate_mt_keys::<Digest, _>(2, &mut rng).expect("valid depth");
        let signature = key.sign(b"message").expect("unused leaf");
        let key_bytes = key.to_bytes();
        let verifying_bytes = verifying_key.to_bytes();
        let signature_bytes = signature.to_bytes();
        assert_eq!(
            MtSigningKey::<Digest>::from_bytes(&key_bytes)
                .expect("private key round trip")
                .to_bytes(),
            key_bytes
        );
        assert_eq!(
            MtVerifyingKey::<Digest>::from_bytes(&verifying_bytes)
                .expect("verifying key round trip")
                .to_bytes(),
            verifying_bytes
        );
        let restored =
            MtSignature::<Digest>::from_bytes(&signature_bytes).expect("signature round trip");
        verifying_key
            .verify(&restored, b"message")
            .expect("restored signature verifies");

        let json = serde_json::to_string(&signature).expect("serialize signature");
        let decoded: MtSignature<Digest> =
            serde_json::from_str(&json).expect("deserialize signature");
        assert_eq!(decoded.to_bytes(), signature_bytes);

        let mut invalid_version = key_bytes.clone();
        invalid_version[0] = STATE_FORMAT_VERSION + 1;
        assert!(matches!(
            MtSigningKey::<Digest>::from_bytes(invalid_version),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        assert!(MtSigningKey::<Digest>::from_bytes([STATE_FORMAT_VERSION]).is_err());
        assert!(MtSigningKey::<Digest>::from_bytes([STATE_FORMAT_VERSION, 0]).is_err());
        assert!(MtSigningKey::<Digest>::from_bytes([STATE_FORMAT_VERSION, 1]).is_err());

        let mut invalid_secret = key_bytes.clone();
        *invalid_secret
            .last_mut()
            .expect("remaining secret material") ^= 1;
        assert!(matches!(
            MtSigningKey::<Digest>::from_bytes(invalid_secret),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));

        let mut invalid_index = key_bytes;
        invalid_index[2] = 5;
        assert!(matches!(
            MtSigningKey::<Digest>::from_bytes(invalid_index),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
    }

    #[test]
    fn compact_state_reload_preserves_the_next_index() {
        let mut rng = ChaCha8Rng::from_seed([23; 32]);
        let (mut key, verifying_key) =
            generate_mt_keys::<Digest, _>(2, &mut rng).expect("valid depth");
        let initial_size = key.to_bytes().len();

        for index in 0usize..4 {
            let persisted = key.to_bytes();
            assert_eq!(
                persisted.len(),
                initial_size - index * signing_key_material_size::<Digest>()
            );
            let mut reloaded =
                MtSigningKey::<Digest>::from_bytes(&persisted).expect("reload compact state");
            assert_eq!(reloaded.next_index(), index);
            let message = u8::try_from(index).expect("small index").to_be_bytes();
            let cached_signature = key.sign(message).expect("cached signing");
            let rebuilt_signature = reloaded.sign(message).expect("reloaded signing");
            assert_eq!(cached_signature.to_bytes(), rebuilt_signature.to_bytes());
            verifying_key
                .verify(&cached_signature, message)
                .expect("signature verifies");
        }

        let persisted = key.to_bytes();
        let mut exhausted =
            MtSigningKey::<Digest>::from_bytes(persisted).expect("reload exhausted key");
        assert_eq!(exhausted.next_index(), exhausted.capacity());
        assert_eq!(
            exhausted.to_bytes().len(),
            3 + exhausted.capacity() * Digest::digest_size_in_bytes()
        );
        assert!(matches!(
            exhausted.sign(b"exhausted"),
            Err(LamportError::NoUnusedSigningKeys)
        ));
    }

    #[test]
    fn threshold_signatures_work_across_multiple_indices() {
        let mut rng = ChaCha8Rng::from_seed([22; 32]);
        let (key, verifying_key) = generate_mt_keys::<Digest, _>(2, &mut rng).expect("valid depth");
        let mut shares = key.split(2, 3, &mut rng).expect("split tree keys");
        let initial_share_size = shares[0].to_bytes().len();
        let consumed_share_size =
            signing_key_share_material_size::<Digest>() + verifying_key_size::<Digest>();

        for index in 0..2 {
            let partials = shares
                .iter_mut()
                .map(|share| share.sign(b"threshold"))
                .collect::<LamportResult<Vec<_>>>()
                .expect("produce shares");
            let signature = MtSignature::combine(&partials[..2]).expect("combine shares");
            assert_eq!(signature.index(), index);
            verifying_key
                .verify(&signature, b"threshold")
                .expect("threshold signature verifies");

            let partial_bytes = partials[0].to_bytes();
            assert_eq!(
                MtSignatureShare::<Digest>::from_bytes(&partial_bytes)
                    .expect("signature share round trip")
                    .to_bytes(),
                partial_bytes
            );
            assert!(shares.iter().all(|share| share.next_index() == index + 1));
            assert_eq!(
                shares[0].to_bytes().len(),
                initial_share_size - (index + 1) * consumed_share_size
            );
        }

        let encoded = shares[0].to_bytes();
        let decoded =
            MtSigningKeyShare::<Digest>::from_bytes(&encoded).expect("key share round trip");
        assert_eq!(decoded.next_index(), 2);
        assert_eq!(decoded.to_bytes(), encoded);
        let mut invalid_public_key = encoded;
        *invalid_public_key.last_mut().expect("remaining public key") ^= 1;
        assert!(matches!(
            MtSigningKeyShare::<Digest>::from_bytes(invalid_public_key),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
        let mut combined = MtSigningKey::combine(&shares[..2]).expect("combine tree shares");
        assert_eq!(
            MtVerifyingKey::from(&combined).to_bytes(),
            verifying_key.to_bytes()
        );
        let combined_signature = combined
            .sign(b"combined key")
            .expect("sign with reconstructed remaining key");
        assert_eq!(combined_signature.index(), 2);
        verifying_key
            .verify(&combined_signature, b"combined key")
            .expect("reconstructed tree key verifies");

        shares[0]
            .sign(b"diverge")
            .expect("advance only one participant");
        assert!(matches!(
            MtSigningKey::combine(&shares[..2]),
            Err(LamportError::InvalidPrivateKeyBytes)
        ));
    }

    #[test]
    #[cfg(feature = "serde")]
    fn threshold_signatures_work_at_all_supported_depths_and_exhaust() {
        for depth in MIN_DEPTH..=MAX_DEPTH {
            let mut rng = ChaCha8Rng::from_seed([30 + depth; 32]);
            let (key, verifying_key) =
                generate_mt_keys::<Digest, _>(depth, &mut rng).expect("valid depth");
            let mut shares = key.split(2, 3, &mut rng).expect("split tree keys");
            let count = 1usize << depth;

            for share in &shares {
                assert_eq!(share.depth(), depth);
                assert_eq!(share.capacity(), count);
                assert_eq!(share.next_index(), 0);
                assert_eq!(share.remaining_signatures(), count);
                assert_eq!(
                    MtVerifyingKey::from(share).to_bytes(),
                    verifying_key.to_bytes()
                );
            }

            for index in 0..count {
                for share in &mut shares {
                    let encoded = share.to_bytes();
                    *share = MtSigningKeyShare::from_bytes(encoded)
                        .expect("canonical key-share round trip");
                }
                let json = serde_json::to_string(&shares[0]).expect("serialize key share");
                shares[0] = serde_json::from_str(&json).expect("deserialize key share");

                let message = [depth, u8::try_from(index).expect("small index")];
                let partials = shares
                    .iter_mut()
                    .map(|share| share.sign(message))
                    .collect::<LamportResult<Vec<_>>>()
                    .expect("produce threshold signature shares");
                for partial in &partials {
                    assert_eq!(partial.depth(), depth);
                    assert_eq!(partial.index(), index);
                    let encoded = partial.to_bytes();
                    assert_eq!(
                        MtSignatureShare::<Digest>::from_bytes(&encoded)
                            .expect("canonical signature-share round trip")
                            .to_bytes(),
                        partial.to_bytes()
                    );
                    let json = serde_json::to_string(partial).expect("serialize signature share");
                    let decoded: MtSignatureShare<Digest> =
                        serde_json::from_str(&json).expect("deserialize signature share");
                    assert_eq!(decoded.to_bytes(), partial.to_bytes());
                }

                let signature = MtSignature::combine(&partials[..2]).expect("combine shares");
                assert_eq!(signature.index(), index);
                verifying_key
                    .verify(&signature, message)
                    .expect("threshold signature verifies");
                assert!(verifying_key.verify(&signature, b"wrong").is_err());
            }

            for share in &mut shares {
                assert_eq!(share.remaining_signatures(), 0);
                assert!(matches!(
                    share.sign(b"exhausted"),
                    Err(LamportError::NoUnusedSigningKeys)
                ));
            }
        }
    }

    #[test]
    fn exhausted_threshold_state_contains_only_leaf_commitments() {
        let mut rng = ChaCha8Rng::from_seed([24; 32]);
        let (key, _) = generate_mt_keys::<Digest, _>(1, &mut rng).expect("valid depth");
        let mut shares = key.split(2, 2, &mut rng).expect("split tree keys");

        for index in 0..2 {
            for share in &mut shares {
                let partial = share.sign([u8::try_from(index).expect("small index")]);
                assert!(partial.is_ok());
            }
        }

        let encoded = shares[0].to_bytes();
        assert_eq!(encoded.len(), 3 + 2 * Digest::digest_size_in_bytes());
        let decoded =
            MtSigningKeyShare::<Digest>::from_bytes(encoded).expect("decode exhausted share");
        assert_eq!(decoded.capacity(), 2);
        assert_eq!(decoded.remaining_signatures(), 0);

        let mut combined = MtSigningKey::combine(&shares).expect("combine exhausted shares");
        assert!(matches!(
            combined.sign(b"exhausted"),
            Err(LamportError::NoUnusedSigningKeys)
        ));
        assert!(matches!(
            combined.split(2, 2, &mut rng),
            Err(LamportError::NoUnusedSigningKeys)
        ));
    }

    #[test]
    fn malformed_mt_encodings_and_incompatible_shares_are_rejected() {
        let mut rng = ChaCha8Rng::from_seed([40; 32]);
        let split_key = MtSigningKey::<Digest>::random(1, &mut rng).expect("valid depth");
        assert!(split_key.split(0, 2, &mut rng).is_err());

        let mut internally_used_key =
            MtSigningKey::<Digest>::random(1, &mut rng).expect("valid depth");
        internally_used_key.keys[0].used = true;
        assert!(matches!(
            internally_used_key.sign(b"message"),
            Err(LamportError::PrivateKeyReuseError)
        ));

        let (mut key, verifying_key) =
            generate_mt_keys::<Digest, _>(1, &mut rng).expect("valid depth");
        let signature = key.sign(b"message").expect("unused leaf");

        assert!(MtVerifyingKey::<Digest>::from_bytes([]).is_err());
        assert!(MtVerifyingKey::<Digest>::from_bytes([0]).is_err());
        let mut invalid_verifying_key = verifying_key.to_bytes();
        invalid_verifying_key.pop();
        assert!(MtVerifyingKey::<Digest>::from_bytes(invalid_verifying_key).is_err());

        assert!(MtSignature::<Digest>::from_bytes([]).is_err());
        let mut invalid_signature = signature.to_bytes();
        invalid_signature[1] = 2;
        assert!(MtSignature::<Digest>::from_bytes(invalid_signature).is_err());
        let mut invalid_signature_depth = signature.to_bytes();
        invalid_signature_depth[0] = 0;
        assert!(MtSignature::<Digest>::from_bytes(invalid_signature_depth).is_err());

        let sharing_key = MtSigningKey::<Digest>::random(1, &mut rng).expect("valid depth");
        let mut shares = sharing_key.split(2, 3, &mut rng).expect("split tree keys");
        let partials = shares
            .iter_mut()
            .map(|share| share.sign(b"threshold"))
            .collect::<LamportResult<Vec<_>>>()
            .expect("produce shares");
        assert!(MtSignature::<Digest>::combine(&[]).is_err());
        assert!(MtSignature::<Digest>::combine(&partials[..1]).is_err());
        let mut incompatible_partials = partials;
        incompatible_partials[1].index = 1;
        assert!(MtSignature::<Digest>::combine(&incompatible_partials[..2]).is_err());

        assert!(MtSignatureShare::<Digest>::from_bytes([]).is_err());
        let mut invalid_partial = incompatible_partials[0].to_bytes();
        invalid_partial[1] = 2;
        assert!(MtSignatureShare::<Digest>::from_bytes(invalid_partial).is_err());
        let mut invalid_partial_depth = incompatible_partials[0].to_bytes();
        invalid_partial_depth[0] = 0;
        assert!(MtSignatureShare::<Digest>::from_bytes(invalid_partial_depth).is_err());
        let mut invalid_partial_metadata = incompatible_partials[0].to_bytes();
        let partial_signature_offset = 2
            + verifying_key_size::<Digest>()
            + usize::from(incompatible_partials[0].depth) * Digest::digest_size_in_bytes();
        invalid_partial_metadata[partial_signature_offset] = 0;
        assert!(MtSignatureShare::<Digest>::from_bytes(invalid_partial_metadata).is_err());

        assert!(MtSigningKey::<Digest>::combine(&[]).is_err());
        assert!(MtSigningKey::<Digest>::combine(&shares[..1]).is_err());
        shares[0].depth = 0;
        assert!(MtSigningKey::<Digest>::combine(&shares[..2]).is_err());
        let mut combine_shares = sharing_key
            .split(2, 3, &mut rng)
            .expect("split fresh tree keys");
        for share in &mut combine_shares {
            share.public_keys[0].zero_values.data[0] ^= 1;
        }
        assert!(MtSigningKey::<Digest>::combine(&combine_shares[..2]).is_err());

        let mut internally_used_share = combine_shares.remove(0);
        internally_used_share.keys[0].used = true;
        assert!(matches!(
            internally_used_share.sign(b"message"),
            Err(LamportError::PrivateKeyReuseError)
        ));

        let share_key = MtSigningKey::<Digest>::random(1, &mut rng).expect("valid depth");
        let share = share_key
            .split(2, 2, &mut rng)
            .expect("split tree keys")
            .remove(0);
        let encoded = share.to_bytes();
        let leaves_size = 2 * Digest::digest_size_in_bytes();
        let first_share = 3 + leaves_size;
        let pair_size =
            signing_key_share_material_size::<Digest>() + verifying_key_size::<Digest>();

        let mut invalid_version = encoded.clone();
        invalid_version[0] = STATE_FORMAT_VERSION + 1;
        assert!(MtSigningKeyShare::<Digest>::from_bytes(invalid_version).is_err());
        assert!(MtSigningKeyShare::<Digest>::from_bytes([STATE_FORMAT_VERSION]).is_err());
        assert!(MtSigningKeyShare::<Digest>::from_bytes([STATE_FORMAT_VERSION, 0]).is_err());
        assert!(MtSigningKeyShare::<Digest>::from_bytes([STATE_FORMAT_VERSION, 1]).is_err());

        let mut invalid_length = encoded.clone();
        invalid_length.pop();
        assert!(MtSigningKeyShare::<Digest>::from_bytes(invalid_length).is_err());

        let mut invalid_identifier = encoded.clone();
        invalid_identifier[first_share] = 0;
        assert!(MtSigningKeyShare::<Digest>::from_bytes(invalid_identifier).is_err());

        let mut inconsistent_identifier = encoded;
        inconsistent_identifier[first_share + pair_size] =
            inconsistent_identifier[first_share].wrapping_add(1).max(1);
        assert!(MtSigningKeyShare::<Digest>::from_bytes(inconsistent_identifier).is_err());
    }

    #[test]
    fn mt_secret_states_can_be_zeroized_explicitly() {
        let mut rng = ChaCha8Rng::from_seed([41; 32]);
        let (mut key, _) = generate_mt_keys::<Digest, _>(1, &mut rng).expect("valid depth");
        let mut share = key
            .split(2, 2, &mut rng)
            .expect("split tree keys")
            .remove(0);

        key.zeroize();
        assert_eq!(key.next_index(), 0);
        assert_eq!(key.remaining_signatures(), 0);

        share.zeroize();
        assert_eq!(share.next_index(), 0);
        assert_eq!(share.remaining_signatures(), 0);
        assert!(matches!(
            share.sign(b"zeroized"),
            Err(LamportError::NoUnusedSigningKeys)
        ));
    }
}
