# `lamport_signature_plus`

[![Crates.io](https://img.shields.io/crates/v/lamport_signature_plus.svg)](https://crates.io/crates/lamport_signature_plus)
[![docs.rs](https://docs.rs/lamport_signature_plus/badge.svg)](https://docs.rs/lamport_signature_plus)
[![Apache 2.0/MIT licensed](https://img.shields.io/badge/license-Apache--2.0%2FMIT-blue.svg)](https://github.com/mikelodder7/lamport_signature_plus#license)
[![codecov](https://codecov.io/gh/mikelodder7/lamport_signature_plus/branch/main/graph/badge.svg)](https://codecov.io/gh/mikelodder7/lamport_signature_plus)

*lamport_signature_plus* is an implementation of the [Lamport one-time signature scheme](https://en.wikipedia.org/wiki/Lamport_signature).

## Documentation

Documentation is [available here](https://docs.rs/lamport_signature_plus).
Release history is recorded in the [changelog](CHANGELOG.md).

## Usage

```rust
use lamport_signature_plus::{VerifyingKey, SigningKey, LamportFixedDigest};
use sha2::Sha256;

let mut signing_key = SigningKey::<LamportFixedDigest<Sha256>>::random(rand::rng());
let verifying_key = VerifyingKey::from(&signing_key);

let signature = signing_key.sign(b"Hello, World!").expect("signing failed");

assert!(verifying_key.verify(&signature, b"Hello, World!").is_ok());
```

This crate supports hash functions that implement either `Digest` or
`ExtendableOutput` from the `digest` crate. The `SigningKey`, `VerifyingKey`,
and `Signature` types are generic over the selected hash function.

Serde support is enabled by default. Applications that only use the canonical
byte encodings can disable it with `default-features = false`.

## Merkle-tree Lamport signatures

`MtSigningKey` commits several Lamport public keys in a Merkle tree, so one
compact `MtVerifyingKey` can authorize multiple signatures. Depths 1, 2, and 3
are supported, yielding 2, 4, and 8 one-time leaf keys respectively. A
signature contains the selected Lamport public key and its authentication path.

```rust
use lamport_signature_plus::{LamportFixedDigest, generate_mt_keys};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::Sha256;

let mut rng = ChaCha8Rng::from_seed([7; 32]);
let (mut signing_key, verifying_key) =
    generate_mt_keys::<LamportFixedDigest<Sha256>, _>(2, &mut rng).unwrap();

let signature = signing_key.sign(b"first message").unwrap();
assert_eq!(signature.index(), 0);
verifying_key.verify(&signature, b"first message").unwrap();

// The next call automatically consumes index 1.
let signature = signing_key.sign(b"another message").unwrap();
assert_eq!(signature.index(), 1);
verifying_key.verify(&signature, b"another message").unwrap();
```

The MT signing key is stateful. Persist its new state after every signature.
Rolling back or copying that state can reuse a one-time leaf and break the
scheme's security. Each successful signing operation destroys the consumed
leaf secret; the canonical signing-key encoding therefore becomes smaller as
indices are consumed while retaining the leaf commitments needed for proofs.

Threshold signing composes with the tree: `MtSigningKey::split` shares every
leaf under one threshold policy, each participant calls `sign` in the same
sequence, and `MtSignature::combine` reconstructs a signature with the common
inclusion proof.

## Threshold signatures

This crate supports threshold signing by splitting a `SigningKey` into shares
and creating a `SignatureShare` from each key share. The signature shares can
then be combined into a `Signature` using `Signature::combine`.

```rust
use lamport_signature_plus::{LamportFixedDigest, Signature, generate_keys};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::Sha256;

const SEED: [u8; 32] = [0u8; 32];
let mut rng = ChaCha8Rng::from_seed(SEED);
let (sk, pk) = generate_keys::<LamportFixedDigest<Sha256>, _>(&mut rng);
let message = b"hello, world!";
let mut shares = sk.split(3, 5, &mut rng).unwrap();
let signatures = shares
    .iter_mut()
    .map(|share| share.sign(message).unwrap())
    .collect::<Vec<_>>();

let res = Signature::combine(&signatures[..3]);
assert!(res.is_ok());
let signature = res.unwrap();
assert!(pk.verify(&signature, message).is_ok());
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.
