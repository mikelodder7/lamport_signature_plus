# `lamport_signature`

[![Crates.io](https://img.shields.io/crates/v/lamport_signature_plus.svg)](https://crates.io/crates/lamport_signature_plus)
[![docs.rs](https://docs.rs/lamport_signature/badge.svg)](https://docs.rs/lamport_signature_plus)
[![GitHub license](https://img.shields.io/badge/license-Apache2.0.svg)](https://github.com/mikelodder7/lamport_signature_plus/blob/master/LICENSE)

*lamport_signature_plus* is an implementation of the [Lamport one-time signature scheme](https://en.wikipedia.org/wiki/Lamport_signature).

## Documentation

Documentation is [available here](https://docs.rs/lamport_signature_plus).

## Usage

```rust
use lamport_signature::{VerifyingKey, SigningKey, LamportFixedDigest};
use sha2::Sha256;
use rand::thread_rng;

let mut signing_key = SigningKey::<LamportFixedDigest<Sha256>>::random(thread_rng());
let verifying_key = VerifyingKey::from(&signing_key);

let signature = signing_key.sign(b"Hello, World!").expect("signing failed");

assert!(verifying_key.verify(&signature, b"Hello, World!").is_ok());
```

This crate supports any hash function that implements the `Digest` trait from the `digest` crate or `ExtendableOutputFunction`. 
The `SigningKey`, `VerifyingKey`, and `Signature` types are generic over the hash function used.

# Threshold Signatures
This crate supports threshold signing by first splitting the `SigningKey` into shares and creating 
`SignatureShare`s from each share. The `SignatureShare`s can then be combined into a `Signature` using the `combine` method.

```rust
use lamport_signature_plus::{VerifyingKey, SigningKey, LamportFixedDigest, Rand, generate_keys};
use sha2::Sha256;

const SEED: [u8; 32] = [0u8; 32];
let mut rng = rand_chacha::ChaCha8Rng::from_seed(SEED);
let (sk, pk) = generate_keys::<LamportFixedDigest<Sha256>, _>(&mut rng);
let message = b"hello, world!";
let mut shares = sk.split(3, 5, Rand::new(&mut rng)).unwrap();
let signatures = shares
    .iter_mut()
    .map(|share| share.sign(message).unwrap())
    .collect::<Vec<_>>();

let res = Signature::combine(&signatures[..3]);
assert!(res.is_ok());
let signature = res.unwrap();
assert!(pk.verify(&signature, message).is_ok());
```

# License

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

# Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be licensed as above, without any additional terms or
conditions.