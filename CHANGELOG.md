# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Publication dates and the release list were cross-checked against crates.io.

## [Unreleased]

## [0.5.0] - 2026-08-24

### Added

- Add stateful Merkle-tree Lamport signatures through `MtSigningKey`,
  `MtVerifyingKey`, and `MtSignature`.
- Support Merkle-tree depths 1, 2, and 3, providing 2, 4, or 8 one-time
  signatures from one compact Merkle root.
- Add domain-separated leaf and internal-node hashing, authentication paths,
  canonical byte encodings, and Serde support for Merkle-tree keys and
  signatures.
- Add `MtSigningKeyShare` and `MtSignatureShare` so threshold signing composes
  with Merkle-tree Lamport keys.
- Add an authoritative, automatically advanced signing index to Merkle-tree
  signing keys and key shares. Compact-state decoding reconstructs the
  remaining-key state and derived Merkle cache from this index and the stored
  leaf commitments.
- Add versioned, shrinking state encodings that retain compact leaf commitments
  while discarding consumed signing keys and threshold shares.

### Changed

- Move to Rust 2024 and update to `digest` 0.11, `rand_core` 0.10, stable
  `vsss-rs` 6.0, and the corresponding RustCrypto hash releases.
- Declare Rust 1.96 as the minimum supported Rust version and make Serde support
  an optional, default-enabled feature.
- Reduce temporary allocations in hashing, signing, verification, canonical
  serialization, and threshold-share processing.
- Disable Postcard's unused default features in development builds, removing
  its unmaintained `atomic-polyfill` dependency.
- Improve README examples, rustdoc grammar, terminology, and release-facing
  documentation.

### Removed

- Remove the public `Rand`, `TryRand`, and `SplitRng` compatibility adapters;
  threshold splitting now accepts a cryptographically secure RNG directly.

### Fixed

- Strengthen canonical decoding and threshold-share validation for malformed
  metadata and incompatible shares.
- Preserve one-time-use state across canonical and Serde round trips.

### Security

- Zeroize and release each consumed Lamport leaf secret immediately after
  producing its signature or signature share.

## [0.5.0-rc2] - 2026-07-27

### Changed

- Depend directly on `rand_core` and remove the main library's direct `rand`
  dependency.
- Disable unnecessary default features for `hex`, `subtle`, and `vsss-rs`;
  use the `alloc` support in `vsss-rs` 6.0.0-rc8.
- Refactor canonical serialization and threshold-share processing into shared
  helpers.

### Tests

- Expand negative-input, serialization, conversion, zeroization, and threshold
  tests, reaching complete line coverage for the release candidate.

## [0.5.0-rc1] - 2026-07-27

### Changed

- Update `vsss-rs` from 6.0.0-rc5 to 6.0.0-rc6.

## [0.5.0-rc0] - 2026-07-25

### Changed

- Move to Rust 2024 and update to `digest` 0.11, `rand` 0.10, `vsss-rs` 6.0
  release candidates, and the corresponding RustCrypto hash releases.
- Add direct-to-buffer digest operations and reduce temporary allocations in
  signing, verification, byte encoding, and benchmark setup.
- Strengthen canonical decoding and threshold-share validation, including
  malformed metadata and incompatible shares.
- Make signing-key shares non-cloneable and zeroize their secret material on
  drop.

### Removed

- Remove the public `Rand`, `TryRand`, and `SplitRng` compatibility adapters;
  threshold splitting now accepts a cryptographically secure RNG directly.

### Tests

- Add broad unit coverage for byte conversions, Serde round trips, invalid
  inputs, key reuse, and zeroization.

## [0.4.0] - 2026-02-09

### Added

- Add adapters for using rand 0.10 and fallible RNGs with the rand 0.8-based
  threshold implementation.
- Add strict crate-level Rust and Clippy lints and a GitHub Actions workflow.

### Changed

- Update to `rand` 0.10, `vsss-rs` 5.2, `thiserror` 2, `subtle` 2.6, and
  Criterion 0.8.
- Update signing, verification, benchmarks, and threshold support for the new
  dependency APIs.

## [0.3.0] - 2024-04-17

### Added

- Add threshold Lamport signing backed by `vsss-rs` 4.0.
- Add `SigningKeyShare` and `SignatureShare` types.
- Add signing-key splitting and reconstruction through `SigningKey::split`
  and `SigningKey::combine`.
- Add partial-signature creation and reconstruction through
  `Signature::combine`.
- Add threshold examples and integration tests.

## [0.2.0] - 2024-04-16

### Changed

- Rename the crate from `lamport_signature` to `lamport_signature_plus` and
  redesign the public API around `SigningKey`, `VerifyingKey`, and `Signature`.
- Move to Rust 2021 and modern RustCrypto, rand, Serde, subtle, thiserror, and
  zeroize dependencies.
- Split the original single-file implementation into dedicated hashing,
  signing, verification, signature, error, and multidimensional-vector
  modules.
- Adopt dual MIT or Apache-2.0 licensing.

### Added

- Add `LamportFixedDigest` and `LamportExtendableDigest` adapters for
  fixed-output and extendable-output hash functions.
- Add canonical byte conversion and Serde support for keys and signatures.
- Add constant-time secret selection and signature comparison.
- Add explicit one-time-key reuse detection and secret-key zeroization.
- Add `MultiVec`, conversion traits, `generate_keys`, Criterion benchmarks,
  and expanded documentation and tests.

## Predecessor crate: `lamport_signature`

Versions 0.1.0 through 0.1.4 were published under the original
[`lamport_signature`](https://crates.io/crates/lamport_signature) package name.
Their source history is retained in this repository.

## [0.1.4] - 2018-05-31

### Added

- Add debug logging for expected serialized key and signature sizes.
- Add decoding and verification coverage across the supported hash functions.

### Changed

- Simplify I/O error propagation while decoding keys and signatures.

## [0.1.3] - 2018-05-30

### Changed

- Remove unnecessary test-only private-key accessors and redundant code.
- Expand the crates.io keyword metadata.

## [0.1.2] - 2018-05-28

### Fixed

- Correct the published crate version metadata.

## [0.1.1] - 2018-05-28

### Added

- Add README usage documentation and the docs.rs metadata link.

## [0.1.0] - 2018-05-28

### Added

- Initial implementation of Lamport one-time signatures.
- Add generic fixed-output RustCrypto hash support and pluggable random number
  generators.
- Add key generation, signing, verification, serialized key and signature
  conversion, one-time private-key state, benchmarks, and tests.

[Unreleased]: https://github.com/mikelodder7/lamport_signature_plus
[0.5.0]: https://crates.io/crates/lamport_signature_plus/0.5.0
[0.5.0-rc2]: https://crates.io/crates/lamport_signature_plus/0.5.0-rc2
[0.5.0-rc1]: https://crates.io/crates/lamport_signature_plus/0.5.0-rc1
[0.5.0-rc0]: https://crates.io/crates/lamport_signature_plus/0.5.0-rc0
[0.4.0]: https://crates.io/crates/lamport_signature_plus/0.4.0
[0.3.0]: https://crates.io/crates/lamport_signature_plus/0.3.0
[0.2.0]: https://crates.io/crates/lamport_signature_plus/0.2.0
[0.1.4]: https://crates.io/crates/lamport_signature/0.1.4
[0.1.3]: https://crates.io/crates/lamport_signature/0.1.3
[0.1.2]: https://crates.io/crates/lamport_signature/0.1.2
[0.1.1]: https://crates.io/crates/lamport_signature/0.1.1
[0.1.0]: https://crates.io/crates/lamport_signature/0.1.0
