//! SHA2 benchmarks
#![allow(clippy::unwrap_used)]

use criterion::*;
use lamport_signature_plus::{LamportFixedDigest, SigningKey, VerifyingKey};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use sha2::{Sha256, Sha384, Sha512};

fn bench_sha256(c: &mut Criterion) {
    const DATA: &[u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
            sk.sign(DATA).expect("operation should succeed");
        });
    });
    c.bench_function("Verify with Sha256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).expect("operation should succeed");
            pk.verify(&signature, DATA)
                .expect("operation should succeed");
        });
    });
}

fn bench_sha384(c: &mut Criterion) {
    const DATA: &[u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha384", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportFixedDigest<Sha384>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha384", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha384>>::random(rng);
            sk.sign(DATA).expect("operation should succeed");
        });
    });
    c.bench_function("Verify with Sha384", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha384>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).expect("operation should succeed");
            pk.verify(&signature, DATA)
                .expect("operation should succeed");
        });
    });
}

fn bench_sha512(c: &mut Criterion) {
    const DATA: &[u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha512", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportFixedDigest<Sha512>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha512", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha512>>::random(rng);
            sk.sign(DATA).expect("operation should succeed");
        });
    });
    c.bench_function("Verify with Sha512", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha512>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).expect("operation should succeed");
            pk.verify(&signature, DATA)
                .expect("operation should succeed");
        });
    });
}

criterion_group!(benches, bench_sha256, bench_sha384, bench_sha512);

criterion_main!(benches);
