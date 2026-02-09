//! SHA3 benchmarks
#![allow(clippy::unwrap_used)]

use criterion::*;
use lamport_signature_plus::{
    LamportExtendableDigest, LamportFixedDigest, SigningKey, VerifyingKey,
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use sha3::{Sha3_256, Sha3_384, Sha3_512, Shake128, Shake256};

fn bench_sha3_256(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha3_256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportFixedDigest<Sha3_256>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha3_256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha3_256>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Sha3_256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha3_256>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

fn bench_sha3_384(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha3_384", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportFixedDigest<Sha3_384>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha3_384", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha3_384>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Sha3_384", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha3_384>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

fn bench_sha3_512(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha3_512", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportFixedDigest<Sha3_512>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha3_512", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha3_512>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Sha3_512", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportFixedDigest<Sha3_512>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

fn bench_shake128(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Shake128", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportExtendableDigest<Shake128>>::random(rng);
        });
    });
    c.bench_function("Sign with Shake128", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportExtendableDigest<Shake128>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Shake128", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportExtendableDigest<Shake128>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

fn bench_shake256(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Shake256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<LamportExtendableDigest<Shake256>>::random(rng);
        });
    });
    c.bench_function("Sign with Shake256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportExtendableDigest<Shake256>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Shake256", |b| {
        b.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut sk = SigningKey::<LamportExtendableDigest<Shake256>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

criterion_group!(
    benches,
    bench_sha3_256,
    bench_sha3_384,
    bench_sha3_512,
    bench_shake128,
    bench_shake256
);

criterion_main!(benches);
