//! SHA-3 and SHAKE benchmarks.

mod common;

use common::bench_digest;
use criterion::*;
use lamport_signature_plus::{LamportExtendableDigest, LamportFixedDigest};
use sha3::{Sha3_256, Sha3_384, Sha3_512};
use shake::{Shake128, Shake256};

fn bench_sha3_256(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Sha3_256>>(c, "Sha3_256");
}

fn bench_sha3_384(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Sha3_384>>(c, "Sha3_384");
}

fn bench_sha3_512(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Sha3_512>>(c, "Sha3_512");
}

fn bench_shake128(c: &mut Criterion) {
    bench_digest::<LamportExtendableDigest<Shake128>>(c, "Shake128");
}

fn bench_shake256(c: &mut Criterion) {
    bench_digest::<LamportExtendableDigest<Shake256>>(c, "Shake256");
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
