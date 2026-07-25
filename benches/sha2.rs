//! SHA2 benchmarks

mod common;

use common::bench_digest;
use criterion::*;
use lamport_signature_plus::LamportFixedDigest;
use sha2::{Sha256, Sha384, Sha512};

fn bench_sha256(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Sha256>>(c, "Sha256");
}

fn bench_sha384(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Sha384>>(c, "Sha384");
}

fn bench_sha512(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Sha512>>(c, "Sha512");
}

criterion_group!(benches, bench_sha256, bench_sha384, bench_sha512);
criterion_main!(benches);
