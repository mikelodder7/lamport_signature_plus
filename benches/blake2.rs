//! BLAKE2 benchmarks.

mod common;

use blake2::{Blake2b512, Blake2s256};
use common::bench_digest;
use criterion::*;
use lamport_signature_plus::LamportFixedDigest;

fn bench_blake2s(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Blake2s256>>(c, "Blake2s");
}

fn bench_blake2b(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Blake2b512>>(c, "Blake2b");
}

criterion_group!(benches, bench_blake2s, bench_blake2b);
criterion_main!(benches);
