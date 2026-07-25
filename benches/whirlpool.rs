//! Whirlpool benchmarks

mod common;

use common::bench_digest;
use criterion::*;
use lamport_signature_plus::LamportFixedDigest;
use whirlpool::Whirlpool;

fn bench_whirlpool(c: &mut Criterion) {
    bench_digest::<LamportFixedDigest<Whirlpool>>(c, "Whirlpool");
}

criterion_group!(benches, bench_whirlpool);
criterion_main!(benches);
