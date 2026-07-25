use criterion::{BatchSize, Criterion};
use lamport_signature_plus::{LamportDigest, SigningKey, VerifyingKey};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

pub fn bench_digest<T: LamportDigest>(criterion: &mut Criterion, name: &str) {
    const DATA: &[u8] = b"hello, world!";

    criterion.bench_function(&format!("New Signing Key with {name}"), |bencher| {
        bencher.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let _ = SigningKey::<T>::random(rng);
        });
    });
    criterion.bench_function(&format!("Sign with {name}"), |bencher| {
        bencher.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut signing_key = SigningKey::<T>::random(rng);
            signing_key
                .sign(DATA)
                .expect("benchmark signing should succeed");
        });
    });
    criterion.bench_function(&format!("Verify with {name}"), |bencher| {
        bencher.iter(|| {
            let rng = ChaCha20Rng::from_seed([0u8; 32]);
            let mut signing_key = SigningKey::<T>::random(rng);
            let verifying_key = VerifyingKey::from(&signing_key);
            let signature = signing_key
                .sign(DATA)
                .expect("benchmark signing should succeed");
            verifying_key
                .verify(&signature, DATA)
                .expect("benchmark verification should succeed");
        });
    });

    criterion.bench_function(&format!("Sign only with {name}"), |bencher| {
        bencher.iter_batched(
            || SigningKey::<T>::random(ChaCha20Rng::from_seed([0u8; 32])),
            |mut signing_key| {
                signing_key
                    .sign(DATA)
                    .expect("benchmark signing should succeed")
            },
            BatchSize::SmallInput,
        );
    });
    criterion.bench_function(&format!("Verify only with {name}"), |bencher| {
        bencher.iter_batched(
            || {
                let mut signing_key = SigningKey::<T>::random(ChaCha20Rng::from_seed([0u8; 32]));
                let verifying_key = VerifyingKey::from(&signing_key);
                let signature = signing_key
                    .sign(DATA)
                    .expect("benchmark signing should succeed");
                (verifying_key, signature)
            },
            |(verifying_key, signature)| {
                verifying_key
                    .verify(&signature, DATA)
                    .expect("benchmark verification should succeed")
            },
            BatchSize::SmallInput,
        );
    });
    criterion.bench_function(&format!("Partial sign only with {name}"), |bencher| {
        bencher.iter_batched(
            || {
                let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
                let signing_key = SigningKey::<T>::random(&mut rng);
                signing_key
                    .split(2, 2, &mut rng)
                    .expect("benchmark key splitting should succeed")
                    .remove(0)
            },
            |mut share| {
                share
                    .sign(DATA)
                    .expect("benchmark partial signing should succeed")
            },
            BatchSize::SmallInput,
        );
    });
}
