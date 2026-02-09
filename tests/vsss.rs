//! Test the VSSS implementation.

use lamport_signature_plus::{generate_keys, LamportFixedDigest, Rand, Signature};
use rand_chacha::rand_core::SeedableRng;
use sha2::Sha256;

#[test]
fn partial_sign() {
    let mut rng = rand_chacha::ChaChaRng::from_rng(&mut rand::rng());
    for _ in 0..10 {
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

        let res = Signature::combine(&signatures[1..3]);
        assert!(res.is_err());
    }
}
