//! Public API coverage for generic serialization and conversion implementations.

use lamport_signature_plus::{
    LamportFixedDigest, Signature, SignatureShare, SigningKey, SigningKeyShare, VerifyingKey,
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::Sha256;

type Digest = LamportFixedDigest<Sha256>;

#[test]
fn generic_serialization_paths() {
    let mut rng = ChaCha8Rng::from_seed([13; 32]);
    let mut signing_key = SigningKey::<Digest>::random(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let signature = signing_key
        .sign(b"message")
        .expect("signing should succeed");

    round_trip(&signing_key);
    round_trip(&verifying_key);
    round_trip(&signature);

    let key = SigningKey::<Digest>::random(&mut rng);
    let mut key_shares = key
        .split(2, 2, &mut rng)
        .expect("key splitting should succeed");
    let signature_shares = key_shares
        .iter_mut()
        .map(|share| {
            share
                .sign(b"message")
                .expect("partial signing should succeed")
        })
        .collect::<Vec<_>>();

    round_trip(&key_shares[0]);
    round_trip(&signature_shares[0]);

    assert!(serde_json::from_str::<VerifyingKey<Digest>>("123").is_err());
    assert!(serde_json::from_str::<Signature<Digest>>("\"not-hex\"").is_err());
    assert!(serde_json::from_str::<SigningKey<Digest>>("\"00\"").is_err());
    assert!(postcard::from_bytes::<SignatureShare<Digest>>(&[0xff]).is_err());

    assert_conversions::<Signature<Digest>>(signature.to_bytes());
    assert_conversions::<VerifyingKey<Digest>>(verifying_key.to_bytes());
    assert_conversions::<SigningKey<Digest>>(signing_key.to_bytes());
    assert_conversions::<SignatureShare<Digest>>(signature_shares[0].to_bytes());
    assert_conversions::<SigningKeyShare<Digest>>(key_shares[0].to_bytes());
}

fn round_trip<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let json = serde_json::to_string(value).expect("JSON serialization should succeed");
    let _: T = serde_json::from_str(&json).expect("JSON deserialization should succeed");

    let bytes = postcard::to_stdvec(value).expect("postcard serialization should succeed");
    let _: T = postcard::from_bytes(&bytes).expect("postcard deserialization should succeed");
}

fn assert_conversions<T>(bytes: Vec<u8>)
where
    T: TryFrom<Vec<u8>, Error = lamport_signature_plus::LamportError>
        + for<'a> TryFrom<&'a Vec<u8>, Error = lamport_signature_plus::LamportError>
        + for<'a> TryFrom<&'a [u8], Error = lamport_signature_plus::LamportError>
        + TryFrom<Box<[u8]>, Error = lamport_signature_plus::LamportError>,
{
    T::try_from(bytes.clone()).expect("vector conversion should succeed");
    T::try_from(&bytes).expect("vector reference conversion should succeed");
    T::try_from(bytes.as_slice()).expect("slice conversion should succeed");
    T::try_from(bytes.into_boxed_slice()).expect("boxed slice conversion should succeed");
}
