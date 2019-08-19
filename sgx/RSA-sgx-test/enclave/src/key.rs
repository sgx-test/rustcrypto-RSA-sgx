use rsa::key::*;
use rsa::internals;
use num_traits::{FromPrimitive, ToPrimitive};
use rand::{rngs::ThreadRng, thread_rng};
use num_bigint::BigUint;
use rsa::algorithms::generate_multi_prime_key;

//#[test]
pub fn test_from_into() {
    let private_key = RSAPrivateKey {
        n: BigUint::from_u64(100).unwrap(),
        e: BigUint::from_u64(200).unwrap(),
        d: BigUint::from_u64(123).unwrap(),
        primes: vec![],
        precomputed: None,
    };
    let public_key: RSAPublicKey = private_key.into();

    assert_eq!(public_key.n().to_u64(), Some(100));
    assert_eq!(public_key.e().to_u64(), Some(200));
}

fn test_key_basics(private_key: &RSAPrivateKey) {
    private_key.validate().expect("invalid private key");

    assert!(
        private_key.d() < private_key.n(),
        "private exponent too large"
    );

    let pub_key: RSAPublicKey = private_key.clone().into();
    let m = BigUint::from_u64(42).expect("invalid 42");
    let c = internals::encrypt(&pub_key, &m);
    let m2 = internals::decrypt::<ThreadRng>(None, &private_key, &c)
        .expect("unable to decrypt without blinding");
    assert_eq!(m, m2);
    let mut rng = thread_rng();
    let m3 = internals::decrypt(Some(&mut rng), &private_key, &c)
        .expect("unable to decrypt with blinding");
    assert_eq!(m, m3);
}

macro_rules! key_generation {
    ($name:ident, $multi:expr, $size:expr) => {
        //#[test]
        pub fn $name() {
            let mut rng = thread_rng();

            for _ in 0..10 {
                let private_key = if $multi == 2 {
                    RSAPrivateKey::new(&mut rng, $size).expect("failed to generate key")
                } else {
                    generate_multi_prime_key(&mut rng, $multi, $size).unwrap()
                };
                assert_eq!(private_key.n().bits(), $size);

                test_key_basics(&private_key);
            }
        }
    };
}

key_generation!(key_generation_128, 2, 128);
key_generation!(key_generation_1024, 2, 1024);

key_generation!(key_generation_multi_3_256, 3, 256);

key_generation!(key_generation_multi_4_64, 4, 64);

key_generation!(key_generation_multi_5_64, 5, 64);
key_generation!(key_generation_multi_8_576, 8, 576);
key_generation!(key_generation_multi_16_1024, 16, 1024);

//#[test]
pub fn test_impossible_keys() {
    // make sure not infinite loops are hit here.
    let mut rng = thread_rng();
    for i in 0..32 {
        let _ = RSAPrivateKey::new(&mut rng, i).is_err();
        let _ = generate_multi_prime_key(&mut rng, 3, i);
        let _ = generate_multi_prime_key(&mut rng, 4, i);
        let _ = generate_multi_prime_key(&mut rng, 5, i);
    }
}

//#[test]
pub fn test_negative_decryption_value() {
    let private_key = RSAPrivateKey::from_components(
        BigUint::from_bytes_le(&vec![
            99, 192, 208, 179, 0, 220, 7, 29, 49, 151, 75, 107, 75, 73, 200, 180,
        ]),
        BigUint::from_bytes_le(&vec![1, 0, 1]),
        BigUint::from_bytes_le(&vec![
            81, 163, 254, 144, 171, 159, 144, 42, 244, 133, 51, 249, 28, 12, 63, 65,
        ]),
        vec![
            BigUint::from_bytes_le(&vec![105, 101, 60, 173, 19, 153, 3, 192]),
            BigUint::from_bytes_le(&vec![235, 65, 160, 134, 32, 136, 6, 241]),
        ],
    );

    for _ in 0..1000 {
        test_key_basics(&private_key);
    }
}

//#[test]
pub fn test_serde() {
    use rand::{SeedableRng};
    use rand_xorshift::XorShiftRng;
    use serde_test::{assert_tokens, Token};

    let mut rng = XorShiftRng::from_seed([1; 16]);
    let priv_key = RSAPrivateKey::new(&mut rng, 64).expect("failed to generate key");

    let priv_tokens = [
        Token::Struct {
            name: "RSAPrivateKey",
            len: 4,
        },
        Token::Str("n"),
        Token::Seq { len: Some(2) },
        Token::U32(1296829443),
        Token::U32(2444363981),
        Token::SeqEnd,
        Token::Str("e"),
        Token::Seq { len: Some(1) },
        Token::U32(65537),
        Token::SeqEnd,
        Token::Str("d"),
        Token::Seq { len: Some(2) },
        Token::U32(298985985),
        Token::U32(2349628418),
        Token::SeqEnd,
        Token::Str("primes"),
        Token::Seq { len: Some(2) },
        Token::Seq { len: Some(1) },
        Token::U32(3238068481),
        Token::SeqEnd,
        Token::Seq { len: Some(1) },
        Token::U32(3242199299),
        Token::SeqEnd,
        Token::SeqEnd,
        Token::StructEnd,
    ];
    assert_tokens(&priv_key, &priv_tokens);

    let priv_tokens = [
        Token::Struct {
            name: "RSAPublicKey",
            len: 2,
        },
        Token::Str("n"),
        Token::Seq { len: Some(2) },
        Token::U32(1296829443),
        Token::U32(2444363981),
        Token::SeqEnd,
        Token::Str("e"),
        Token::Seq { len: Some(1) },
        Token::U32(65537),
        Token::SeqEnd,
        Token::StructEnd,
    ];
    assert_tokens(&RSAPublicKey::from(priv_key), &priv_tokens);
}
