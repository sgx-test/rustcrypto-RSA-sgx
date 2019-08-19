use std::prelude::v1::*;
use rsa::pkcs1v15::*;
use base64;
use hex;
use num_traits::FromPrimitive;
use num_traits::Num;
use rand::thread_rng;
use sha1::{Digest, Sha1};

use rsa::hash::Hashes;
use rsa::key::{RSAPrivateKey, RSAPublicKey};
use rsa::PublicKey;
use rsa::padding::PaddingScheme;
use num_bigint::BigUint;
use rand::Rng;

//#[test]
pub fn test_non_zero_bytes() {
    for _ in 0..10 {
        let mut rng = thread_rng();
        let mut b = vec![0u8; 512];
        non_zero_random_bytes(&mut rng, &mut b);
        for el in &b {
            assert_ne!(*el, 0u8);
        }
    }
}

fn get_private_key() -> RSAPrivateKey {
    // In order to generate new test vectors you'll need the PEM form of this key:
    // -----BEGIN RSA PRIVATE KEY-----
    // MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0
    // fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu
    // /ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWu
    // RTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/
    // EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7A
    // IU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlS
    // tAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V
    // -----END RSA PRIVATE KEY-----

    RSAPrivateKey::from_components(
        BigUint::from_str_radix("9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077", 10).unwrap(),
        BigUint::from_u64(65537).unwrap(),
        BigUint::from_str_radix("7266398431328116344057699379749222532279343923819063639497049039389899328538543087657733766554155839834519529439851673014800261285757759040931985506583861", 10).unwrap(),
        vec![
            BigUint::from_str_radix("98920366548084643601728869055592650835572950932266967461790948584315647051443",10).unwrap(),
            BigUint::from_str_radix("94560208308847015747498523884063394671606671904944666360068158221458669711639", 10).unwrap()
        ],
    )
}

//#[test]
pub fn test_decrypt_pkcs1v15() {
    let priv_key = get_private_key();

    let tests = [[
    "gIcUIoVkD6ATMBk/u/nlCZCCWRKdkfjCgFdo35VpRXLduiKXhNz1XupLLzTXAybEq15juc+EgY5o0DHv/nt3yg==",
    "x",
], [
    "Y7TOCSqofGhkRb+jaVRLzK8xw2cSo1IVES19utzv6hwvx+M8kFsoWQm5DzBeJCZTCVDPkTpavUuEbgp8hnUGDw==",
    "testing.",
], [
    "arReP9DJtEVyV2Dg3dDp4c/PSk1O6lxkoJ8HcFupoRorBZG+7+1fDAwT1olNddFnQMjmkb8vxwmNMoTAT/BFjQ==",
    "testing.\n",
], [
"WtaBXIoGC54+vH0NH0CHHE+dRDOsMc/6BrfFu2lEqcKL9+uDuWaf+Xj9mrbQCjjZcpQuX733zyok/jsnqe/Ftw==",
	"01234567890123456789012345678901234567890123456789012",
]];

    for test in &tests {
        let out = priv_key
            .decrypt(PaddingScheme::PKCS1v15, &base64::decode(test[0]).unwrap())
            .unwrap();
        assert_eq!(out, test[1].as_bytes());
    }
}

//#[test]
pub fn test_encrypt_decrypt_pkcs1v15() {
    let mut rng = thread_rng();
    let priv_key = get_private_key();
    let k = priv_key.size();

    for i in 1..100 {
        let mut input: Vec<u8> = (0..i * 8).map(|_| rng.gen()).collect();
        if input.len() > k - 11 {
            input = input[0..k - 11].to_vec();
        }

        let pub_key: RSAPublicKey = priv_key.clone().into();
        let ciphertext = encrypt(&mut rng, &pub_key, &input).unwrap();
        assert_ne!(input, ciphertext);
        let blind: bool = rng.gen();
        let blinder = if blind { Some(&mut rng) } else { None };
        let plaintext = decrypt(blinder, &priv_key, &ciphertext).unwrap();
        assert_eq!(input, plaintext);
    }
}

//#[test]
pub fn test_sign_pkcs1v15() {
    let priv_key = get_private_key();

    let tests = [[
        "Test.\n", "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e336ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
]];

    for test in &tests {
        let digest = Sha1::digest(test[0].as_bytes()).to_vec();
        let expected = hex::decode(test[1]).unwrap();

        let out = priv_key
            .sign(PaddingScheme::PKCS1v15, Some(&Hashes::SHA1), &digest)
            .unwrap();
        assert_ne!(out, digest);
        assert_eq!(out, expected);

        let mut rng = thread_rng();
        let out2 = priv_key
            .sign_blinded(
                &mut rng,
                PaddingScheme::PKCS1v15,
                Some(&Hashes::SHA1),
                &digest,
            )
            .unwrap();
        assert_eq!(out2, expected);
    }
}

//#[test]
pub fn test_verify_pkcs1v15() {
    let priv_key = get_private_key();

    let tests = [[
        "Test.\n", "a4f3fa6ea93bcdd0c57be020c1193ecbfd6f200a3d95c409769b029578fa0e336ad9a347600e40d3ae823b8c7e6bad88cc07c1d54c3a1523cbbb6d58efc362ae"
]];
    let pub_key: RSAPublicKey = priv_key.into();

    for test in &tests {
        let digest = Sha1::digest(test[0].as_bytes()).to_vec();
        let sig = hex::decode(test[1]).unwrap();

        pub_key
            .verify(PaddingScheme::PKCS1v15, Some(&Hashes::SHA1), &digest, &sig)
            .expect("failed to verify");
    }
}

//#[test]
pub fn test_unpadded_signature() {
    let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
    let expected_sig = base64::decode("pX4DR8azytjdQ1rtUiC040FjkepuQut5q2ZFX1pTjBrOVKNjgsCDyiJDGZTCNoh9qpXYbhl7iEym30BWWwuiZg==").unwrap();
    let priv_key = get_private_key();

    let sig = priv_key
        .sign::<Hashes>(PaddingScheme::PKCS1v15, None, msg)
        .unwrap();
    assert_eq!(expected_sig, sig);

    let pub_key: RSAPublicKey = priv_key.into();
    pub_key
        .verify::<Hashes>(PaddingScheme::PKCS1v15, None, msg, &sig)
        .expect("failed to verify");
}
