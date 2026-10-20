//! ECDSA on P-224, P-384, P-521 and secp256k1 against Wycheproof's vectors and OpenSSL's signatures with SHA-256.

use krb5_types::pkinit::{IdentityKey, spki_signature_ok};

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn wycheproof(data: &str, alg: &[u8]) -> usize {
    let mut spki = Vec::new();
    let mut checked = 0;
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        match line.split(' ').collect::<Vec<_>>()[..] {
            ["key", der] => spki = hex(der),
            ["tc", id, result, msg, sig] => {
                let ok = spki_signature_ok(&spki, alg, &hex(msg), &hex(sig));
                assert_eq!(ok, result == "valid", "tc {id}");
                checked += 1;
            }
            _ => panic!("unknown line: {line}"),
        }
    }
    checked
}

#[test]
fn wycheproof_vectors_verify() {
    let p384 = include_str!("data/wycheproof-ecdsa-p384-sha256.kat");
    assert_eq!(wycheproof(p384, ECDSA_SHA256), 472);
    let p521 = include_str!("data/wycheproof-ecdsa-p521-sha512.kat");
    assert_eq!(wycheproof(p521, ECDSA_SHA512), 542);
    let p224 = include_str!("data/wycheproof-ecdsa-p224-sha256.kat");
    assert_eq!(wycheproof(p224, ECDSA_SHA256), 481);
    let k256 = include_str!("data/wycheproof-ecdsa-secp256k1-sha256.kat");
    assert_eq!(wycheproof(k256, ECDSA_SHA256), 476);
}

#[test]
fn openssl_signatures_verify_and_ours_verify_too() {
    let (mut key, mut spki) = (None, Vec::new());
    let mut checked = 0;
    for line in include_str!("data/openssl-ecdsa-sha256.kat")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        match line.split(' ').collect::<Vec<_>>()[..] {
            ["key", der] => key = Some(IdentityKey::from_pkcs8(&hex(der)).expect("the key loads")),
            ["spki", der] => spki = hex(der),
            ["tc", id, msg, sig] => {
                let (msg, mut sig) = (hex(msg), hex(sig));
                assert!(
                    spki_signature_ok(&spki, ECDSA_SHA256, &msg, &sig),
                    "tc {id}"
                );
                let last = sig.len() - 1;
                sig[last] ^= 1;
                assert!(
                    !spki_signature_ok(&spki, ECDSA_SHA256, &msg, &sig),
                    "tc {id} altered"
                );
                let key = key.as_ref().expect("a key before its tests");
                let (ours, alg) = key.sign_sha256(&msg).expect("it signs");
                assert_eq!(alg, ECDSA_SHA256, "tc {id}");
                assert!(spki_signature_ok(&spki, alg, &msg, &ours), "tc {id} ours");
                checked += 1;
            }
            _ => panic!("unknown line: {line}"),
        }
    }
    assert_eq!(checked, 24);
}
