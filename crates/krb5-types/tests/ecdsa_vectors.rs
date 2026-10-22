use krb5_types::pkinit::{IdentityKey, P384_ENABLED, spki_signature_ok};

const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
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

fn wycheproof(data: &str, alg: &[u8], curve_on: bool) -> usize {
    let mut spki = Vec::new();
    let mut checked = 0;
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        match line.split(' ').collect::<Vec<_>>()[..] {
            ["key", der] => spki = hex(der),
            ["tc", id, result, msg, sig] => {
                let ok = spki_signature_ok(&spki, alg, &hex(msg), &hex(sig));
                assert_eq!(ok, curve_on && result == "valid", "tc {id}");
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
    assert_eq!(wycheproof(p384, ECDSA_SHA256, P384_ENABLED), 472);
    let p521 = include_str!("data/wycheproof-ecdsa-p521-sha512.kat");
    assert_eq!(wycheproof(p521, ECDSA_SHA512, true), 542);
    let p224 = include_str!("data/wycheproof-ecdsa-p224-sha256.kat");
    assert_eq!(wycheproof(p224, ECDSA_SHA256, true), 481);
    let k256 = include_str!("data/wycheproof-ecdsa-secp256k1-sha256.kat");
    assert_eq!(wycheproof(k256, ECDSA_SHA256, true), 476);
}

/// (a curve this build refuses) must not verify either. Gives (checked, refused).
fn openssl(data: &str) -> (usize, usize) {
    let (mut key, mut spki) = (None, Vec::new());
    let (mut checked, mut refused) = (0, 0);
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        match line.split(' ').collect::<Vec<_>>()[..] {
            ["key", der] => key = IdentityKey::from_pkcs8(&hex(der)),
            ["spki", der] => spki = hex(der),
            ["tc", id, msg, sig] => {
                let (msg, mut sig) = (hex(msg), hex(sig));
                let Some(key) = key.as_ref() else {
                    assert!(
                        !spki_signature_ok(&spki, ECDSA_SHA256, &msg, &sig),
                        "tc {id}"
                    );
                    refused += 1;
                    continue;
                };
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
                let (ours, alg) = key.sign_sha256(&msg).expect("it signs");
                assert_eq!(alg, ECDSA_SHA256, "tc {id}");
                assert!(spki_signature_ok(&spki, alg, &msg, &ours), "tc {id} ours");
                checked += 1;
            }
            _ => panic!("unknown line: {line}"),
        }
    }
    (checked, refused)
}

#[test]
fn openssl_signatures_verify_and_ours_verify_too() {
    let counts = openssl(include_str!("data/openssl-ecdsa-sha256.kat"));
    assert_eq!(counts, if P384_ENABLED { (24, 0) } else { (18, 6) });
    assert_eq!(
        openssl(include_str!("data/openssl-ecdsa-brainpool.kat")),
        if cfg!(target_pointer_width = "64") {
            (36, 12)
        } else {
            (24, 24)
        }
    );
}

#[test]
fn wycheproof_brainpool_verify() {
    let p256 = include_str!("data/wycheproof-ecdsa-brainpoolP256r1-sha256.kat");
    assert_eq!(wycheproof(p256, ECDSA_SHA256, true), 485);
    let p384 = include_str!("data/wycheproof-ecdsa-brainpoolP384r1-sha384.kat");
    assert_eq!(wycheproof(p384, ECDSA_SHA384, true), 516);
    #[cfg(target_pointer_width = "64")]
    {
        let p512 = include_str!("data/wycheproof-ecdsa-brainpoolP512r1-sha512.kat");
        assert_eq!(wycheproof(p512, ECDSA_SHA512, true), 559);
    }
}
