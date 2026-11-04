use krb5_types::pkinit::RsaKey;

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn check(data: &str) -> usize {
    let mut key = None;
    let mut checked = 0;
    for line in data.lines().filter(|l| !l.starts_with('#')) {
        match line.split(' ').collect::<Vec<_>>()[..] {
            ["key", der] => key = Some(RsaKey::from_pkcs8(&hex(der)).expect("the key loads")),
            ["tc", id, msg, sig] => {
                let key = key.as_ref().expect("a key before its tests");
                assert_eq!(key.sign_sha256(&hex(msg)), Some(hex(sig)), "tc {id}");
                checked += 1;
            }
            ["refuse", id, msg] => {
                let key = key.as_ref().expect("a key before its tests");
                assert_eq!(key.sign_sha256(&hex(msg)), None, "refuse {id}");
                checked += 1;
            }
            _ => panic!("unknown line: {line}"),
        }
    }
    checked
}

#[test]
fn wycheproof_pkcs1_sha256_signatures_match() {
    assert_eq!(
        check(include_str!("data/wycheproof-rsa-pkcs1-sha256.kat")),
        27
    );
}

#[test]
fn openssl_signatures_match_up_to_16384_bits_and_five_primes() {
    assert_eq!(check(include_str!("data/openssl-rsa-pkcs1-sha256.kat")), 15);
}
