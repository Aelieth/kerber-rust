//! PKINIT key exchange on MIT's six groups against OpenSSL's shared secrets.

use krb5_types::pkinit::{KxGroup, KxKey, P384_ENABLED};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn openssl_shared_secrets_match_ours() {
    let mut group = None;
    let mut checked = 0;
    for line in include_str!("data/openssl-kx.kat")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        match line.split(' ').collect::<Vec<_>>()[..] {
            ["group", name] => {
                group = Some(match name {
                    "modp2048" => KxGroup::Modp2048,
                    "modp4096" => KxGroup::Modp4096,
                    "modp1024" => KxGroup::Modp1024,
                    "P-256" => KxGroup::P256,
                    "P-384" => KxGroup::P384,
                    _ => KxGroup::P521,
                });
            }
            ["tc", id, secret, peer, shared] => {
                if group == Some(KxGroup::P384) && !P384_ENABLED {
                    assert!(
                        KxKey::from_secret(KxGroup::P384, &hex(secret)).is_none(),
                        "tc {id}"
                    );
                    continue;
                }
                let key =
                    KxKey::from_secret(group.unwrap(), &hex(secret)).expect("the secret loads");
                let ours = key.shared(&hex(peer)).expect("the peer's key is taken");
                assert_eq!(ours.as_slice(), hex(shared).as_slice(), "tc {id}");
                checked += 1;
            }
            _ => panic!("unknown line: {line}"),
        }
    }
    assert_eq!(checked, if P384_ENABLED { 18 } else { 15 });
}
