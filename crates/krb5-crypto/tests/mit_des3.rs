//! MIT 1.22.2's des3-cbc-sha1 keys and hmac-sha1-des3-kd checksum, as its own libkrb5 gives them.
//!
//! `data/mit-des3.kat` is the output of the C program beside it, run on
//! `kerber-rust-mit-kdc:1.22.2`. For each of three des3 keys (the random-to-key of a pattern, the
//! string-to-key of a password, one that `krb5_c_make_random_key` drew) it holds the checksum
//! `krb5_c_make_checksum` gives, cksumtype 12, for eight key usages and eight lengths of data, and it
//! holds the string-to-key of three passwords.
//!
//! MIT `krb5int_dk_checksum` (`lib/crypto/krb/checksum_dk_hmac.c:33-58`): `Kc` is `krb5int_derive_key` of the usage and the constant `0x99` over the enctype's own provider, which for des3 is the 3DES derivation ending in `k5_rand2key_des3`, and the checksum is HMAC-SHA1 under it.
//! MIT `krb5_c_make_random_key` (`lib/crypto/krb/make_random_key.c:31-76`): a key it draws has odd parity on every octet, as `k5_rand2key_des3` and `k5_des_fixup_key_parity` make it.

use krb5_crypto::{
    EncryptionType, Error, KeyUsage, ProtocolKey, checksum, checksum_output_size, string_to_key,
    verify_checksum_keyed, verify_checksum_type,
};

const KAT: &str = include_str!("data/mit-des3.kat");

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn key(bytes: &[u8]) -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Des3CbcSha1, bytes).expect("a 24-octet key")
}

/// One `sum` line: a key usage, the data and the checksum MIT made of it.
struct Sum {
    usage: u32,
    data: Vec<u8>,
    mac: Vec<u8>,
}

struct Keyed {
    label: String,
    key: Vec<u8>,
    sums: Vec<Sum>,
}

fn keyed() -> Vec<Keyed> {
    let mut out: Vec<Keyed> = Vec::new();
    for line in KAT.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        match parts[0] {
            "key" => out.push(Keyed {
                label: parts[1].to_owned(),
                key: hex(parts[2]),
                sums: Vec::new(),
            }),
            "sum" => out.last_mut().expect("a key first").sums.push(Sum {
                usage: parts[1].parse().expect("usage"),
                data: hex(parts[2]),
                mac: hex(parts[3]),
            }),
            _ => {}
        }
    }
    out
}

/// A DES key octet's low bit is the parity bit and the octet has an odd number of one bits.
fn odd_parity(octets: &[u8]) -> bool {
    octets.iter().all(|b| b.count_ones() % 2 == 1)
}

/// The checksum of every key, usage and length MIT made is the one this port makes. Before the port
/// of `krb5int_dk_checksum` it derived `Kc` with the AES block cipher, which takes a 16 or 32 octet key, and
/// refused every des3 key with "protocol key length does not match etype".
#[test]
fn the_checksums_mit_makes_under_a_des3_key_are_reproduced() {
    let keys = keyed();
    assert_eq!(keys.len(), 3, "the pattern, the password, the drawn key");
    let mut n = 0;
    for k in &keys {
        assert_eq!(
            k.sums.len(),
            64,
            "{}: eight usages of eight lengths",
            k.label
        );
        let key = key(&k.key);
        for s in &k.sums {
            let usage = KeyUsage::new(s.usage).expect("usage");
            let got = checksum(&key, usage, &s.data).unwrap_or_else(|e| {
                panic!("{} usage {} len {}: {e}", k.label, s.usage, s.data.len())
            });
            assert_eq!(
                got,
                s.mac,
                "{} usage {} len {}",
                k.label,
                s.usage,
                s.data.len()
            );
            n += 1;
        }
    }
    assert_eq!(n, 192);
}

/// `krb5_c_verify_checksum` of cksumtype 12 takes MIT's checksum, by its type and by the key's mandatory type
/// (0), and not the checksum with its last octet changed or one of the wrong length.
#[test]
fn the_checksums_mit_makes_verify_and_a_changed_one_does_not() {
    assert_eq!(checksum_output_size(12), Some(20));
    for k in keyed() {
        let key = key(&k.key);
        for s in k
            .sums
            .iter()
            .filter(|s| matches!(s.data.len(), 0 | 21 | 300))
        {
            let usage = KeyUsage::new(s.usage).expect("usage");
            for ctype in [12, 0] {
                verify_checksum_type(&key, usage, &s.data, ctype, &s.mac)
                    .unwrap_or_else(|e| panic!("{} usage {} type {ctype}: {e}", k.label, s.usage));
            }
            verify_checksum_keyed(&key, usage, &s.data, 12, &s.mac).expect("keyed, type 12");
            let mut changed = s.mac.clone();
            let last = changed.len() - 1;
            changed[last] ^= 1;
            assert_eq!(
                verify_checksum_type(&key, usage, &s.data, 12, &changed),
                Err(Error::Integrity),
                "{} usage {}",
                k.label,
                s.usage
            );
            assert_eq!(
                verify_checksum_type(&key, usage, &s.data, 12, &s.mac[..19]),
                Err(Error::BadChecksumSize)
            );
            // The usage is part of the key derivation: another usage gives another checksum.
            let other = KeyUsage::new(s.usage + 1).expect("usage");
            assert_eq!(
                verify_checksum_type(&key, other, &s.data, 12, &s.mac),
                Err(Error::Integrity)
            );
        }
    }
}

/// The three keys of the file are MIT's own, so each has odd parity on every octet; MIT's `s2k` lines
/// are the key this port's string-to-key makes, parity and all.
#[test]
fn string_to_key_is_mits_and_its_keys_have_odd_parity() {
    let mut n = 0;
    for line in KAT.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        match parts[0] {
            "s2k" => {
                let want = hex(parts[3]);
                let got = string_to_key(
                    EncryptionType::Des3CbcSha1,
                    hex(parts[1]),
                    hex(parts[2]),
                    None,
                )
                .expect("string-to-key");
                assert_eq!(got.as_bytes(), want, "{line}");
                assert!(odd_parity(got.as_bytes()), "{line}");
                n += 1;
            }
            "key" => assert!(odd_parity(&hex(parts[2])), "{line}"),
            _ => {}
        }
    }
    assert_eq!(n, 3);
}
