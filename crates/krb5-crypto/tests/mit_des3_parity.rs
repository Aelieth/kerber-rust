//! What MIT 1.22.2 returns for a des3-cbc-sha1 key whose parity is wrong or which holds a weak DES key, from its own libkrb5.
//!
//! `data/mit-des3-parity.kat` is the output of the C program beside it, run on `kerber-rust-mit-kdc:1.22.2`, which is built
//! with the release's default crypto (`--with-crypto-impl=builtin`). For 53 keys it holds what `krb5_c_encrypt`, `krb5_c_decrypt`,
//! `krb5_c_make_checksum` and `krb5_c_verify_checksum` (cksumtype 12) and `krb5_c_prf` return, by operation and key usage:
//! the good keys, a key with one octet of even parity in each of its three DES keys, a key with every octet wrong, the weak
//! and semi-weak keys in each of the three places, and keys that have both faults, which decide the order of the checks.
//!
//! MIT `mit_des3_key_sched` (`lib/crypto/builtin/des/d3_kysched.c:29-53`): for each DES key in turn, its parity (`-1`) and then its weakness (`-2`).
//! MIT `validate_and_schedule` (`lib/crypto/builtin/enc_provider/des3.c:33-53`): `-1` is `KRB5DES_BAD_KEYPAR` and `-2` is `KRB5DES_WEAK_KEY`, returned by every use of the key.
//! The same key loads: a keytab, a dump or a ticket's session key is taken as it is, and only its first use fails.

use krb5_crypto::{
    EncryptionType, Error, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, prf,
    verify_checksum_type,
};

const KAT: &str = include_str!("data/mit-des3-parity.kat");
const DES3: EncryptionType = EncryptionType::Des3CbcSha1;

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

struct Kat {
    keys: Vec<(String, Vec<u8>)>,
    /// The ciphertext MIT made of 24 octets under the key `good`, key usage 1.
    ct: Vec<u8>,
    /// The checksum MIT made of `hello` under the key `good`, key usage 6.
    mac: Vec<u8>,
    /// `(operation, key, usage, MIT's word)`.
    ops: Vec<(String, String, u32, String)>,
}

fn kat() -> Kat {
    let mut k = Kat {
        keys: Vec::new(),
        ct: Vec::new(),
        mac: Vec::new(),
        ops: Vec::new(),
    };
    for line in KAT.lines() {
        let p: Vec<&str> = line.split(' ').collect();
        match p[0] {
            "key" => k.keys.push((p[1].to_owned(), hex(p[2]))),
            "ct" => k.ct = hex(p[2]),
            "cs" => {
                assert_eq!(hex(p[2]), b"hello");
                k.mac = hex(p[3]);
            }
            "enc" | "dec" | "sum" | "ver" | "prf" => k.ops.push((
                p[0].to_owned(),
                p[1].to_owned(),
                p[2].parse().expect("usage"),
                p[3].to_owned(),
            )),
            _ => {}
        }
    }
    k
}

/// MIT's word for what an operation returned, as this port's result.
fn expect(word: &str) -> Result<(), Error> {
    match word {
        "OK" => Ok(()),
        "BAD_KEYPAR" => Err(Error::DesBadParity),
        "WEAK_KEY" => Err(Error::DesWeakKey),
        // `krb5_c_decrypt` and `krb5_c_verify_checksum` of data made under another key usage.
        "OTHER-1765328353" | "INVALID" => Err(Error::Integrity),
        other => panic!("a word this test does not know: {other}"),
    }
}

fn of(k: &Kat, name: &str) -> ProtocolKey {
    let key = &k
        .keys
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no key {name}"))
        .1;
    ProtocolKey::from_bytes(DES3, key).expect("a 24-octet key loads, whatever its parity")
}

/// Every operation under every key returns what MIT returns: a good key is used, and a key with a wrong octet or a weak DES
/// key is refused with MIT's code. Before the port of `mit_des3_key_sched`, this port used any 24 octets.
#[test]
fn every_use_of_a_des3_key_is_refused_as_mit_refuses_it() {
    let k = kat();
    assert_eq!(k.keys.len(), 53);
    let plain: Vec<u8> = (0..24u8).map(|i| i * 5 + 1).collect();
    let mut n = 0;
    for (op, name, usage, word) in &k.ops {
        let key = of(&k, name);
        let usage_k = KeyUsage::new(if op == "prf" { 1 } else { *usage }).expect("usage");
        let got: Result<(), Error> = match op.as_str() {
            "enc" => encrypt(&key, usage_k, &plain).map(|_| ()),
            "dec" => decrypt(&key, usage_k, &k.ct).map(|_| ()),
            "sum" => checksum(&key, usage_k, b"hello").map(|_| ()),
            "ver" => verify_checksum_type(&key, usage_k, b"hello", 12, &k.mac),
            "prf" => prf(&key, b"test").map(|_| ()),
            other => panic!("{other}"),
        };
        assert_eq!(got, expect(word), "{op} under {name}, usage {usage}");
        n += 1;
    }
    // 53 keys: encrypt, decrypt, checksum and verify at three key usages, and the PRF once.
    assert_eq!(n, 53 * (4 * 3 + 1));
}

/// The first failing check decides: parity then weakness of the first DES key, then of the second, then of the third.
#[test]
fn the_checks_run_in_mits_order() {
    let k = kat();
    let want = [
        ("order-k0-weak-k1-badpar", Error::DesWeakKey),
        ("order-k0-badpar-k1-weak", Error::DesBadParity),
        ("order-k1-weak-k2-badpar", Error::DesWeakKey),
        ("order-k1-badpar-k2-weak", Error::DesBadParity),
        ("weak01-with-bad-octet-k0", Error::DesBadParity),
    ];
    for (name, err) in want {
        let key = of(&k, name);
        let usage = KeyUsage::new(1).expect("usage");
        assert_eq!(encrypt(&key, usage, &[0u8; 8]), Err(err.clone()), "{name}");
        assert_eq!(prf(&key, b"x"), Err(err), "{name}");
    }
}

/// The two-key layout (the third DES key the first) and the one-key layout are accepted when their parity is right: MIT's
/// `mit_des3_key_sched` does not compare the three keys.
#[test]
fn the_two_key_and_one_key_layouts_are_not_refused() {
    let k = kat();
    for name in ["two-key-k1k2k1", "one-key-k1k1k1", "good-rotated"] {
        let key = of(&k, name);
        encrypt(&key, KeyUsage::new(1).unwrap(), &[0u8; 8])
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

/// MIT's message for each code, which a tool prints and the KDC logs.
#[test]
fn the_refusals_read_as_mits_codes_do() {
    assert_eq!(Error::DesBadParity.to_string(), "DES key has bad parity");
    assert_eq!(Error::DesWeakKey.to_string(), "DES key is a weak key");
    for line in KAT.lines().filter(|l| l.starts_with("code ")) {
        let p: Vec<&str> = line.splitn(4, ' ').collect();
        match p[1] {
            "BAD_KEYPAR" => {
                assert_eq!(p[2], "-1765328198");
                assert_eq!(p[3], Error::DesBadParity.to_string());
            }
            "WEAK_KEY" => {
                assert_eq!(p[2], "-1765328197");
                assert_eq!(p[3], Error::DesWeakKey.to_string());
            }
            _ => {}
        }
    }
}

/// A key of any parity loads, as MIT's keytab, database and ticket readers load it; the refusal is at its use.
#[test]
fn a_key_of_bad_parity_loads() {
    let bad = [0u8; 24];
    let key = ProtocolKey::from_bytes(DES3, &bad).expect("loads");
    assert_eq!(key.as_bytes(), &bad);
    assert_eq!(
        checksum(&key, KeyUsage::new(6).unwrap(), b"x"),
        Err(Error::DesBadParity)
    );
}
