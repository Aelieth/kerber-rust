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
    ct: Vec<u8>,
    mac: Vec<u8>,
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

fn expect(word: &str) -> Result<(), Error> {
    match word {
        "OK" => Ok(()),
        "BAD_KEYPAR" => Err(Error::DesBadParity),
        "WEAK_KEY" => Err(Error::DesWeakKey),
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
    assert_eq!(n, 53 * (4 * 3 + 1));
}

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
