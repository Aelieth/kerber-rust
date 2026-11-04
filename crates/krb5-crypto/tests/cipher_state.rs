use krb5_crypto::{
    CipherState, EncryptionType, Error, KeyUsage, ProtocolKey, decrypt, decrypt_with_state,
    encrypt_with_confounder, encrypt_with_confounder_and_state,
};

const KAT: &str = include_str!("data/mit-cipher-state.kat");

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

struct Single {
    conf: Vec<u8>,
    plain: Vec<u8>,
    cipher: Vec<u8>,
}

struct Message {
    conf: Vec<u8>,
    plain: Vec<u8>,
    cipher: Vec<u8>,
    state: [u8; 16],
    tamper: Option<(Vec<u8>, [u8; 16])>,
}

struct Chain {
    etype: i32,
    key: Vec<u8>,
    state0: [u8; 16],
    singles: Vec<Single>,
    messages: Vec<Message>,
}

impl Chain {
    fn key(&self) -> ProtocolKey {
        ProtocolKey::from_bytes(EncryptionType::known(self.etype).unwrap(), &self.key).unwrap()
    }
}

fn chains() -> Vec<Chain> {
    let mut out = Vec::new();
    let mut cur: Option<Chain> = None;
    let mut conf = Vec::new();
    let mut plain = Vec::new();
    let mut cipher = Vec::new();
    for line in KAT.lines() {
        let (tag, rest) = line.split_once(' ').unwrap_or((line, ""));
        match tag {
            "etype" => {
                cur = Some(Chain {
                    etype: rest.parse().expect("etype"),
                    key: Vec::new(),
                    state0: [0; 16],
                    singles: Vec::new(),
                    messages: Vec::new(),
                });
            }
            "key" => cur.as_mut().expect("etype first").key = hex(rest),
            "state0" => cur.as_mut().expect("etype first").state0 = hex(rest).try_into().unwrap(),
            "single" => {
                let f: Vec<&str> = rest.split(' ').collect();
                assert_eq!(f.len(), 3, "single {rest:?}");
                cur.as_mut().expect("etype first").singles.push(Single {
                    conf: hex(f[0]),
                    plain: hex(f[1]),
                    cipher: hex(f[2]),
                });
            }
            "conf" => conf = hex(rest),
            "plain" => plain = hex(rest),
            "cipher" => cipher = hex(rest),
            "state" => cur.as_mut().expect("etype first").messages.push(Message {
                conf: std::mem::take(&mut conf),
                plain: std::mem::take(&mut plain),
                cipher: std::mem::take(&mut cipher),
                state: hex(rest).try_into().unwrap(),
                tamper: None,
            }),
            "tamper" => {
                let (bad, left) = rest.split_once(' ').expect("tamper CIPHER STATE");
                cur.as_mut()
                    .expect("etype first")
                    .messages
                    .last_mut()
                    .expect("a message first")
                    .tamper = Some((hex(bad), hex(left).try_into().unwrap()));
            }
            "end" => out.extend(cur.take()),
            _ => panic!("unknown line {line:?}"),
        }
    }
    out
}

fn krb_priv_usage() -> KeyUsage {
    KeyUsage::new(13).unwrap()
}

#[test]
fn a_message_sealed_alone_is_byte_for_byte_mits() {
    for chain in chains() {
        let key = chain.key();
        for (i, s) in chain.singles.iter().enumerate() {
            let sealed = encrypt_with_confounder(&key, krb_priv_usage(), &s.conf, &s.plain)
                .unwrap_or_else(|e| panic!("etype {} single {i}: {e}", chain.etype));
            assert_eq!(
                sealed,
                s.cipher,
                "etype {} single {i} ({} octets of data)",
                chain.etype,
                s.plain.len()
            );
            let plain = decrypt(&key, krb_priv_usage(), &s.cipher)
                .unwrap_or_else(|e| panic!("etype {} single {i}: {e}", chain.etype));
            assert_eq!(plain, s.plain, "etype {} single {i}", chain.etype);
        }
    }
}

#[test]
fn a_chain_mit_sealed_decrypts_and_leaves_mits_state() {
    for chain in chains() {
        let key = chain.key();
        let mut state = CipherState { iv: chain.state0 };
        for (i, m) in chain.messages.iter().enumerate() {
            let plain = decrypt_with_state(&key, krb_priv_usage(), &mut state, &m.cipher)
                .unwrap_or_else(|e| panic!("etype {} message {i}: {e}", chain.etype));
            assert_eq!(plain, m.plain, "etype {} message {i}", chain.etype);
            assert_eq!(
                state.iv, m.state,
                "etype {} message {i}: the state",
                chain.etype
            );
        }
    }
}

#[test]
fn a_chain_sealed_with_mits_confounders_is_mits_bytes_and_state() {
    for chain in chains() {
        let key = chain.key();
        let mut state = CipherState { iv: chain.state0 };
        for (i, m) in chain.messages.iter().enumerate() {
            let sealed = encrypt_with_confounder_and_state(
                &key,
                krb_priv_usage(),
                &m.conf,
                &mut state,
                &m.plain,
            )
            .unwrap_or_else(|e| panic!("etype {} message {i}: {e}", chain.etype));
            assert_eq!(
                sealed,
                m.cipher,
                "etype {} message {i} ({} octets of data): the bytes",
                chain.etype,
                m.plain.len()
            );
            assert_eq!(
                state.iv, m.state,
                "etype {} message {i}: the state",
                chain.etype
            );
        }
    }
}

#[test]
fn a_message_failing_its_integrity_check_leaves_the_state_mit_leaves() {
    for chain in chains() {
        let key = chain.key();
        let aes_sha2 = matches!(chain.etype, 19 | 20);
        let mut before = chain.state0;
        let mut tried = 0;
        for (i, m) in chain.messages.iter().enumerate() {
            if let Some((bad, left)) = &m.tamper {
                let mut state = CipherState { iv: before };
                let err = decrypt_with_state(&key, krb_priv_usage(), &mut state, bad)
                    .expect_err("an altered MAC must not verify");
                assert!(
                    matches!(err, Error::Integrity),
                    "etype {} message {i}: {err}",
                    chain.etype
                );
                assert_eq!(
                    state.iv, *left,
                    "etype {} message {i}: the state",
                    chain.etype
                );
                let moved = !aes_sha2 && !m.plain.is_empty();
                assert_eq!(*left != before, moved, "etype {} message {i}", chain.etype);
                tried += 1;
            }
            before = m.state;
        }
        assert_eq!(tried, 3, "etype {}", chain.etype);
    }
}
