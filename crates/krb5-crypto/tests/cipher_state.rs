//! MIT 1.22.2's AES and Camellia encryption as its own libkrb5 does it: a message sealed alone, the cipher
//! state that chains one message to the next, and the state a message that fails its integrity check leaves.
//!
//! `data/mit-cipher-state.kat` is the output of the C program beside it (`data/mit-cipher-state`'s source) run on
//! `kerber-rust-mit-kdc:1.22.2`. For each AES and Camellia enctype it holds a fixed key and
//!  - messages that `krb5_c_encrypt` seals alone, with no cipher state, as a ticket or an authenticator is,
//!    with the confounder it drew (`single`);
//!  - a chain of messages that `krb5_c_encrypt` seals under one cipher state, with the confounder it drew and
//!    the state after each: kprop and kpropd seal their KRB-PRIV blocks that way, one state for the dump;
//!  - for some of those, the ciphertext with its last octet changed and the state `krb5_c_decrypt` leaves
//!    when it fails its integrity check (`tamper`).
//!
//! MIT `krb5int_aes_encrypt` (`lib/crypto/builtin/enc_provider/aes.c:239-298`): a message of one block is one CBC block under a zero IV and leaves the state as it was; any other leaves the first of the last two blocks of the stream, `C_n` of the ciphertext stealing.
//! MIT `krb5int_aes_decrypt` (`lib/crypto/builtin/enc_provider/aes.c:301-370`): decrypting leaves the same block.
//! MIT `krb5int_dk_decrypt` (`lib/crypto/krb/enc_dk_hmac.c:246-259`): the provider decrypts, and so takes the state, before the hash is compared.
//! MIT `krb5int_dk_cmac_decrypt` (`lib/crypto/krb/enc_dk_cmac.c:163-174`): the same for Camellia, before the CMAC is compared.
//! MIT `krb5int_etm_decrypt` (`lib/crypto/krb/enc_etm.c:238-250`): the MAC, which covers the state the message began with, is compared before the decrypt.

use krb5_crypto::{
    CipherState, EncryptionType, Error, KeyUsage, ProtocolKey, decrypt, decrypt_with_state,
    encrypt_with_confounder, encrypt_with_confounder_and_state,
};

const KAT: &str = include_str!("data/mit-cipher-state.kat");

/// The octets of `s`; "-" is none.
fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A message sealed alone.
struct Single {
    conf: Vec<u8>,
    plain: Vec<u8>,
    cipher: Vec<u8>,
}

struct Message {
    /// The confounder MIT drew for it.
    conf: Vec<u8>,
    plain: Vec<u8>,
    cipher: Vec<u8>,
    state: [u8; 16],
    /// The ciphertext with its last octet changed, and the state MIT's decrypt of it left, from the state
    /// the message began with.
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
    // KRB5_KEYUSAGE_KRB_PRIV_ENCPART
    KeyUsage::new(13).unwrap()
}

/// A message MIT sealed alone opens here, and given the confounder MIT drew this side seals the same bytes:
/// the common case, a ticket or an authenticator, which starts from no state and keeps none. It does not touch
/// the cipher state, so it is as green before the state was chained as after.
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

/// A chain MIT sealed decrypts message by message, and each decrypt leaves the state MIT's did.
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

/// A chain sealed here from the state MIT began with, with the confounders MIT drew, is MIT's bytes and leaves
/// MIT's state after each message: the encrypt side of the chain, for the aes-sha1, aes-sha2 and Camellia paths
/// alike.
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

/// A message that fails its integrity check leaves the state MIT leaves: the aes-sha1 and Camellia decrypts
/// have taken it by the time they compare the hash, the aes-sha2 decrypt compares the MAC first and leaves it,
/// and a message of one block leaves it either way.
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
                // What MIT's data says, for the reader: moved except for aes-sha2 and for one block.
                let moved = !aes_sha2 && !m.plain.is_empty();
                assert_eq!(*left != before, moved, "etype {} message {i}", chain.etype);
                tried += 1;
            }
            before = m.state;
        }
        assert_eq!(tried, 3, "etype {}", chain.etype);
    }
}
