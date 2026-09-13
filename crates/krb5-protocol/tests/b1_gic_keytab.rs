//! W1-B B1: `gic_keytab.c` highest kvno + etype sort.
//! Live oracle: `client-differential-gate.sh` two-kvno `kinit -k`.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_protocol::{Keytab, KeytabEntry, keytab_init_creds_keys, sort_etypes_keytab_first};
use krb5_types::{PrincipalName, ascii};

fn entry(realm: &str, name: &str, kvno: u32, key: &[u8], etype: EncryptionType) -> KeytabEntry {
    KeytabEntry {
        realm: ascii(realm),
        name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]),
        timestamp: 1,
        kvno,
        key: ProtocolKey::from_bytes(etype, key).expect("key"),
    }
}

fn sample_kt() -> Keytab {
    Keytab {
        version: 0x0502,
        entries: vec![
            entry(
                "KERBER.TEST",
                "user",
                1,
                &[1u8; 32],
                EncryptionType::Aes256CtsHmacSha196,
            ),
            entry(
                "OTHER.TEST",
                "user",
                9,
                &[9u8; 32],
                EncryptionType::Aes256CtsHmacSha196,
            ),
            entry(
                "KERBER.TEST",
                "user",
                2,
                &[2u8; 16],
                EncryptionType::Aes128CtsHmacSha196,
            ),
            entry(
                "KERBER.TEST",
                "user",
                2,
                &[3u8; 32],
                EncryptionType::Aes256CtsHmacSha196,
            ),
        ],
        skipped_unknown_etype: 0,
        unparsed: vec![],
    }
}

#[test]
fn b1_gic_keytab_uses_highest_kvno_only() {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let (keys, etypes) = keytab_init_creds_keys(&sample_kt(), &user, "KERBER.TEST").expect("keys");
    assert_eq!(keys.len(), 2, "both etypes at kvno 2");
    assert_eq!(etypes, vec![17, 18]);
    assert_eq!(keys[0].as_bytes(), &[2u8; 16]);
    assert_eq!(keys[1].as_bytes(), &[3u8; 32]);
}

#[test]
fn b1_gic_keytab_wrong_realm_is_ignored() {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let (keys, _) = keytab_init_creds_keys(&sample_kt(), &user, "KERBER.TEST").expect("keys");
    assert!(keys.iter().all(|k| k.as_bytes() != [9u8; 32]));
}

#[test]
fn b1_gic_keytab_unknown_principal_is_none() {
    let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
    assert!(keytab_init_creds_keys(&sample_kt(), &other, "KERBER.TEST").is_none());
}

#[test]
fn b1_gic_keytab_sort_moves_keytab_etypes_front() {
    let mut req = [18, 17, 20, 19];
    sort_etypes_keytab_first(&mut req, &[17]);
    assert_eq!(req, [17, 18, 20, 19]);
}
