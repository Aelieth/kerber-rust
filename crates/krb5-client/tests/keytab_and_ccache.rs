//! Keytab v2 and FILE ccache round-trips through the shipped serializers.

use krb5_client::{parse_principal, Keytab};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{ascii, PrincipalName};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn keytab_v2_round_trip_preserves_key_bytes() {
    let key_bytes = hex("42263c6e89f4fc28b8df68ee09799f15");
    let key = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &key_bytes).unwrap();
    let kt = Keytab::single(
        ascii("KERBER.TEST"),
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        3,
        key,
    );
    let bytes = kt.to_bytes();
    assert_eq!(bytes[0], 0x05);
    assert_eq!(bytes[1], 0x02);
    let parsed = Keytab::parse(&bytes).unwrap();
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].kvno, 3);
    assert_eq!(parsed.entries[0].key.as_bytes(), key_bytes.as_slice());
    assert_eq!(
        parsed.entries[0].key.etype(),
        EncryptionType::Aes128CtsHmacSha196
    );
}

#[test]
fn parse_principal_splits_realm() {
    let (n, r) = parse_principal("user@KERBER.TEST").unwrap();
    assert_eq!(r, "KERBER.TEST");
    assert_eq!(n.name_type, PrincipalName::NT_PRINCIPAL);
}

#[test]
fn truncated_keytab_is_error() {
    assert!(Keytab::parse(&[0x05, 0x03]).is_err());
    assert!(Keytab::parse(&[0x05, 0x01]).is_ok()); // empty v1 is valid
    let mut truncated = vec![0x05, 0x02];
    truncated.extend_from_slice(&20i32.to_be_bytes());
    truncated.push(0);
    assert!(Keytab::parse(&truncated).is_err());
}
