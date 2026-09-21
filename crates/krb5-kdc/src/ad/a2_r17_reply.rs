use super::*;
use krb5_types::s4u::{PaS4uX509User, S4uUserId, s4u_reply_key_usage_flags};

#[test]
fn reply_130_omits_subject_cert() {
    let key =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42; 32]).expect("key");
    let req = PaS4uX509User {
        user_id: S4uUserId {
            nonce: 1,
            user: Some(PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"])),
            realm: krb5_types::try_ascii("KERBER.TEST").expect("realm"),
            subject_cert: Some(b"cert".to_vec().into()),
            options: Some(s4u_reply_key_usage_flags()),
        },
        cksum: krb5_types::Checksum {
            cksumtype: key.etype().checksum_type(),
            checksum: vec![0; 12].into(),
        },
    };
    let (pa, _) = make_s4u2self_rep(&req, &key, None).expect("rep");
    let rep: PaS4uX509User = decode(pa.padata_value.as_ref()).expect("decode");
    assert!(rep.user_id.subject_cert.is_none());
    assert_eq!(rep.user_id.nonce, 1);
    assert!(rep.user_id.use_reply_key_usage());
}
