//! Z6.1: FAST armor-TGT decrypt is MIT `krb5_ktkdb_get_entry`
//! (`lib/kdb/keytab.c:157`) — `krb5_dbe_find_enctype(entry, xrealm ? etype : -1,
//! -1, kvno)` pins the ticket kvno and skips non-permitted enctypes; a local
//! TGS whose first permitted key is not similar to the ticket etype is
//! `KRB5_KDB_NO_PERMITTED_KEY` → wire 60 `FIND_FAST` (`fast_util.c:52-59`,
//! `errcode_to_protocol`). Compiles at the parent and fails there:
//! `armor_key_from_ap` iterated every krbtgt key unfiltered.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::{
    KeyEntry, PrincipalStore, TEST_REALM, TEST_USER, as_req, bootstrap_documented,
    pa_enc_timestamp, random_key,
};
use krb5_protocol::{armor_key, attach_fast, build_fast_armor};
use krb5_types::{EncTicketPart, PrincipalName, Ticket, ascii, err, ku};

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha196;
const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

fn user_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn store_permitting_aes256() -> PrincipalStore {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(store.policy().etype_permitted(AES256));
    assert!(!store.policy().etype_permitted(AES128));
    store
}

fn set_krbtgt_keys(store: &mut PrincipalStore, keys: Vec<KeyEntry>, keepold: u32) {
    store
        .set_keys(&PrincipalName::krbtgt(TEST_REALM), keys, keepold)
        .unwrap();
}

fn issue_user_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let key = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .find(|k| k.etype == AES256)
        .expect("user aes256")
        .key
        .clone();
    let req = as_req(
        user_name(),
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS issues")
}

fn reseal_ticket(ticket: &Ticket, old: &ProtocolKey, new: &ProtocolKey) -> Ticket {
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(old, usage, ticket.enc_part.cipher.as_ref()).expect("decrypt tkt");
    let part: EncTicketPart = decode(&plain).expect("enc-tkt");
    let der = encode(&part).expect("re-encode");
    let cipher = encrypt(new, usage, &der).expect("reseal");
    let mut out = ticket.clone();
    out.enc_part.cipher = cipher.into();
    out.enc_part.etype = new.etype().to_iana();
    out
}

fn fast_as_with_armor_ticket(
    store: &PrincipalStore,
    ticket: Ticket,
    session: &ProtocolKey,
    nonce: u32,
) -> Result<krb5_kdc::IssuedAs, krb5_kdc::Error> {
    let sub = ProtocolKey::from_bytes(AES256, &[0x61u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        ticket,
        session,
        &ascii(TEST_REALM),
        &user_name(),
        Some(&sub),
    )
    .expect("armor AP-REQ");
    let akey = armor_key(session, Some(&sub)).expect("armor key");
    let user_key = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .find(|k| k.etype == AES256)
        .expect("user aes256")
        .key
        .clone();
    let mut req = as_req(user_name(), TEST_REALM, nonce, None).unwrap();
    attach_fast(
        &mut req,
        &armor_ap,
        &akey,
        vec![pa_enc_timestamp(&user_key).unwrap()],
    )
    .expect("FAST wrap");
    krb5_kdc::issue_as(store, &req)
}

fn assert_find_fast(err: krb5_kdc::Error, code: i32) {
    match err {
        krb5_kdc::Error::Protocol {
            code: got,
            text,
            detail,
            ..
        } => {
            assert_eq!(got, code, "wire code, detail={detail:?}");
            assert_eq!(text.as_deref(), Some("FIND_FAST"));
            assert_eq!(detail.as_deref(), Some("FAST armor TGT"));
        }
        other => panic!("expected {code} FIND_FAST, got {other:?}"),
    }
}

/// `keytab.c:157` + `:171-178`: an armor TGT sealed under a non-permitted
/// enctype (aes128 while `permitted_enctypes = aes256`) is 60 `FIND_FAST`,
/// not decrypted with the leftover aes128 krbtgt key.
#[test]
fn z6_armor_tgt_under_a_non_permitted_etype_is_generic_find_fast() {
    let mut store = store_permitting_aes256();
    set_krbtgt_keys(
        &mut store,
        vec![
            KeyEntry::new(AES128, random_key(AES128).unwrap(), 0),
            KeyEntry::new(AES256, random_key(AES256).unwrap(), 0),
        ],
        0,
    );
    let tgt = issue_user_tgt(&store, 0x2600_0061);
    assert_eq!(tgt.rep.0.ticket.enc_part.etype, AES256.to_iana());
    let krbtgt = store.get_name(&PrincipalName::krbtgt(TEST_REALM)).unwrap();
    let aes128 = krbtgt.keys.iter().find(|k| k.etype == AES128).unwrap();
    let aes256 = krbtgt.keys.iter().find(|k| k.etype == AES256).unwrap();
    let forged = reseal_ticket(&tgt.rep.0.ticket, &aes256.key, &aes128.key);
    assert_eq!(forged.enc_part.etype, AES128.to_iana());
    let err = fast_as_with_armor_ticket(&store, forged, &tgt.session_key, 0x2600_0062)
        .expect_err("non-permitted armor etype");
    assert_find_fast(err, err::GENERIC);
}

/// `keytab.c:157` pins the ticket kvno. A TGT labelled kvno N sealed under
/// kvno N+1 decrypts under the old walk and is `BAD_INTEGRITY` 31 once the
/// lookup is pinned (`rd_req_dec.c:344-345` after a successful `kt_get_entry`).
#[test]
fn z6_armor_tgt_labelled_n_sealed_under_n_plus_1_is_bad_integrity() {
    let (mut store, _) = bootstrap_documented().unwrap();
    set_krbtgt_keys(
        &mut store,
        vec![KeyEntry::new(AES256, random_key(AES256).unwrap(), 0)],
        0,
    );
    set_krbtgt_keys(
        &mut store,
        vec![KeyEntry::new(AES256, random_key(AES256).unwrap(), 0)],
        1,
    );
    let tgt = issue_user_tgt(&store, 0x2600_0065);
    let krbtgt = store.get_name(&PrincipalName::krbtgt(TEST_REALM)).unwrap();
    let top = krbtgt.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(top >= 2, "keepold must leave two kvnos, top={top}");
    let mut mislabelled = tgt.rep.0.ticket.clone();
    mislabelled.enc_part.kvno = Some(top - 1);
    let err = fast_as_with_armor_ticket(&store, mislabelled, &tgt.session_key, 0x2600_0066)
        .expect_err("mislabelled kvno");
    assert_find_fast(err, err::BAD_INTEGRITY);
}
