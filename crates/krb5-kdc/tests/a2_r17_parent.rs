//! R17 statuses that fail at parent `a40c63e` (inject this file only).

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{
    PrincipalStore, TEST_ADMIN, TEST_REALM, as_req, bootstrap_documented, decrypt_ticket_part,
    documented_admin_id, documented_host, pa_enc_timestamp,
};
use krb5_protocol::{pa_for_user, tgs_req_ex};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, err};

const FOREIGN: &str = "OTHER.TEST";

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn host_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        host,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn code(e: krb5_kdc::Error) -> (i32, Option<String>) {
    match e {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a2_r17_create_host_has_no_s4u_to_targets() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = store.get_name(&documented_host()).expect("host");
    assert!(host.s4u_allowed_to.is_empty());
}

#[test]
fn a2_r17_s4u2self_keeps_f_without_clearing_targets() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17100);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let host = documented_host();
    let req = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        17101,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &req).unwrap();
    let hostk = store.get_name(&host).unwrap().best_key().unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert!(part.flags.forwardable());
}

#[test]
fn a2_r17_explicit_cross_tgs_is_server_mismatch() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x11; 32]).unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir)
        .unwrap();
    let tgt = host_tgt(&store, 17110);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let host = documented_host();
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", FOREIGN]);
    let req = tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        other,
        TEST_REALM,
        17111,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADMATCH);
    assert_eq!(
        text.as_deref(),
        Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
    );
}
