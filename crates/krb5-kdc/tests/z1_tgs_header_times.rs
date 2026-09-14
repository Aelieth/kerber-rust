//! Z1.3 follow-up: the KDC's header-ticket time check is `krb5int_validate_times`
//! too (`kdc_util.c` `kdc_rd_ap_req` → `krb5_rd_req_decoded_anyflag` →
//! `rd_req_dec.c:627` → `valid_times.c:44-51`): a TGT with no `starttime` is
//! judged by its `authtime`. Compiles at the parent `284ec70` and fails there —
//! `check_header_times_rd_req` only tested NYV when `starttime` was present, so
//! a resealed TGT with a future `authtime` and no `starttime` was accepted.

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, encrypt};
use krb5_kdc::{
    PrincipalStore, TEST_REALM, TEST_USER, as_req, bootstrap_documented, decrypt_ticket_part,
    documented_host, pa_enc_timestamp,
};
use krb5_protocol::tgs_req;
use krb5_types::{EncTicketPart, KerberosTime, PaData, PaPacRequest, PrincipalName, err, ku, pa};

fn user_key(store: &PrincipalStore) -> krb5_crypto::ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone()
}

/// Reseal the TGT under the krbtgt key after `mutate` rewrote its
/// `EncTicketPart` (the session key is untouched, so the TGS-REQ authenticator
/// still verifies).
fn reseal_tgt(
    store: &PrincipalStore,
    ticket: &krb5_types::Ticket,
    mutate: impl FnOnce(&mut EncTicketPart),
) -> krb5_types::Ticket {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&key.key, ticket).unwrap();
    mutate(&mut part);
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut out = ticket.clone();
    out.enc_part.cipher = encrypt(&key.key, usage, &der).unwrap().into();
    out
}

#[test]
fn z1_tgs_header_tgt_without_starttime_and_future_authtime_is_nyv() {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    // PA-PAC-REQUEST false: a PAC-bearing TGT would fail HEADER_PAC on the
    // rewritten authtime before any time check could be reached, masking the
    // laxness this unit pins (MIT validates times in rd_req, before the PAC).
    let padata = vec![
        pa_enc_timestamp(&user_key(&store)).unwrap(),
        PaData {
            padata_type: pa::PAC_REQUEST,
            padata_value: encode(&PaPacRequest { include_pac: false }).unwrap().into(),
        },
    ];
    let req = as_req(cname.clone(), TEST_REALM, 0x2600_0001, Some(padata)).unwrap();
    let tgt = krb5_kdc::issue_as(&store, &req).unwrap();

    // Control: the untouched TGT gets a host ticket.
    let ok_req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2600_0002,
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &ok_req).expect("control TGS issues");

    // valid_times.c:44-46 starttime == 0 → authtime; :47-51 far-future → NYV.
    let far = KerberosTime::now()
        .add_seconds(store.policy().skew + 3600)
        .unwrap();
    let forged = reseal_tgt(&store, &tgt.rep.0.ticket, |part| {
        part.starttime = None;
        part.authtime = far.clone();
    });
    let req = tgs_req(
        forged,
        &tgt.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2600_0003,
    )
    .unwrap();
    match krb5_kdc::issue_tgs(&store, &req) {
        Err(krb5_kdc::Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::TKT_NYV, "KRB5KRB_AP_ERR_TKT_NYV, got {text:?}");
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        Err(other) => panic!("expected 33 PROCESS_TGS, got {other:?}"),
        Ok(_) => panic!("a TGT with no starttime and a future authtime must be NYV"),
    }
}
