//! W1-B B1: `vfy_increds.c` `krb5_verify_init_creds`.
//! Live oracle: `client-differential-gate.sh` vs MIT `t_vfy_increds`.

#[path = "common/mod.rs"]
mod common;
use common::client_key;

use krb5_kdc::{
    TEST_REALM, TEST_USER, as_req, bootstrap_documented, documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::{
    CcacheCred, CcacheKeyblock, KdcAddr, Keytab, host_princs_from_keytab, keytab_has_server, realm,
    tgt_cred, verify_init_creds, verify_init_creds_nofail,
};
use krb5_types::{EncKdcRepPart, EncryptionKey, KerberosTime, PrincipalName, TicketFlags, ascii};

fn dummy_cred() -> CcacheCred {
    CcacheCred {
        client: (
            realm(TEST_REALM),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        ),
        server: (realm(TEST_REALM), PrincipalName::krbtgt(TEST_REALM)),
        key: CcacheKeyblock {
            etype: 0,
            contents: Vec::new(),
        },
        authtime: 1,
        starttime: 1,
        endtime: u32::MAX,
        renew_till: 0,
        is_skey: 0,
        ticket_flags: 0,
        addresses: Vec::new(),
        authdata: Vec::new(),
        ticket: Vec::new(),
        second_ticket: Vec::new(),
    }
}

fn dummy_kdc() -> KdcAddr {
    KdcAddr::new("127.0.0.1")
}

#[test]
fn b1_vfy_increds_opt_overrides_conf() {
    assert!(verify_init_creds_nofail(Some(true), false));
    assert!(!verify_init_creds_nofail(Some(false), true));
    assert!(verify_init_creds_nofail(None, true));
    assert!(!verify_init_creds_nofail(None, false));
}

#[test]
fn b1_vfy_increds_missing_keytab_succeeds_unless_nofail() {
    let cred = dummy_cred();
    let kdc = dummy_kdc();
    verify_init_creds(&cred, None, None, &kdc, false).unwrap();
    assert!(verify_init_creds(&cred, None, None, &kdc, true).is_err());
}

#[test]
fn b1_vfy_increds_nfs_only_is_no_host_keys() {
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["nfs", "vfy.kerber.test"]);
    let key = client_key();
    let kt = Keytab::single(realm(TEST_REALM), host.clone(), 1, key);
    assert!(host_princs_from_keytab(&kt).is_empty());
    assert!(keytab_has_server(&kt, &realm(TEST_REALM), &host));
    let cred = dummy_cred();
    let kdc = dummy_kdc();
    verify_init_creds(&cred, None, Some(&kt), &kdc, false).unwrap();
    assert!(verify_init_creds(&cred, None, Some(&kt), &kdc, true).is_err());
}

#[test]
fn b1_vfy_increds_unknown_server_succeeds_unless_nofail() {
    let host = documented_host();
    let other = PrincipalName::new(PrincipalName::NT_SRV_HST, ["nfs", "vfy.kerber.test"]);
    let kt = Keytab::single(realm(TEST_REALM), host, 1, client_key());
    let cred = dummy_cred();
    let kdc = dummy_kdc();
    verify_init_creds(
        &cred,
        Some((&realm(TEST_REALM), &other)),
        Some(&kt),
        &kdc,
        false,
    )
    .unwrap();
    assert!(
        verify_init_creds(
            &cred,
            Some((&realm(TEST_REALM), &other)),
            Some(&kt),
            &kdc,
            true
        )
        .is_err()
    );
}

#[test]
fn b1_vfy_increds_matching_service_ticket_verifies() {
    let (store, acl) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        21,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let host = documented_host();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        host.clone(),
        TEST_REALM,
        22,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let now = KerberosTime::now();
    let enc = EncKdcRepPart {
        key: EncryptionKey {
            keytype: tgs_out.session_key.etype().to_iana(),
            keyvalue: tgs_out.session_key.as_bytes().to_vec().into(),
        },
        last_req: Vec::new(),
        nonce: 0,
        key_expiration: None,
        flags: TicketFlags::from_u32(0),
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: now,
        renew_till: None,
        srealm: ascii(TEST_REALM),
        sname: host.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let cred = tgt_cred(
        &ascii(TEST_REALM),
        &cname,
        &tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &enc,
    )
    .unwrap();
    let kt = store
        .export_keytab(&acl, &krb5_kdc::documented_admin_id(), &host)
        .unwrap();
    let kdc = dummy_kdc();
    verify_init_creds(
        &cred,
        Some((&ascii(TEST_REALM), &host)),
        Some(&kt),
        &kdc,
        true,
    )
    .unwrap();
}

#[test]
fn b1_vfy_increds_wrong_keytab_is_err() {
    let (store, acl) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        23,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let host = documented_host();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        host.clone(),
        TEST_REALM,
        24,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let now = KerberosTime::now();
    let enc = EncKdcRepPart {
        key: EncryptionKey {
            keytype: tgs_out.session_key.etype().to_iana(),
            keyvalue: tgs_out.session_key.as_bytes().to_vec().into(),
        },
        last_req: Vec::new(),
        nonce: 0,
        key_expiration: None,
        flags: TicketFlags::from_u32(0),
        authtime: now.clone(),
        starttime: Some(now.clone()),
        endtime: now,
        renew_till: None,
        srealm: ascii(TEST_REALM),
        sname: host.clone(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let cred = tgt_cred(
        &ascii(TEST_REALM),
        &cname,
        &tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &enc,
    )
    .unwrap();
    let good = store
        .export_keytab(&acl, &krb5_kdc::documented_admin_id(), &host)
        .unwrap();
    let mut bad = good;
    for e in &mut bad.entries {
        e.key = client_key();
    }
    let kdc = dummy_kdc();
    assert!(
        verify_init_creds(
            &cred,
            Some((&ascii(TEST_REALM), &host)),
            Some(&bad),
            &kdc,
            true
        )
        .is_err()
    );
}
