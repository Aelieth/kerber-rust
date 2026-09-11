//! A′-2 R19: TGS constraint slots before svc policy; rd_req times after BADMATCH/BADADDR.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{
    Error, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_TGT_BASED, KeyEntry,
    PacTicket, PrincipalStore, TEST_ADMIN, TEST_REALM, TEST_USER, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_admin_id, documented_host, handle_request_from,
    pa_enc_timestamp, random_key, sign_pac, ticket_checksum_der, wrap_win2k_pac,
};
use krb5_protocol::{tgs_req, tgs_req_ex};
use krb5_types::{
    EncTicketPart, EncryptedData, HostAddress, KdcOptions, KerberosTime, KrbError, PrincipalName,
    Ticket, err, flag_bit, ku,
};

const FOREIGN: &str = "OTHER.TEST";

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn issue_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn issue_host_tgt(store: &PrincipalStore, dest: &PrincipalName, nonce: u32) -> krb5_kdc::IssuedAs {
    let key = store
        .get_name(dest)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        dest.clone(),
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn reseal(ticket: &Ticket, part: &EncTicketPart, key: &ProtocolKey) -> Ticket {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut out = ticket.clone();
    out.enc_part.cipher = encrypt(key, usage, &der).unwrap().into();
    out
}

fn inet(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
    HostAddress {
        addr_type: HostAddress::ADDRTYPE_INET,
        address: vec![a, b, c, d].into(),
    }
}

fn err_of(bytes: &[u8]) -> (i32, String) {
    let e: KrbError = krb5_asn1::decode(bytes).unwrap();
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("")
        .to_owned();
    (e.error_code, text)
}

fn expire_tgt(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> Ticket {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).unwrap();
    part.endtime = KerberosTime::now().add_seconds(-3600).unwrap();
    reseal(&issued.rep.0.ticket, &part, &krbtgt.key)
}

fn pac_mismatch_tgt(store: &PrincipalStore, issued: &krb5_kdc::IssuedAs) -> Ticket {
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &issued.rep.0.ticket).unwrap();
    let ident = store.pac_identity(&part.cname, TEST_REALM);
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(&part).unwrap();
    let wrong = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
    let pac = sign_pac(
        &wrong,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: &krbtgt.key,
            kdc: &krbtgt.key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
    reseal(&issued.rep.0.ticket, &part, &krbtgt.key)
}

fn or_attrs(store: &mut PrincipalStore, name: &PrincipalName, bits: u32) {
    let attrs = store.get_name(name).unwrap().attributes | bits;
    store
        .apply_admin_fields(name, Some(attrs), None, None, None, None, false, None)
        .unwrap();
}

#[test]
fn a2_r19_locked_host_pac_mismatch_is_header_pac() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let dest = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "locked.kerber.test"]);
    store
        .create_host(&acl, &documented_admin_id(), &dest)
        .unwrap();
    or_attrs(&mut store, &dest, KDB_DISALLOW_ALL_TIX);
    let as_out = issue_tgt(&store, 19010);
    let tkt = pac_mismatch_tgt(&store, &as_out);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        19011,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &req).unwrap_err();
    assert_eq!(proto(&err), (err::BADOPTION, Some("HEADER_PAC")));
}

#[test]
fn a2_r19_dup_skey_beats_tgt_based() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let dest = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "dupskey.kerber.test"]);
    store
        .create_host(&acl, &documented_admin_id(), &dest)
        .unwrap();
    or_attrs(
        &mut store,
        &dest,
        KDB_DISALLOW_DUP_SKEY | KDB_DISALLOW_TGT_BASED,
    );
    let extra = issue_host_tgt(&store, &dest, 19020).rep.0.ticket;
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, 19021);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        19022,
        KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
        Some(vec![extra]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &req).unwrap_err();
    assert_eq!(proto(&err), (err::POLICY, Some("DUP_SKEY DISALLOWED")));
}

#[test]
fn a2_r19_lineage_before_u2u() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x44; 32]).unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    let as_out = issue_tgt(&store, 19030);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &as_out.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let header = Ticket {
        tkt_vno: as_out.rep.0.ticket.tkt_vno,
        realm: krb5_types::try_ascii(FOREIGN).unwrap(),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM]),
        enc_part: EncryptedData {
            etype: ir.etype().to_iana(),
            kvno: Some(1),
            cipher: encrypt(&ir, usage, &der).unwrap().into(),
        },
    };
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = {
        let key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            admin,
            TEST_REALM,
            19031,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&store, &req).unwrap().rep.0.ticket
    };
    let req = tgs_req_ex(
        header,
        &as_out.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19032,
        KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
        Some(vec![admin_tgt]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &req).unwrap_err();
    assert_eq!(proto(&err), (err::POLICY, Some("INVALID LINEAGE")));
}

#[test]
fn a2_r19_expired_caddr_is_badaddr() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 19040);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.endtime = KerberosTime::now().add_seconds(-3600).unwrap();
    part.caddr = Some(vec![inet(10, 0, 0, 1)]);
    let tkt = reseal(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19041,
    )
    .unwrap();
    let bytes =
        handle_request_from(&store, &encode(&req).unwrap(), Some(&inet(192, 0, 2, 1))).unwrap();
    let (code, text) = err_of(&bytes);
    assert_eq!(code, err::BADADDR);
    assert_eq!(text, "PROCESS_TGS");
}

#[test]
fn a2_r19_expired_authenticator_mismatch_is_badmatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, 19050);
    let tkt = expire_tgt(&store, &as_out);
    let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let req = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &other,
        documented_host(),
        TEST_REALM,
        19051,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &req).unwrap_err();
    assert_eq!(proto(&err), (err::BADMATCH, Some("PROCESS_TGS")));
}

#[test]
fn a2_r19_renew_pac_service_after_krbtgt_enctype_rekey() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let as_out = {
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let mut req = as_req(
            user,
            TEST_REALM,
            19060,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        req.0.req_body.kdc_options = req
            .0
            .req_body
            .kdc_options
            .with_bit(flag_bit::RENEWABLE, true);
        krb5_kdc::issue_as(&store, &req).unwrap()
    };
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let first = tgs_req_ex(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19061,
        KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let svc = krb5_kdc::issue_tgs(&store, &first).unwrap();
    let aes128 = random_key(EncryptionType::Aes128CtsHmacSha196).unwrap();
    store
        .set_keys(
            &PrincipalName::krbtgt(TEST_REALM),
            vec![KeyEntry::new(
                EncryptionType::Aes128CtsHmacSha196,
                aes128,
                0,
            )],
            1,
        )
        .unwrap();
    let renew = tgs_req_ex(
        svc.rep.0.ticket,
        &svc.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19062,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &renew).expect("RENEW after krbtgt enctype rekey");
}
