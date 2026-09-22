//! A′-2 item 6: TGS gather order, `is_crossrealm`, constraints skeleton, header PAC.
//! A′-2 item 6 PAC-shape units that need APIs parent `2e5995a` does not export.
//! A′-2 R19: TGS constraint slots before svc policy; rd_req times after BADMATCH/BADADDR.
//! Remaining `GET_LOCAL_TGT` sites (`ad.rs` S4U2Proxy PAC) wire 60,
//! and `kdc_rd_ap_req` kvno 0 decrypts the previous kvno (`kdc_util.c:325-346`).

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    bootstrap_documented, documented_admin_id, documented_host,
};
use krb5_kdc::{
    Error, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED,
    KdcEnv, KeyEntry, PacTicket, Policy, Principal, PrincipalRead, PrincipalStore,
    decrypt_ticket_part, handle_request_from, pac_from_ticket_part, random_key, sign_pac,
    ticket_checksum_der, wrap_win2k_pac,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_testkit::{
    TgsReqBuilder, err_of, issue_tgt, issue_tgt_password, password_key, pref_etypes, reseal, status,
};
use krb5_types::pac::{PAC_SERVER_CHECKSUM, Pac, RpcSid};
use krb5_types::{
    EncTicketPart, EncryptedData, HostAddress, KdcOptions, KerberosTime, KrbError, PrincipalName,
    Ticket, err, flag_bit, ku,
};

fn renewable_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let mut req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::RENEWABLE, true);
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn rewrap(
    ticket: &krb5_types::Ticket,
    part: &EncTicketPart,
    key: &ProtocolKey,
) -> krb5_types::Ticket {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut out = ticket.clone();
    out.enc_part.cipher = encrypt(key, usage, &der).unwrap().into();
    out
}

fn host_tgs(issued: &krb5_kdc::IssuedAs, nonce: u32) -> krb5_types::TgsReq {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    tgs_req(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        nonce,
    )
    .unwrap()
}

#[test]
fn tgs_renew_service_ticket_issues() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = renewable_tgt(&store, 6010);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let first = TgsReqBuilder::new(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6011,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let svc = krb5_kdc::issue_tgs(&store, &first).unwrap();
    let renew = TgsReqBuilder::new(
        svc.rep.0.ticket.clone(),
        &svc.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6012,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    krb5_kdc::issue_tgs(&store, &renew).expect("RENEW of a service ticket");
}

#[test]
// oracle: differential-gate.sh tgs-proxy-krbtgt
fn tgs_proxy_krbtgt_is_cant_proxy_tgt() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = password_key(TEST_USER, TEST_USER_PASSWORD);
    let mut req = as_req(
        cname.clone(),
        TEST_REALM,
        6020,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    req.0.req_body.kdc_options = req
        .0
        .req_body
        .kdc_options
        .with_bit(flag_bit::PROXIABLE, true);
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = TgsReqBuilder::new(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        6021,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::PROXY, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::BADOPTION, Some("CAN'T PROXY TGT")));
}

#[test]
// oracle: differential-gate.sh tgs-pac-corrupt-before-sname
fn tgs_corrupt_pac_before_unknown_sname_is_header_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6030);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    let pac = pac_from_ticket_part(&part).unwrap();
    let mut parsed = Pac::parse(&pac).unwrap();
    let buf = parsed
        .buffers
        .iter_mut()
        .find(|b| b.kind == PAC_SERVER_CHECKSUM)
        .unwrap();
    buf.data[4] ^= 0xff;
    part.authorization_data = Some(wrap_win2k_pac(&parsed.to_bytes()).unwrap());
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "x"]),
        TEST_REALM,
        6031,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::MODIFIED, Some("HEADER_PAC")));
}

#[test]
// oracle: differential-gate.sh tgs-pac-client-mismatch
fn tgs_pac_client_mismatch_is_header_pac() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6040);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
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
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6041,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::BADOPTION, Some("HEADER_PAC")));
}

#[test]
fn tgs_missing_pa_tgs_req_is_padata_type_nosupp() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6060);
    let mut tgs = host_tgs(&as_out, 6061);
    tgs.0.padata = None;
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::PADATA_TYPE_NOSUPP, Some("PROCESS_TGS")));
}

#[test]
fn tgs_disallow_svr_service_header_is_process_tgs() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let as_out = renewable_tgt(&store, 6070);
    let svc = krb5_kdc::issue_tgs(&store, &host_tgs(&as_out, 6071)).unwrap();
    let host = documented_host();
    let attrs = store.get_name(&host).unwrap().attributes | KDB_DISALLOW_SVR;
    store
        .apply_admin_fields(&host, Some(attrs), None, None, None, None, false, None)
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let renew = TgsReqBuilder::new(
        svc.rep.0.ticket.clone(),
        &svc.session_key,
        TEST_REALM,
        &cname,
        host,
        TEST_REALM,
        6072,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &renew).unwrap_err();
    assert_eq!(
        status(&err),
        (err::S_PRINCIPAL_UNKNOWN, Some("PROCESS_TGS"))
    );
}

#[test]
// oracle: differential-gate.sh tgs-forwarded-on-non-f-tgt
fn tgs_forwarded_without_forwardable_is_tgt_not_forwardable() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6110);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, false);
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = TgsReqBuilder::new(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6111,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::FORWARDED, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::BADOPTION, Some("TGT NOT FORWARDABLE")));
}

#[test]
// oracle: differential-gate.sh tgs-proxy-on-non-p-tgt
fn tgs_proxy_without_proxiable_is_tgt_not_proxiable() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6120);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.flags = part.flags.with_bit(flag_bit::PROXIABLE, false);
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = TgsReqBuilder::new(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        6121,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::PROXY, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(status(&err), (err::BADOPTION, Some("TGT NOT PROXIABLE")));
}

#[test]
// oracle: differential-gate.sh tgs-not-a-tgt
fn tgs_not_a_tgt_decrypts_and_names_client() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6001);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let mut svc_tkt = as_out.rep.0.ticket.clone();
    svc_tkt.sname = documented_host();
    svc_tkt.enc_part.etype = host.etype.to_iana();
    svc_tkt.enc_part.kvno = Some(host.kvno);
    let svc_tkt = rewrap(&svc_tkt, &part, &host.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        svc_tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        6003,
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    let ke: KrbError = decode(&bytes).unwrap();
    assert_eq!(ke.error_code, err::NOT_US);
    let et = ke
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(et, Some("BAD TGS SERVER NAME"));
    assert_eq!(
        ke.cname.as_ref().map(PrincipalName::components_joined),
        Some(TEST_USER.to_owned())
    );
}

#[test]
// oracle: differential-gate.sh tgs-expired-vs-unknown-sname
fn tgs_expired_beats_unknown_sname() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 6080);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &as_out.rep.0.ticket).unwrap();
    part.endtime = KerberosTime::now().add_seconds(-3600).unwrap();
    let tkt = rewrap(&as_out.rep.0.ticket, &part, &krbtgt.key);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = tgs_req(
        tkt,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::new(PrincipalName::NT_SRV_INST, ["nosuch", "x"]),
        TEST_REALM,
        6081,
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::TKT_EXPIRED);
            assert_eq!(text.as_deref(), Some("PROCESS_TGS"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn tgs_canonicalize_renew_issues_local_tgt() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = renewable_tgt(&store, 6090);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgs = TgsReqBuilder::new(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        6091,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true)
            .with_bit(flag_bit::CANONICALIZE, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(vec![EncryptionType::Aes256CtsHmacSha196.to_iana()])
    .build()
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(out.rep.0.ticket.sname.is_krbtgt_for(TEST_REALM));
}

const FOREIGN: &str = "OTHER.TEST";

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

fn inet(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
    HostAddress {
        addr_type: HostAddress::ADDRTYPE_INET,
        address: vec![a, b, c, d].into(),
    }
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
// oracle: differential-gate.sh tgs-locked-pac-mismatch
fn locked_host_pac_mismatch_is_header_pac() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let dest = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "locked.kerber.test"]);
    store
        .create_host(&acl, &documented_admin_id(), &dest)
        .unwrap();
    or_attrs(&mut store, &dest, KDB_DISALLOW_ALL_TIX);
    let as_out = issue_tgt(&store, TEST_USER, 19010);
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
    assert_eq!(status(&err), (err::BADOPTION, Some("HEADER_PAC")));
}

#[test]
fn dup_skey_beats_tgt_based() {
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
    let tgt = issue_tgt(&store, TEST_USER, 19021);
    let req = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        19022,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true))
    .additional_tickets(Some(vec![extra]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &req).unwrap_err();
    assert_eq!(status(&err), (err::POLICY, Some("DUP_SKEY DISALLOWED")));
}

#[test]
fn lineage_before_u2u() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x44; 32]).unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    let as_out = issue_tgt(&store, TEST_USER, 19030);
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
    let req = TgsReqBuilder::new(
        header,
        &as_out.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19032,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true))
    .additional_tickets(Some(vec![admin_tgt]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &req).unwrap_err();
    assert_eq!(status(&err), (err::POLICY, Some("INVALID LINEAGE")));
}

#[test]
// oracle: differential-gate.sh tgs-expired-addr-mismatch
fn tgs_expired_caddr_is_badaddr() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, TEST_USER, 19040);
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
// oracle: differential-gate.sh tgs-expired-badmatch
fn expired_authenticator_mismatch_is_badmatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let as_out = issue_tgt(&store, TEST_USER, 19050);
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
    assert_eq!(status(&err), (err::BADMATCH, Some("PROCESS_TGS")));
}

#[test]
fn renew_pac_service_after_krbtgt_enctype_rekey() {
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
    let first = TgsReqBuilder::new(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19061,
    )
    .options(KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true))
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
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
    let renew = TgsReqBuilder::new(
        svc.rep.0.ticket,
        &svc.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        19062,
    )
    .options(
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
    )
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    krb5_kdc::issue_tgs(&store, &renew).expect("RENEW after krbtgt enctype rekey");
}

struct HideLocalTgt<'a>(&'a PrincipalStore);

impl PrincipalRead for HideLocalTgt<'_> {
    fn realm(&self) -> &str {
        self.0.realm()
    }
    fn policy(&self) -> &Policy {
        self.0.policy()
    }
    fn domain_sid(&self) -> &RpcSid {
        self.0.domain_sid()
    }
    fn env(&self) -> &KdcEnv {
        self.0.env()
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        PrincipalRead::fetch(self.0, id)
    }
    fn fetch_krbtgt(&self) -> Result<Option<Principal>, Error> {
        Ok(None)
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        PrincipalRead::list_ids(self.0)
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        PrincipalRead::list_principals(self.0)
    }
}

#[test]
fn s4u2proxy_missing_local_tgt_is_get_local_tgt() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_to(&user, &documented_host().components_joined());
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 731);
    let evidence_tgs = krb5_protocol::tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        732,
    )
    .unwrap();
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).unwrap();
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 733);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        734,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let err = krb5_kdc::issue_tgs(&HideLocalTgt(&store), &tgs).unwrap_err();
    let (code, text) = status(&err);
    assert_eq!(code, err::GENERIC);
    assert_eq!(text, Some("GET_LOCAL_TGT"));
}

#[test]
fn tgs_header_kvno_zero_decrypts_previous_kvno() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 751);
    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    store.chrand_keepold_n(&krbtgt, 1).unwrap();
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.kvno = Some(0);
    let tgs = krb5_protocol::tgs_req(
        ticket,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        752,
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &tgs).expect("kvno 0 walks back to the previous key");
}
