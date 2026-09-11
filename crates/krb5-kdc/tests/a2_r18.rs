//! A′-2 R18: S4U2Proxy identity, PAC client info, cross-realm gather.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{
    PacTicket, PrincipalStore, TEST_ADMIN, TEST_REALM, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_admin_id, documented_host, pa_enc_timestamp,
    pac_from_ticket_part, sign_reply_pac, ticket_checksum_der, wrap_win2k_pac,
};
use krb5_protocol::{pa_pac_options, tgs_req_ex};
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_DELEGATION_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer,
    parse_client_info, parse_delegation_info,
};
use krb5_types::{
    EncTicketPart, EncryptedData, KdcOptions, PrincipalName, Ticket, err, flag_bit, ku,
};

const FOREIGN: &str = "OTHER.TEST";
const SUBJECT: &str = "alice";
const SUBJECT_REALM: &str = "ALICE.TEST";

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn aes_key(b: u8) -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[b; 32]).expect("key")
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

fn cname_addl() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
}

fn attach_pac(key: &ProtocolKey, part: &mut EncTicketPart, info_name: &str) {
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

fn attach_deleg_pac(key: &ProtocolKey, part: &mut EncTicketPart, info_name: &str, transited: &str) {
    let di = krb5_types::pac::S4uDelegationInfo {
        proxy_target: documented_host().unparse(),
        transited_services: vec![transited.to_owned()],
    };
    let stub = Pac::built(
        0,
        vec![
            PacBuffer::new(
                PAC_CLIENT_INFO,
                client_info_buffer(part.authtime.unix_seconds(), info_name),
            ),
            PacBuffer::new(
                PAC_DELEGATION_INFO,
                krb5_types::pac::delegation_info_buffer(&di),
            ),
        ],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

fn reseal_incoming(key: &ProtocolKey, tgt: &krb5_kdc::IssuedAs, part: &EncTicketPart) -> Ticket {
    let der = encode(part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    Ticket {
        tkt_vno: tgt.rep.0.ticket.tkt_vno,
        realm: krb5_types::try_ascii(FOREIGN).unwrap(),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", TEST_REALM]),
        enc_part: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: Some(1),
            cipher: encrypt(key, usage, &der).unwrap().into(),
        },
    }
}

fn cross_store() -> (PrincipalStore, ProtocolKey) {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = aes_key(0x44);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    store.allow_s4u_from(
        &documented_host(),
        &documented_host().unparse_with_realm(FOREIGN),
    );
    (store, ir)
}

fn foreign_host_header(
    store: &PrincipalStore,
    ir: &ProtocolKey,
    nonce: u32,
) -> (Ticket, ProtocolKey) {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(FOREIGN).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    attach_pac(ir, &mut part, &documented_host().components_joined());
    (reseal_incoming(ir, &tgt, &part), tgt.session_key)
}

fn cross_evidence(
    store: &PrincipalStore,
    ir: &ProtocolKey,
    nonce: u32,
    crealm: &str,
    info_name: &str,
) -> Ticket {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(crealm).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    let hop = documented_host().unparse_with_realm(crealm);
    attach_deleg_pac(ir, &mut part, info_name, &hop);
    reseal_incoming(ir, &tgt, &part)
}

fn proxy_cross(
    header: Ticket,
    session: &ProtocolKey,
    evidence: Ticket,
    nonce: u32,
) -> krb5_types::TgsReq {
    let host = documented_host();
    tgs_req_ex(
        header,
        session,
        FOREIGN,
        &host,
        host.clone(),
        TEST_REALM,
        nonce,
        cname_addl(),
        Some(vec![evidence]),
        vec![pa_pac_options(true).unwrap()],
        pref_etypes(),
    )
    .unwrap()
}

#[test]
fn a2_r18_local_s4u2proxy_client_info_omits_realm() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    store.allow_s4u_to(&user, &documented_host().components_joined());
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
            admin.clone(),
            TEST_REALM,
            18000,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&store, &req).unwrap()
    };
    let ev = krb5_kdc::issue_tgs(
        &store,
        &tgs_req_ex(
            admin_tgt.rep.0.ticket.clone(),
            &admin_tgt.session_key,
            TEST_REALM,
            &admin,
            user.clone(),
            TEST_REALM,
            18001,
            KdcOptions::forwardable(),
            None,
            vec![],
            pref_etypes(),
        )
        .unwrap(),
    )
    .unwrap()
    .rep
    .0
    .ticket;
    let user_tgt = {
        let key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            user.clone(),
            TEST_REALM,
            18002,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&store, &req).unwrap()
    };
    let out = krb5_kdc::issue_tgs(
        &store,
        &tgs_req_ex(
            user_tgt.rep.0.ticket,
            &user_tgt.session_key,
            TEST_REALM,
            &user,
            documented_host(),
            TEST_REALM,
            18003,
            cname_addl(),
            Some(vec![ev]),
            vec![],
            pref_etypes(),
        )
        .unwrap(),
    )
    .unwrap();
    let hostk = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    let pac = Pac::parse(&pac_from_ticket_part(&part).unwrap()).unwrap();
    let (_, name) =
        parse_client_info(pac.unique_buffer(PAC_CLIENT_INFO).unwrap().unwrap()).unwrap();
    assert!(!name.contains('@'), "{name}");
    let di =
        parse_delegation_info(pac.unique_buffer(PAC_DELEGATION_INFO).unwrap().unwrap()).unwrap();
    assert_eq!(di.proxy_target, documented_host().unparse());
}

#[test]
fn a2_r18_cross_stkt_realm_mismatch_is_xrealm() {
    let (store, ir) = cross_store();
    let (header, session) = foreign_host_header(&store, &ir, 18100);
    let ev = cross_evidence(
        &store,
        &ir,
        18110,
        "THIRD.TEST",
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
    );
    let (c, text) =
        code(krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18120)).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("XREALM_EVIDENCE_TICKET_MISMATCH"));
}

#[test]
fn a2_r18_cross_pac_without_realm_is_rbcd_pac_princ() {
    let (store, ir) = cross_store();
    let (header, session) = foreign_host_header(&store, &ir, 18200);
    let ev = cross_evidence(&store, &ir, 18210, FOREIGN, SUBJECT);
    let (c, text) =
        code(krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18220)).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("RBCD_PAC_PRINC"));
}

#[test]
fn a2_r18_cross_tkt_client_realm_is_transited() {
    let (store, ir) = cross_store();
    let (header, session) = foreign_host_header(&store, &ir, 18250);
    let ev = cross_evidence(
        &store,
        &ir,
        18260,
        FOREIGN,
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
    );
    let (c, text) =
        code(krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18270)).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
}

#[test]
fn a2_r18_cross_issues_pac_client_and_realm() {
    let (mut store, ir) = cross_store();
    store.policy.reject_bad_transit = false;
    let (header, session) = foreign_host_header(&store, &ir, 18300);
    let ev = cross_evidence(
        &store,
        &ir,
        18310,
        FOREIGN,
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
    );
    let out = krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18320))
        .expect("cross S4U2Proxy");
    let hostk = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname.components_joined(), SUBJECT);
    assert_eq!(
        std::str::from_utf8(part.crealm.as_bytes()).unwrap(),
        SUBJECT_REALM
    );
    let pac = Pac::parse(&pac_from_ticket_part(&part).unwrap()).unwrap();
    let (_, name) =
        parse_client_info(pac.unique_buffer(PAC_CLIENT_INFO).unwrap().unwrap()).unwrap();
    assert_eq!(name, SUBJECT);
    let di =
        parse_delegation_info(pac.unique_buffer(PAC_DELEGATION_INFO).unwrap().unwrap()).unwrap();
    assert_eq!(di.proxy_target, documented_host().unparse());
}
