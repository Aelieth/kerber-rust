//! A′-2 R22: realm-aware RBCD ACL; create_host seeds no s4u_allowed_from.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{
    PacTicket, PrincipalStore, TEST_REALM, as_req, bootstrap_documented, decrypt_ticket_part,
    documented_admin_id, documented_host, pa_enc_timestamp, sign_reply_pac, ticket_checksum_der,
    wrap_win2k_pac,
};
use krb5_protocol::{pa_pac_options, tgs_req_ex};
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_DELEGATION_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer,
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

fn extra_host() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "rbcd.kerber.test"])
}

fn attach_deleg_pac(
    key: &ProtocolKey,
    part: &mut EncTicketPart,
    info_name: &str,
    transited: &str,
    dest: &PrincipalName,
) {
    let di = krb5_types::pac::S4uDelegationInfo {
        proxy_target: dest.unparse(),
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

fn foreign_header(store: &PrincipalStore, ir: &ProtocolKey, nonce: u32) -> (Ticket, ProtocolKey) {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(FOREIGN).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    attach_pac(ir, &mut part, &documented_host().components_joined());
    (reseal_incoming(ir, &tgt, &part), tgt.session_key)
}

fn foreign_evidence(store: &PrincipalStore, ir: &ProtocolKey, nonce: u32) -> Ticket {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(FOREIGN).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    let hop = documented_host().unparse_with_realm(FOREIGN);
    attach_deleg_pac(
        ir,
        &mut part,
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
        &hop,
        &extra_host(),
    );
    reseal_incoming(ir, &tgt, &part)
}

fn proxy_cross(
    header: Ticket,
    session: &ProtocolKey,
    evidence: Ticket,
    nonce: u32,
) -> krb5_types::TgsReq {
    let dest = extra_host();
    tgs_req_ex(
        header,
        session,
        FOREIGN,
        &documented_host(),
        dest,
        TEST_REALM,
        nonce,
        cname_addl(),
        Some(vec![evidence]),
        vec![pa_pac_options(true).unwrap()],
        pref_etypes(),
    )
    .unwrap()
}

fn store_with_ir() -> (PrincipalStore, ProtocolKey) {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = aes_key(0x44);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    store
        .create_host(&acl, &documented_admin_id(), &extra_host())
        .unwrap();
    store.policy.reject_bad_transit = false;
    (store, ir)
}

#[test]
fn a2_r22_create_host_has_no_s4u_from() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = store.get_name(&documented_host()).expect("host");
    assert!(host.s4u_allowed_from.is_empty());
}

#[test]
fn a2_r22_foreign_impersonator_vs_local_grant_is_not_allowed() {
    let (mut store, ir) = store_with_ir();
    store.allow_s4u_from(&extra_host(), &documented_host().components_joined());
    let (header, session) = foreign_header(&store, &ir, 22000);
    let ev = foreign_evidence(&store, &ir, 22010);
    let (c, text) =
        code(krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 22020)).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("NOT_ALLOWED_TO_DELEGATE"));
}

#[test]
fn a2_r22_realm_qualified_foreign_grant_matches() {
    let (mut store, ir) = store_with_ir();
    store.allow_s4u_from(
        &extra_host(),
        &documented_host().unparse_with_realm(FOREIGN),
    );
    let (header, session) = foreign_header(&store, &ir, 22100);
    let ev = foreign_evidence(&store, &ir, 22110);
    krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 22120))
        .expect("realm-qualified RBCD");
}
