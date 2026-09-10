//! A′-2 R17: S4U2Self keep-F default, is_referral, reply 130, policy cells.

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, encrypt};
use krb5_kdc::{
    PacTicket, PrincipalStore, TEST_ADMIN, TEST_REALM, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_admin_id, documented_host, pa_enc_timestamp, sign_reply_pac,
    ticket_checksum_der, wrap_win2k_pac,
};
use krb5_protocol::{pa_for_user, pa_s4u_x509_user, tgs_req_ex};
use krb5_types::pac::{PAC_CLIENT_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer};
use krb5_types::{
    EncTicketPart, EncryptedData, KdcOptions, PaData, PrincipalName, Ticket, err, flag_bit, ku, pa,
};

const FOREIGN: &str = "OTHER.TEST";

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

fn s4u_tgs(
    tgt: &krb5_kdc::IssuedAs,
    sname: PrincipalName,
    padata: Vec<PaData>,
    nonce: u32,
    opts: KdcOptions,
) -> krb5_types::TgsReq {
    let host = documented_host();
    tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        sname,
        TEST_REALM,
        nonce,
        opts,
        None,
        padata,
        pref_etypes(),
    )
    .unwrap()
}

fn code(e: krb5_kdc::Error) -> (i32, Option<String>) {
    match e {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
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

#[test]
fn a2_r17_create_host_has_no_s4u_to_targets() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = store.get_name(&documented_host()).expect("host");
    assert!(host.s4u_allowed_to.is_empty());
}

#[test]
fn a2_r17_s4u2self_keeps_f_without_clearing_targets() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17000);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let out = krb5_kdc::issue_tgs(
        &store,
        &s4u_tgs(
            &tgt,
            documented_host(),
            vec![pa],
            17001,
            KdcOptions::forwardable(),
        ),
    )
    .unwrap();
    let hostk = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part: EncTicketPart = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert!(part.flags.forwardable());
}

#[test]
fn a2_r17_explicit_cross_tgs_is_server_mismatch() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, aes_key(0x11))
        .unwrap();
    let tgt = host_tgt(&store, 17010);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", FOREIGN]);
    let (c, text) = code(
        krb5_kdc::issue_tgs(
            &store,
            &s4u_tgs(&tgt, other, vec![pa], 17011, KdcOptions::forwardable()),
        )
        .unwrap_err(),
    );
    assert_eq!(c, err::BADMATCH);
    assert_eq!(
        text.as_deref(),
        Some("INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH")
    );
}

#[test]
fn a2_r17_s4u2self_u2u_is_invalid_options() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17020);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    let (c, text) = code(
        krb5_kdc::issue_tgs(
            &store,
            &s4u_tgs(
                &tgt,
                documented_host(),
                vec![pa],
                17021,
                KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
            ),
        )
        .unwrap_err(),
    );
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("INVALID S4U2SELF OPTIONS"));
}

#[test]
fn a2_r17_truncated_x509_is_decode() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17030);
    let pa = PaData {
        padata_type: pa::FOR_X509_USER,
        padata_value: b"\x30\x03\x01\x01".to_vec().into(),
    };
    let (c, text) = code(
        krb5_kdc::issue_tgs(
            &store,
            &s4u_tgs(
                &tgt,
                documented_host(),
                vec![pa],
                17031,
                KdcOptions::forwardable(),
            ),
        )
        .unwrap_err(),
    );
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("DECODE_PA_S4U_X509_USER"));
}

#[test]
fn a2_r17_foreign_pac_client() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = aes_key(0x33);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    let tgt = host_tgt(&store, 17040);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    attach_pac(&ir, &mut part, &documented_host().components_joined());
    let header = reseal_incoming(&ir, &tgt, &part);
    let alice = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["alice"]);
    let pa = pa_for_user(&tgt.session_key, alice, FOREIGN).unwrap();
    let host = documented_host();
    let req = tgs_req_ex(
        header,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        17041,
        KdcOptions::forwardable(),
        None,
        vec![pa],
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("S4U2SELF_FOREIGN_PAC_CLIENT"));
}

#[test]
fn a2_r17_reply_130_has_no_subject_cert() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = host_tgt(&store, 17050);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_s4u_x509_user(&tgt.session_key, admin, TEST_REALM, 17051).unwrap();
    let out = krb5_kdc::issue_tgs(
        &store,
        &s4u_tgs(
            &tgt,
            documented_host(),
            vec![pa],
            17051,
            KdcOptions::forwardable(),
        ),
    )
    .unwrap();
    let raw = out
        .rep
        .0
        .padata
        .as_ref()
        .and_then(|v| v.iter().find(|p| p.padata_type == pa::FOR_X509_USER))
        .expect("reply 130");
    let rep: krb5_types::s4u::PaS4uX509User = krb5_asn1::decode(raw.padata_value.as_ref()).unwrap();
    assert!(rep.user_id.subject_cert.is_none());
}
