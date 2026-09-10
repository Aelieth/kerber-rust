//! Item 10 copy rules that fail at parent `05c75a0` (inject this file only).

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, checksum, encrypt};
use krb5_kdc::{
    PrincipalStore, TEST_REALM, TEST_USER, as_req, bootstrap_documented, decrypt_ticket_part,
    documented_host, pa_enc_timestamp,
};
use krb5_protocol::tgs_req;
use krb5_types::{
    ApOptions, ApReq, Authenticator, Checksum, EncryptedData, HostAddress, KdcOptions, KdcReq,
    KdcReqBody, KerberosTime, Microseconds, PaData, PaPacRequest, PrincipalName, TgsReq, Ticket,
    flag_bit, ku, pa,
};

fn inet(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: vec![a, b, c, d].into(),
    }
}

fn pref_etypes() -> Vec<i32> {
    krb5_crypto::EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

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

fn as_with_addrs(
    store: &PrincipalStore,
    addrs: Option<Vec<HostAddress>>,
    nonce: u32,
    pac: bool,
    renewable: bool,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut padata = vec![pa_enc_timestamp(&user_key(store)).unwrap()];
    if !pac {
        padata.push(PaData {
            padata_type: pa::PAC_REQUEST,
            padata_value: encode(&PaPacRequest { include_pac: false }).unwrap().into(),
        });
    }
    let mut req = as_req(cname, TEST_REALM, nonce, Some(padata)).unwrap();
    req.0.req_body.addresses = addrs;
    if renewable {
        req.0.req_body.kdc_options = req
            .0
            .req_body
            .kdc_options
            .with_bit(flag_bit::RENEWABLE, true);
    }
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn tkt_part(store: &PrincipalStore, ticket: &Ticket) -> krb5_types::EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    decrypt_ticket_part(&key.key, ticket).unwrap()
}

fn host_part(store: &PrincipalStore, ticket: &Ticket) -> krb5_types::EncTicketPart {
    let key = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    decrypt_ticket_part(&key.key, ticket).unwrap()
}

fn tgs_with_addr(
    ticket: Ticket,
    session: &krb5_crypto::ProtocolKey,
    cname: &PrincipalName,
    sname: PrincipalName,
    nonce: u32,
    opts: KdcOptions,
    addresses: Option<Vec<HostAddress>>,
) -> TgsReq {
    let till = KerberosTime::now()
        .add_hours(10)
        .unwrap_or_else(|_| KerberosTime::now());
    let body = KdcReqBody {
        kdc_options: opts,
        cname: None,
        realm: krb5_types::try_ascii(TEST_REALM).unwrap(),
        sname: Some(sname),
        from: None,
        till,
        rtime: None,
        nonce,
        etype: pref_etypes(),
        addresses,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    let body_der = encode(&body).unwrap();
    let mic = checksum(
        session,
        KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM).unwrap(),
        &body_der,
    )
    .unwrap();
    let now = KerberosTime::now();
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: krb5_types::try_ascii(TEST_REALM).unwrap(),
        cname: cname.clone(),
        cksum: Some(Checksum {
            cksumtype: session.etype().checksum_type(),
            checksum: mic.into(),
        }),
        cusec: Microseconds::from_subsec_micros(now.0.timestamp_subsec_micros()),
        ctime: now,
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let auth_cipher = encrypt(
        session,
        KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR).unwrap(),
        &encode(&authenticator).unwrap(),
    )
    .unwrap();
    let ap = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket,
        authenticator: EncryptedData {
            etype: session.etype().to_iana(),
            kvno: None,
            cipher: auth_cipher.into(),
        },
    };
    TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(vec![PaData {
            padata_type: pa::TGS_REQ,
            padata_value: encode(&ap).unwrap().into(),
        }]),
        req_body: body,
    })
}

#[test]
fn as_copies_request_addresses() {
    let (store, _) = bootstrap_documented().unwrap();
    let addrs = vec![inet(192, 0, 2, 10)];
    let issued = as_with_addrs(&store, Some(addrs.clone()), 10100, true, false);
    assert_eq!(
        tkt_part(&store, &issued.rep.0.ticket).caddr.as_ref(),
        Some(&addrs)
    );
}

#[test]
fn tgs_copies_header_caddr() {
    let (store, _) = bootstrap_documented().unwrap();
    let addrs = vec![inet(192, 0, 2, 11)];
    let tgt = as_with_addrs(&store, Some(addrs.clone()), 10110, true, false);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_req(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        10111,
    )
    .unwrap();
    let issued = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert_eq!(
        host_part(&store, &issued.rep.0.ticket).caddr.as_ref(),
        Some(&addrs)
    );
}

#[test]
fn tgs_forwarded_copies_request_addresses() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = as_with_addrs(&store, None, 10120, false, false);
    let want = vec![inet(192, 0, 2, 12)];
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_with_addr(
        tgt.rep.0.ticket,
        &tgt.session_key,
        &user,
        PrincipalName::krbtgt(TEST_REALM),
        10121,
        KdcOptions::none().with_bit(flag_bit::FORWARDED, true),
        Some(want.clone()),
    );
    let issued = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert_eq!(
        tkt_part(&store, &issued.rep.0.ticket).caddr.as_ref(),
        Some(&want)
    );
}

#[test]
fn tgs_renew_keeps_header_caddr() {
    let (store, _) = bootstrap_documented().unwrap();
    let addrs = vec![inet(192, 0, 2, 13)];
    let tgt = as_with_addrs(&store, Some(addrs.clone()), 10130, true, true);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = tgs_with_addr(
        tgt.rep.0.ticket,
        &tgt.session_key,
        &user,
        PrincipalName::krbtgt(TEST_REALM),
        10131,
        KdcOptions::none().with_bit(flag_bit::RENEW, true),
        None,
    );
    let issued = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert_eq!(
        tkt_part(&store, &issued.rep.0.ticket).caddr.as_ref(),
        Some(&addrs)
    );
}
