//! MIT `k5_identify_realm`'s AS probe for an S4U2Self user (`kvno -U`): one request for the
//! client in a realm, no preauthentication sent, that ends at the KDC's first answer.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;
use krb5_asn1::{decode, encode};
use krb5_protocol::{AsRequest, AsTicketOpts, IdentifyReply, KdcAddr, as_identify_realm};
use krb5_types::{
    AsReq, KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err, flag_bit,
};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;

/// A KDC on a local UDP port answering every AS-REQ with `error_code`, naming the client in
/// `crealm` when given, and keeping each request.
fn kdc_replying(error_code: i32, crealm: Option<&'static str>) -> (u16, Arc<Mutex<Vec<AsReq>>>) {
    let seen: Arc<Mutex<Vec<AsReq>>> = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            let Ok(req) = decode::<AsReq>(&buf[..n]) else {
                continue;
            };
            record.lock().unwrap().push(req);
            let reply = encode(&KrbError {
                pvno: KrbError::PVNO,
                msg_type: KrbError::MSG_TYPE,
                ctime: None,
                cusec: None,
                stime: KerberosTime::now(),
                susec: Microseconds::ZERO,
                error_code,
                crealm: crealm.map(ascii),
                cname: crealm.map(|_| client()),
                realm: ascii("KERBER.TEST"),
                sname: PrincipalName::krbtgt("KERBER.TEST"),
                e_text: None,
                e_data: None,
            })
            .unwrap();
            let _ = udp.send_to(&reply, src);
        }
    });
    (port, seen)
}

fn client() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_ENTERPRISE, ["user@OTHER.TEST"])
}

/// The probe for [`client`] in KERBER.TEST, sent to the local KDC on `port`.
fn probe(port: u16) -> Result<IdentifyReply, krb5_protocol::Error> {
    let kdc = KdcAddr {
        host: "127.0.0.1".into(),
        port,
    };
    as_identify_realm(&AsRequest {
        cname: client(),
        realm: "KERBER.TEST",
        password: b"",
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: true,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts {
            lifetime: Some(15),
            forwardable: false,
            proxiable: false,
            ..AsTicketOpts::default()
        },
    })
}

/// MIT `k5_identify_realm` (`lib/krb5/krb/get_in_tkt.c:2062-2083`): the request asks for a 15-second ticket, neither renewable nor forwardable nor proxiable, canonicalized.
/// MIT `init_creds_step_reply` (`lib/krb5/krb/get_in_tkt.c:1721-1726`): while identifying the realm, preauthentication required or an expired key ends the exchange: the client exists.
#[test]
fn the_probe_ends_at_preauthentication_required_or_an_expired_key() {
    isolate_host_krb5();
    let (port, seen) = kdc_replying(err::PREAUTH_REQUIRED, None);
    assert_eq!(probe(port).unwrap(), IdentifyReply::Here);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one request");
    let body = &seen[0].0.req_body;
    assert!(body.kdc_options.bit(flag_bit::CANONICALIZE));
    assert!(body.kdc_options.bit(flag_bit::RENEWABLE_OK));
    assert!(!body.kdc_options.bit(flag_bit::FORWARDABLE));
    assert!(!body.kdc_options.bit(flag_bit::PROXIABLE));
    assert!(!body.kdc_options.bit(flag_bit::RENEWABLE));
    let life = body.till.unix_seconds() - KerberosTime::now().unix_seconds();
    assert!((0..=15).contains(&life), "{life}");
    let padata: Vec<i32> = seen[0]
        .0
        .padata
        .iter()
        .flatten()
        .map(|p| p.padata_type)
        .collect();
    assert_eq!(padata, [150, 149], "no preauthentication sent");
    let (port, _) = kdc_replying(err::KEY_EXPIRED, None);
    assert_eq!(probe(port).unwrap(), IdentifyReply::Here);
}

/// MIT `is_referral` (`lib/krb5/krb/get_in_tkt.c:1450-1458`): a referral is WRONG_REALM or C_PRINCIPAL_UNKNOWN whose client is in another realm.
/// MIT `init_creds_step_reply` (`lib/krb5/krb/get_in_tkt.c:1745-1758`): a client referral rewrites the request's realm and starts over there.
#[test]
fn a_client_in_another_realm_is_a_referral_and_an_unknown_one_an_error() {
    isolate_host_krb5();
    for code in [err::WRONG_REALM, err::C_PRINCIPAL_UNKNOWN] {
        let (port, _) = kdc_replying(code, Some("OTHER.TEST"));
        assert_eq!(
            probe(port).unwrap(),
            IdentifyReply::Referral("OTHER.TEST".into())
        );
    }
    for crealm in [Some("KERBER.TEST"), None] {
        let (port, _) = kdc_replying(err::C_PRINCIPAL_UNKNOWN, crealm);
        assert!(matches!(
            probe(port),
            Err(krb5_protocol::Error::KrbError { code: 6, .. })
        ));
    }
}
