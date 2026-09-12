//! W1-J L3b: an AS exchange where the KDC echoes PA-FX-FAST records FAST
//! availability on the outcome (MIT writes `fast_avail` to the ccache).

use std::net::UdpSocket;
use std::thread;
use std::time::Duration;

use krb5_kdc::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, serve, shared_store,
};
use krb5_protocol::{AsRequest, AsTicketOpts, FastArmor, KdcAddr, as_exchange};
use krb5_types::{PrincipalName, pa};

fn isolate_host_krb5() {
    krb5_config::isolate_test_krb5();
}

#[test]
fn as_exchange_records_fast_availability() {
    isolate_host_krb5();
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let port = addr.port();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    thread::sleep(Duration::from_millis(50));

    let out = as_exchange(&AsRequest {
        cname,
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc: &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    })
    .expect("AS exchange with enc-pa-rep negotiation");
    // The client advertised PA-149; the KDC echoed a valid checksum (else
    // as_exchange would fail KDCREP_MODIFIED) plus PA-FX-FAST.
    assert!(out.fast_avail, "PA-FX-FAST echoed => fast_avail");
}

fn request<'a>(
    cname: &PrincipalName,
    kdc: &'a KdcAddr,
    armor: Option<&'a FastArmor>,
) -> AsRequest<'a> {
    AsRequest {
        cname: cname.clone(),
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc,
        want_spake: false,
        fast_armor: armor,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    }
}

#[test]
fn fast_exchange_negotiates_through_the_armor_like_mit() {
    isolate_host_krb5();
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = std::net::TcpListener::bind(addr).unwrap();
    let port = addr.port();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    thread::sleep(Duration::from_millis(50));
    let kdc = KdcAddr {
        host: "127.0.0.1".into(),
        port,
    };
    // The documented user requires preauth: encrypted timestamp (2) is the
    // selected preauth type MIT would record as pa_type.
    let plain = as_exchange(&request(&cname, &kdc, None)).expect("plain AS exchange");
    assert!(plain.fast_avail);
    assert_eq!(plain.pa_type, Some(pa::ENC_TIMESTAMP));
    let armor = FastArmor {
        ticket: plain.ticket.clone(),
        session: plain.session_key.clone(),
        crealm: plain.crealm.clone(),
        cname: plain.cname.clone(),
    };
    // Under FAST the advertised 150/149 travel inside the FAST-REQ, the KDC
    // swaps the inner request in, and the client verifies the echo over the
    // outer request with the strengthened reply key (krb5int_fast_verify_nego).
    let fast = as_exchange(&request(&cname, &kdc, Some(&armor))).expect("FAST AS exchange");
    assert!(fast.fast_avail, "PA-FX-FAST echoed inside the FAST reply");
    assert_eq!(fast.pa_type, Some(pa::ENC_TIMESTAMP));
}
