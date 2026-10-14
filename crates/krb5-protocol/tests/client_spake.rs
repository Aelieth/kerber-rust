//! The SPAKE client as MIT's `spake_client.c`, against the kerber-rust KDC: the client's groups
//! come from `spake_preauth_groups` (edwards25519 when unset); a KDC sharing no group answers the
//! support message with 24 and the client moves to encrypted timestamp; an optimistic challenge
//! is answered at once; a challenge in a group the client lacks gets one support message; a client
//! with no known group has no SPAKE; after a response there is no fallback.

mod common;

use std::net::UdpSocket;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use common::isolate_host_krb5;
use krb5_asn1::{decode, encode};
use krb5_crypto::SpakeGroup;
use krb5_kdc::PrincipalStore;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_protocol::{AsOutcome, AsRequest, AsTicketOpts, Error, KdcAddr, as_exchange};
use krb5_types::spake::{PaSpake, SpakeSecondFactor};
use krb5_types::{AsReq, KrbError, MethodData, PaData, PrincipalName, err, pa};

/// One AS-REQ as the KDC saw it.
struct Sent {
    types: Vec<i32>,
    spake: Option<PaSpake>,
}

fn kdc(groups: &[SpakeGroup], challenge: Option<&str>) -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.spake_preauth_groups = groups.to_vec();
    store.policy.spake_preauth_kdc_challenge = challenge.map(ToOwned::to_owned);
    store
}

/// One AS exchange with `client_groups` as the client's `spake_preauth_groups` (unset when
/// `None`), and what the KDC received.
fn run(
    store: PrincipalStore,
    client_groups: Option<&str>,
    password: &[u8],
) -> (Result<AsOutcome, Error>, Vec<Sent>) {
    run_with(store, client_groups, password, |reply| reply)
}

/// [`run`], with each KDC reply passed through `rewrite` before the client sees it.
fn run_with(
    store: PrincipalStore,
    client_groups: Option<&str>,
    password: &[u8],
    rewrite: fn(Vec<u8>) -> Vec<u8>,
) -> (Result<AsOutcome, Error>, Vec<Sent>) {
    isolate_host_krb5();
    if let Some(groups) = client_groups {
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "client-spake-{}-{}.conf",
            std::process::id(),
            groups.replace(' ', "_")
        ));
        std::fs::write(
            &path,
            format!(
                "[libdefaults]\n    default_realm = {TEST_REALM}\n    dns_lookup_kdc = false\n    spake_preauth_groups = {groups}\n"
            ),
        )
        .unwrap();
        krb5_config::set_test_krb5_paths(Some(vec![path]));
    }
    let seen: Arc<Mutex<Vec<Sent>>> = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            if let Ok(req) = decode::<AsReq>(&buf[..n]) {
                let padata = req.0.padata.unwrap_or_default();
                let spake = padata
                    .iter()
                    .find(|p| p.padata_type == pa::SPAKE)
                    .and_then(|p| decode::<PaSpake>(p.padata_value.as_ref()).ok());
                record.lock().unwrap().push(Sent {
                    types: padata.iter().map(|p| p.padata_type).collect(),
                    spake,
                });
            }
            if let Ok(reply) = krb5_kdc::handle_request(&store, &buf[..n]) {
                let _ = udp.send_to(&rewrite(reply), src);
            }
        }
    });
    let out = as_exchange(&AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        realm: TEST_REALM,
        password,
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
    });
    let sent = std::mem::take(&mut *seen.lock().unwrap());
    (out, sent)
}

fn types(sent: &[Sent]) -> Vec<Vec<i32>> {
    sent.iter().map(|s| s.types.clone()).collect()
}

const FIRST: [i32; 2] = [pa::AS_FRESHNESS, pa::REQ_ENC_PA_REP];
const SPAKE_NEXT: [i32; 4] = [
    pa::FX_COOKIE,
    pa::SPAKE,
    pa::AS_FRESHNESS,
    pa::REQ_ENC_PA_REP,
];
const ENC_TS_NEXT: [i32; 4] = [
    pa::FX_COOKIE,
    pa::ENC_TIMESTAMP,
    pa::AS_FRESHNESS,
    pa::REQ_ENC_PA_REP,
];

#[test]
fn a_kdc_sharing_no_group_gets_support_then_encrypted_timestamp() {
    // MIT 1.22.2 (Fedora 43 kinit, live): support, 24, then encrypted timestamp on the 24's hint.
    let (out, sent) = run(kdc(&[SpakeGroup::P256], None), None, TEST_USER_PASSWORD);
    assert_eq!(out.expect("AS").pa_type, Some(pa::ENC_TIMESTAMP));
    assert_eq!(
        types(&sent),
        [FIRST.to_vec(), SPAKE_NEXT.to_vec(), ENC_TS_NEXT.to_vec()]
    );
    assert!(matches!(&sent[1].spake, Some(PaSpake::Support(s)) if s.groups == [1]));
}

#[test]
fn an_optimistic_challenge_is_answered_in_the_second_request() {
    let store = kdc(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let (out, sent) = run(store, None, TEST_USER_PASSWORD);
    assert_eq!(out.expect("AS").pa_type, Some(pa::SPAKE));
    assert_eq!(types(&sent), [FIRST.to_vec(), SPAKE_NEXT.to_vec()]);
    assert!(matches!(&sent[1].spake, Some(PaSpake::Response(r)) if r.pubkey.len() == 32));
}

#[test]
fn a_challenge_in_a_group_the_client_lacks_gets_support_then_spake() {
    let store = kdc(&[SpakeGroup::P256, SpakeGroup::Edwards25519], Some("P-256"));
    let (out, sent) = run(store, None, TEST_USER_PASSWORD);
    assert_eq!(out.expect("AS").pa_type, Some(pa::SPAKE));
    assert_eq!(
        types(&sent),
        [FIRST.to_vec(), SPAKE_NEXT.to_vec(), SPAKE_NEXT.to_vec()]
    );
    assert!(matches!(&sent[1].spake, Some(PaSpake::Support(s)) if s.groups == [1]));
    assert!(matches!(&sent[2].spake, Some(PaSpake::Response(r)) if r.pubkey.len() == 32));
}

#[test]
fn the_support_message_lists_the_configured_groups_in_order() {
    let store = kdc(&[SpakeGroup::Edwards25519, SpakeGroup::P256], None);
    let (out, sent) = run(store, Some("P-256 edwards25519"), TEST_USER_PASSWORD);
    assert_eq!(out.expect("AS").pa_type, Some(pa::SPAKE));
    assert!(matches!(&sent[1].spake, Some(PaSpake::Support(s)) if s.groups == [2, 1]));
    // The KDC takes the client's first group it permits: P-256, a 33-octet element.
    assert!(matches!(&sent[2].spake, Some(PaSpake::Response(r)) if r.pubkey.len() == 33));
}

#[test]
fn a_client_with_no_known_group_has_no_spake() {
    let store = kdc(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let (out, sent) = run(store, Some("bogus P-521"), TEST_USER_PASSWORD);
    assert_eq!(out.expect("AS").pa_type, Some(pa::ENC_TIMESTAMP));
    assert_eq!(types(&sent), [FIRST.to_vec(), ENC_TS_NEXT.to_vec()]);
}

#[test]
fn a_wrong_password_after_the_response_does_not_fall_back() {
    let store = kdc(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let (out, sent) = run(store, None, b"wrongpassword");
    assert!(
        matches!(out, Err(Error::KrbError { code, .. }) if code == err::PREAUTH_FAILED),
        "{:?}",
        out.err()
    );
    assert_eq!(types(&sent), [FIRST.to_vec(), SPAKE_NEXT.to_vec()]);
}

/// The KDC's optimistic challenge with its factor list replaced by one without SF-NONE.
fn challenge_without_sf_none(reply: Vec<u8>) -> Vec<u8> {
    let Ok(mut e) = decode::<KrbError>(&reply) else {
        return reply;
    };
    let Some(e_data) = e.e_data.as_ref() else {
        return reply;
    };
    let mut method: MethodData = decode(e_data.as_ref()).unwrap();
    for p in &mut method {
        if p.padata_type != pa::SPAKE || p.padata_value.as_ref().is_empty() {
            continue;
        }
        if let Ok(PaSpake::Challenge(mut c)) = decode::<PaSpake>(p.padata_value.as_ref()) {
            c.factors = vec![SpakeSecondFactor {
                factor_type: 2,
                data: None,
            }];
            *p = PaData {
                padata_type: pa::SPAKE,
                padata_value: encode(&PaSpake::Challenge(c)).unwrap().into(),
            };
        }
    }
    e.e_data = Some(encode(&method).unwrap().into());
    encode(&e).unwrap()
}

#[test]
fn a_challenge_without_sf_none_moves_to_encrypted_timestamp() {
    // MIT `process_challenge`: no SF-NONE fails the module before the response, so the client
    // takes the next mechanism on the same hint.
    let store = kdc(&[SpakeGroup::Edwards25519], Some("edwards25519"));
    let (out, sent) = run_with(store, None, TEST_USER_PASSWORD, challenge_without_sf_none);
    assert_eq!(out.expect("AS").pa_type, Some(pa::ENC_TIMESTAMP));
    assert_eq!(types(&sent), [FIRST.to_vec(), ENC_TS_NEXT.to_vec()]);
}
