//! `[plugins] clpreauth` selects the client's preauth modules by MIT's names.
//!
//! MIT `k5_init_preauth_context` (`lib/krb5/krb/preauth2.c:132-150`): built-ins register, then
//! `k5_plugin_load_all` applies `disable` and `enable_only`. A module that is not loaded does not
//! answer its pa-type.
//! MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:648-728`): a hint whose real types have no
//! loaded module is `KRB5_PREAUTH_FAILED` ("Generic preauthentication failure"), and the prompter
//! is not asked.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use krb5_asn1::{decode, encode};
use krb5_protocol::{
    AsRequest, AsTicketOpts, ClPreauth, Error, KdcAddr, as_exchange, clear_thread_clpreauth,
    set_thread_clpreauth,
};
use krb5_types::{
    AsReq, KerberosTime, KrbError, MethodData, Microseconds, PaData, PrincipalName, ascii, err, pa,
};

fn pin(extra: &str) {
    krb5_config::isolate_test_krb5();
    let dir = krb5_testkit::scratch_dir("pg3-clpreauth");
    let path = dir.join("krb5.conf");
    std::fs::write(
        &path,
        format!(
            "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    udp_preference_limit = 60000\n{extra}"
        ),
    )
    .unwrap();
    krb5_config::set_test_krb5_paths(Some(vec![path]));
}

fn pa_of(padata_type: i32) -> PaData {
    PaData {
        padata_type,
        padata_value: Vec::<u8>::new().into(),
    }
}

fn encode_preauth_required(method: &MethodData) -> Vec<u8> {
    encode(&KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: err::PREAUTH_REQUIRED,
        crealm: None,
        cname: None,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: None,
        e_data: Some(encode(method).expect("METHOD-DATA").into()),
    })
    .expect("KRB-ERROR")
}

fn encode_preauth_failed() -> Vec<u8> {
    encode(&KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::now(),
        susec: Microseconds::ZERO,
        error_code: err::PREAUTH_FAILED,
        crealm: None,
        cname: None,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: None,
        e_data: None,
    })
    .expect("KRB-ERROR")
}

/// Send `hint` as PREAUTH_REQUIRED, then PREAUTH_FAILED. Returns each AS-REQ's pa-types.
fn shots(hint: MethodData) -> (Vec<Vec<i32>>, String) {
    let seen: Arc<Mutex<Vec<Vec<i32>>>> = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let port = udp.local_addr().unwrap().port();
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            let Ok(req) = decode::<AsReq>(&buf[..n]) else {
                continue;
            };
            let types: Vec<i32> = req
                .0
                .padata
                .unwrap_or_default()
                .iter()
                .map(|p| p.padata_type)
                .collect();
            let mut guard = record.lock().unwrap();
            guard.push(types);
            let n_seen = guard.len();
            drop(guard);
            let reply = if n_seen == 1 {
                encode_preauth_required(&hint)
            } else {
                encode_preauth_failed()
            };
            let _ = udp.send_to(&reply, src);
            if n_seen >= 2 {
                break;
            }
        }
    });
    let err = as_exchange(&AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: Some(&[18]),
        ticket: AsTicketOpts::default(),
    });
    let msg = match err {
        Ok(_) => "exchange succeeded".to_owned(),
        Err(e) => e.to_string(),
    };
    (seen.lock().unwrap().clone(), msg)
}

#[test]
fn disable_encrypted_timestamp_sends_no_pa_enc_timestamp() {
    pin(
        "    spake_preauth_groups = nosuch\n[plugins]\n    clpreauth = {\n        disable = encrypted_timestamp\n        disable = nosuch\n    }\n",
    );
    let (seen, msg) = shots(vec![pa_of(pa::ENC_TIMESTAMP)]);
    assert!(
        seen.iter().all(|types| !types.contains(&pa::ENC_TIMESTAMP)),
        "a disabled encrypted_timestamp is not answered: {seen:?}"
    );
    assert_eq!(
        seen.len(),
        1,
        "no second AS-REQ when nothing can answer: {seen:?}"
    );
    assert!(
        msg.contains("Generic preauthentication failure"),
        "MIT KRB5_PREAUTH_FAILED, got {msg}"
    );
}

#[test]
fn enable_only_encrypted_timestamp_skips_spake() {
    pin("[plugins]\n    clpreauth = {\n        enable_only = encrypted_timestamp\n    }\n");
    let (seen, _) = shots(vec![pa_of(pa::SPAKE), pa_of(pa::ENC_TIMESTAMP)]);
    assert!(seen.len() >= 2, "the client answers the hint: {seen:?}");
    assert!(
        seen[1].contains(&pa::ENC_TIMESTAMP),
        "enable_only keeps encrypted_timestamp: {seen:?}"
    );
    assert!(
        !seen[1].contains(&pa::SPAKE),
        "enable_only drops spake: {seen:?}"
    );
}

#[test]
fn enable_only_of_an_absent_name_answers_nothing() {
    pin(
        "    spake_preauth_groups = nosuch\n[plugins]\n    clpreauth = {\n        enable_only = otp\n    }\n",
    );
    let (seen, msg) = shots(vec![pa_of(pa::ENC_TIMESTAMP), pa_of(pa::SPAKE)]);
    assert_eq!(
        seen.len(),
        1,
        "otp is not a loaded module, so enable_only keeps none: {seen:?}"
    );
    assert!(
        msg.contains("Generic preauthentication failure"),
        "absent enable_only is KRB5_PREAUTH_FAILED, got {msg}"
    );
}

#[test]
fn disable_of_an_absent_name_still_answers_encrypted_timestamp() {
    pin(
        "    spake_preauth_groups = nosuch\n[plugins]\n    clpreauth = {\n        disable = otp\n        disable = sam2\n    }\n",
    );
    let (seen, _) = shots(vec![pa_of(pa::ENC_TIMESTAMP)]);
    assert!(seen.len() >= 2, "an absent name drops nothing: {seen:?}");
    assert!(
        seen[1].contains(&pa::ENC_TIMESTAMP),
        "encrypted_timestamp still answers: {seen:?}"
    );
}

#[test]
fn disable_encrypted_timestamp_still_answers_spake() {
    pin("[plugins]\n    clpreauth = {\n        disable = encrypted_timestamp\n    }\n");
    let (seen, _) = shots(vec![pa_of(pa::ENC_TIMESTAMP), pa_of(pa::SPAKE)]);
    assert!(seen.len() >= 2, "SPAKE still runs: {seen:?}");
    assert!(
        seen[1].contains(&pa::SPAKE),
        "disable of encrypted_timestamp leaves spake: {seen:?}"
    );
    assert!(
        !seen[1].contains(&pa::ENC_TIMESTAMP),
        "encrypted_timestamp is not answered: {seen:?}"
    );
}

const WIDGET: i32 = 211;

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        clear_thread_clpreauth();
    }
}

struct Widget;

impl ClPreauth for Widget {
    fn name(&self) -> &'static str {
        "widget"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[WIDGET]
    }
    fn process(&self, _input: &PaData) -> Result<Option<Vec<PaData>>, Error> {
        Ok(Some(vec![PaData {
            padata_type: WIDGET,
            padata_value: b"widget-answer".to_vec().into(),
        }]))
    }
}

/// One AS-REQ's padata, as `(pa-type, value)` pairs.
type PaShot = Vec<(i32, Vec<u8>)>;

/// Each AS-REQ's `(pa-type, value)` list.
fn shot_bodies(hint: MethodData) -> Vec<PaShot> {
    let seen: Arc<Mutex<Vec<PaShot>>> = Arc::new(Mutex::new(Vec::new()));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let port = udp.local_addr().unwrap().port();
    let record = Arc::clone(&seen);
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            let Ok(req) = decode::<AsReq>(&buf[..n]) else {
                continue;
            };
            let bodies: Vec<(i32, Vec<u8>)> = req
                .0
                .padata
                .unwrap_or_default()
                .iter()
                .map(|p| (p.padata_type, p.padata_value.as_ref().to_vec()))
                .collect();
            let mut guard = record.lock().unwrap();
            guard.push(bodies);
            let n_seen = guard.len();
            drop(guard);
            let reply = if n_seen == 1 {
                encode_preauth_required(&hint)
            } else {
                encode_preauth_failed()
            };
            let _ = udp.send_to(&reply, src);
            if n_seen >= 2 {
                break;
            }
        }
    });
    let _ = as_exchange(&AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"userpassword",
        kdc: &KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: Some(&[18]),
        ticket: AsTicketOpts::default(),
    });
    seen.lock().unwrap().clone()
}

#[test]
fn enable_only_widget_sends_the_modules_padata() {
    let _guard = Guard;
    set_thread_clpreauth(vec![Arc::new(Widget)]);
    pin("[plugins]\n    clpreauth = {\n        enable_only = widget\n    }\n");
    let seen = shot_bodies(vec![pa_of(WIDGET)]);
    assert!(seen.len() >= 2, "the selected module answers: {seen:?}");
    assert!(
        seen[1]
            .iter()
            .any(|(ty, val)| *ty == WIDGET && val.as_slice() == b"widget-answer"),
        "the second AS-REQ carries the module's padata: {seen:?}"
    );
    assert!(
        seen[1]
            .iter()
            .all(|(ty, _)| *ty != pa::ENC_TIMESTAMP && *ty != pa::SPAKE),
        "enable_only drops the built-ins: {seen:?}"
    );
}

#[test]
fn a_disabled_widget_is_not_answered() {
    let _guard = Guard;
    set_thread_clpreauth(vec![Arc::new(Widget)]);
    pin("[plugins]\n    clpreauth = {\n        disable = widget\n    }\n");
    let (seen, msg) = shots(vec![pa_of(WIDGET)]);
    assert_eq!(seen.len(), 1, "a dropped module does not answer: {seen:?}");
    assert!(
        seen.iter().all(|types| !types.contains(&WIDGET)),
        "type 211 is not sent: {seen:?}"
    );
    assert!(
        msg.contains("Generic preauthentication failure"),
        "no loaded module is KRB5_PREAUTH_FAILED, got {msg}"
    );
}
