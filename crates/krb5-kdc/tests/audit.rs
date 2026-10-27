//! Audit record fields: the issue log, `tkt_id`, the TestAudit field names, `ktypes2str`,
//! and the TGS audit seed and unknown-server stage.

use krb5_asn1::encode;
use krb5_kdc::testrealm::TestAudit;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{SRVC_PRINC, make_tkt_id};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_testkit::{issue_tgt, scratch_dir, user};
use krb5_types::PrincipalName;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_as(nonce: u32) -> String {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(Capture(Arc::clone(&buf)))
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let (store, _) = bootstrap_documented().unwrap();
        let key = store
            .get_name(&user())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            user(),
            TEST_REALM,
            nonce,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let _ = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    });
    String::from_utf8_lossy(&buf.lock().unwrap()).into_owned()
}

#[test]
fn as_issue_log_has_client_server_etypes() {
    let log = capture_as(2001);
    assert!(log.contains("ISSUE"), "missing ISSUE: {log}");
    assert!(log.contains("user@KERBER.TEST"), "missing client: {log}");
    assert!(log.contains("krbtgt/KERBER.TEST"), "missing server: {log}");
    assert!(
        log.contains("etypes {rep="),
        "missing rep_etypes2str: {log}"
    );
}

#[test]
fn tkt_id_is_sha256_of_ticket_ciphertext() {
    let (store, _) = bootstrap_documented().unwrap();
    let key = store
        .get_name(&user())
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user(),
        TEST_REALM,
        2010,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).unwrap();
    let cipher = issued.rep.0.ticket.enc_part.cipher.as_ref();
    let id = make_tkt_id(cipher);
    assert_eq!(id.len(), 64);
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()),
        "{id}"
    );
    assert_eq!(id, make_tkt_id(cipher));
    let hash = Sha256::digest(cipher);
    let independent: String = hash
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f])
        .map(|n| char::from(b"0123456789ABCDEF"[usize::from(n)]))
        .collect();
    assert_eq!(id, independent);
}

fn audit_lines(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .filter(|l| l.contains("\"event_name\""))
        .collect()
}

fn json_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":");
    let rest = line.split(&pat).nth(1)?;
    if let Some(s) = rest.strip_prefix('"') {
        return s.split('"').next();
    }
    rest.split([',', '}']).next().map(str::trim)
}

#[test]
fn unknown_server_failure_is_srvc_princ() {
    let dir = scratch_dir("f5-tgs-srvc");
    let path = dir.join("au.log");
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .policy
        .plugins
        .set_audit(Arc::new(TestAudit::open(&path).unwrap()));
    let tgt = issue_tgt(&store, TEST_USER, 5103);
    let nosuch = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nosuch.kerber.test"]);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user(),
        nosuch,
        TEST_REALM,
        5104,
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    assert!(bytes.starts_with(&[0x7e]), "unknown server should fail");
    let lines = audit_lines(&path);
    let fail = lines
        .iter()
        .find(|l| l.contains("\"event_name\":\"TGS_REQ\"") && l.contains("\"event_success\":false"))
        .unwrap_or_else(|| panic!("no TGS fail in {lines:?}"));
    assert_eq!(
        json_field(fail, "stage"),
        Some(SRVC_PRINC.to_string()).as_deref(),
        "{fail}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
