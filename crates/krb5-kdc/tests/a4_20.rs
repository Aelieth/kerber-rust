//! A′-4 item 20 units that compile at `7fc6980` and fail there.

use std::io::Write;
use std::sync::{Arc, Mutex};

use krb5_asn1::encode;
use krb5_kdc::{TEST_REALM, TEST_USER, as_req, bootstrap_documented, pa_enc_timestamp};
use krb5_types::PrincipalName;
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

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
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
fn a4_20_as_issue_log_has_client_server_etypes() {
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
fn a4_20_as_issue_log_has_authtime_and_kind() {
    let log = capture_as(2002);
    assert!(
        log.contains("AS_REQ") || log.contains("kind"),
        "missing kind: {log}"
    );
    assert!(log.contains("authtime"), "missing authtime: {log}");
}
