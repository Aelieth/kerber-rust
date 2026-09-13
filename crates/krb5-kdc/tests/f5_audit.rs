//! F5 TGS audit seed + unknown-server stage. Compiles at `70de1ac`.

use std::sync::Arc;

use krb5_asn1::encode;
use krb5_kdc::{
    AUTHN_REQ_CL, ENCR_REP, SRVC_PRINC, TEST_REALM, TEST_USER, TestAudit, as_req,
    bootstrap_documented, clear_thread_audit, documented_host, pa_enc_timestamp, set_thread_audit,
    tgs_req,
};
use krb5_types::PrincipalName;

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let scratch = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|p| std::path::PathBuf::from(p).join("test-krb5"))
        })
        .or_else(|| std::env::var_os("KERBER_SCRATCH").map(std::path::PathBuf::from))
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test-krb5")
        });
    let dir = scratch.join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn issue_tgt(store: &krb5_kdc::PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
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
    krb5_kdc::issue_as(store, &req).unwrap()
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
fn f5_tgs_seed_is_authn_req_cl_without_tkt_out() {
    let dir = scratch_dir("f5-tgs-seed");
    let path = dir.join("au.log");
    set_thread_audit(Arc::new(TestAudit::open(&path).unwrap()));
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = issue_tgt(&store, 5101);
    let tgs = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user(),
        documented_host(),
        TEST_REALM,
        5102,
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&tgs).unwrap()).unwrap();
    assert!(!bytes.starts_with(&[0x7e]), "TGS should succeed");
    clear_thread_audit();
    let lines = audit_lines(&path);
    let seed = lines
        .iter()
        .find(|l| {
            l.contains("\"event_name\":\"TGS_REQ\"")
                && l.contains("\"event_success\":true")
                && !l.contains("tkt_out_id")
        })
        .unwrap_or_else(|| panic!("no TGS seed in {lines:?}"));
    assert_eq!(
        json_field(seed, "stage"),
        Some(AUTHN_REQ_CL.to_string()).as_deref()
    );
    let finish = lines
        .iter()
        .find(|l| l.contains("\"event_name\":\"TGS_REQ\"") && l.contains("\"tkt_out_id\""))
        .unwrap_or_else(|| panic!("no TGS finish in {lines:?}"));
    assert_eq!(
        json_field(finish, "stage"),
        Some(ENCR_REP.to_string()).as_deref()
    );
    assert_eq!(json_field(seed, "req_id"), json_field(finish, "req_id"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn f5_unknown_server_failure_is_srvc_princ() {
    let dir = scratch_dir("f5-tgs-srvc");
    let path = dir.join("au.log");
    set_thread_audit(Arc::new(TestAudit::open(&path).unwrap()));
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = issue_tgt(&store, 5103);
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
    clear_thread_audit();
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
