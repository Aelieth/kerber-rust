//! A′-4 item 20 HEAD-only: tkt_id, TestAudit fields, ktypes2str.

use std::sync::Arc;

use krb5_asn1::encode;
use krb5_kdc::{
    ENCR_REP, TEST_REALM, TestAudit, as_req, bootstrap_documented, clear_thread_audit, ktypes2str,
    make_tkt_id, pa_enc_timestamp, set_thread_audit,
};
use krb5_testkit::{scratch_dir, user};
use sha2::{Digest, Sha256};

#[test]
fn a4_20_tkt_id_is_sha256_of_ticket_ciphertext() {
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

#[test]
fn a4_20_test_audit_writes_mit_field_names() {
    let dir = scratch_dir("a4-20-audit");
    let path = dir.join("au.log");
    let sink = TestAudit::open(&path).unwrap();
    set_thread_audit(Arc::new(sink));
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
        2011,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let _ = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    clear_thread_audit();
    let text = std::fs::read_to_string(&path).unwrap();
    let line = text
        .lines()
        .find(|l| l.contains("\"event_name\":\"AS_REQ\"") && l.contains("\"tkt_out_id\""))
        .unwrap_or_else(|| panic!("no issued AS_REQ in {text}"));
    for key in [
        "event_name",
        "event_success",
        "stage",
        "tkt_out_id",
        "req_id",
        "fromport",
    ] {
        assert!(
            line.contains(&format!("\"{key}\"")),
            "missing {key} in {line}"
        );
    }
    assert!(line.contains(&format!("\"stage\":{ENCR_REP}")), "{line}");
    assert!(line.contains("\"event_success\":true"), "{line}");
    let tkt = line
        .split("\"tkt_out_id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap();
    assert_eq!(tkt.len(), 64);
    assert!(
        tkt.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')),
        "{tkt}"
    );
    let req_id = line
        .split("\"req_id\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap();
    assert_eq!(req_id.len(), krb5_kdc::REQID_LEN - 1);
    assert!(
        req_id.chars().all(|c| c.is_ascii_alphanumeric()),
        "{req_id}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a4_20_ktypes2str_matches_mit() {
    assert_eq!(
        ktypes2str(&[18, 17, 20, 19]),
        "4 etypes {aes256-cts-hmac-sha1-96(18), aes128-cts-hmac-sha1-96(17), aes256-cts-hmac-sha384-192(20), aes128-cts-hmac-sha256-128(19)}"
    );
}
