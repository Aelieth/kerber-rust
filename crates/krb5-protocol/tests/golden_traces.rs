//! Decode checked-in `tests/traces/mit-*.der` with the shipped codec and
//! byte/field-diff a re-encode against the MIT (or self-emitted error) bytes.

use krb5_asn1::{decode, encode};
use krb5_protocol::{as_req, tgs_req};
use krb5_types::{AsRep, AsReq, KrbError, PrincipalName, TgsRep, TgsReq};

fn traces_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/traces")
}

fn load(name: &str) -> Vec<u8> {
    let p = traces_dir().join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn first_diff(a: &[u8], b: &[u8]) -> String {
    let n = a.len().min(b.len());
    let i = (0..n).find(|&i| a[i] != b[i]).unwrap_or(n);
    let win = |s: &[u8]| {
        let lo = i.saturating_sub(4);
        let hi = (i + 12).min(s.len());
        s[lo..hi]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    format!(
        "first differ @ {i} (len {} vs {}): ours [{}] mit [{}]",
        a.len(),
        b.len(),
        win(a),
        win(b)
    )
}

/// Genuine MIT PDUs: re-encode must match the captured bytes.
macro_rules! mit_round_trip {
    ($ty:ty, $name:expr, $tag:expr) => {{
        let raw = load($name);
        assert_eq!(
            raw.first().copied(),
            Some($tag),
            "{} APPLICATION tag",
            $name
        );
        let decoded: $ty = decode(&raw).unwrap_or_else(|e| panic!("decode {}: {e}", $name));
        let again = encode(&decoded).unwrap_or_else(|e| panic!("encode {}: {e}", $name));
        let redecoded: $ty = decode(&again).unwrap_or_else(|e| panic!("redecode {}: {e}", $name));
        assert_eq!(
            decoded, redecoded,
            "{}: decode→encode→decode changed fields",
            $name
        );
        assert_eq!(
            again,
            raw,
            "{}: encoder DER diverged from MIT: {}",
            $name,
            first_diff(&again, &raw)
        );
        decoded
    }};
}

fn utf8_realm(r: &krb5_types::Realm) -> &str {
    std::str::from_utf8(r.as_bytes()).unwrap()
}

#[test]
fn mit_as_req_round_trips_through_encoder() {
    let req: AsReq = mit_round_trip!(AsReq, "mit-as-req.der", 0x6a);
    assert_eq!(req.0.pvno, 5);
    assert_eq!(req.0.msg_type, 10);
    assert_eq!(utf8_realm(&req.0.req_body.realm), "KERBER.TEST");
    let pre: AsReq = mit_round_trip!(AsReq, "mit-as-req-preauth.der", 0x6a);
    assert_eq!(pre.0.msg_type, 10);
    assert!(pre.0.padata.as_ref().is_some_and(|p| !p.is_empty()));
    let our = encode(&as_req(
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        "KERBER.TEST",
        1,
        None,
    ))
    .unwrap();
    assert_eq!(our[0], 0x6a, "shipped AS-REQ encoder APPLICATION 10");
    let decoded: AsReq = decode(&our).unwrap();
    assert_eq!(decoded.0.pvno, 5);
    assert_eq!(decoded.0.msg_type, 10);
    assert_eq!(utf8_realm(&decoded.0.req_body.realm), "KERBER.TEST");
}

#[test]
fn mit_tgs_req_round_trips_through_encoder() {
    let req: TgsReq = mit_round_trip!(TgsReq, "mit-tgs-req.der", 0x6c);
    assert_eq!(req.0.pvno, 5);
    assert_eq!(req.0.msg_type, 12);
}

#[test]
fn mit_as_rep_round_trips_through_encoder() {
    let rep: AsRep = mit_round_trip!(AsRep, "mit-as-rep.der", 0x6b);
    assert_eq!(rep.0.pvno, 5);
    assert_eq!(rep.0.msg_type, 11);
    assert_eq!(utf8_realm(&rep.0.crealm), "KERBER.TEST");
    assert_eq!(utf8_realm(&rep.0.ticket.realm), "KERBER.TEST");
    assert!(rep.0.ticket.enc_part.etype != 0);
}

#[test]
fn mit_tgs_rep_round_trips_through_encoder() {
    let rep: TgsRep = mit_round_trip!(TgsRep, "mit-tgs-rep.der", 0x6d);
    assert_eq!(rep.0.pvno, 5);
    assert_eq!(rep.0.msg_type, 13);
    assert_eq!(utf8_realm(&rep.0.crealm), "KERBER.TEST");
    assert_eq!(utf8_realm(&rep.0.ticket.realm), "KERBER.TEST");
    assert!(rep.0.ticket.enc_part.etype != 0);
}

#[test]
fn mit_krb_error_round_trips_through_encoder() {
    // Self-emitted PREAUTH_REQUIRED (not a MIT-KDC PDU). Semantic fields only;
    // stime/nonce in a live issue_as will not byte-match this capture.
    let raw = load("mit-krb-error-preauth.der");
    assert_eq!(raw.first().copied(), Some(0x7e));
    let e: KrbError = decode(&raw).unwrap();
    let again = encode(&e).unwrap();
    assert_eq!(decode::<KrbError>(&again).unwrap(), e);
    assert_eq!(
        again,
        raw,
        "self-emitted KRB-ERROR re-encode: {}",
        first_diff(&again, &raw)
    );
    assert_eq!(e.pvno, 5);
    assert_eq!(e.msg_type, 30);
    assert_eq!(e.error_code, krb5_types::err::PREAUTH_REQUIRED);
}

#[test]
fn tgs_req_builder_emits_application_12() {
    use krb5_crypto::{string_to_key, EncryptionType};
    use krb5_kdc::{
        as_req as kdc_as_req, bootstrap_documented, documented_host, pa_enc_timestamp, S2K_ITERS,
        TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    };
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = kdc_as_req(
        cname.clone(),
        TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    );
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        2,
    )
    .unwrap();
    let wire = encode(&tgs).unwrap();
    assert_eq!(wire[0], 0x6c);
    let _: TgsReq = decode(&wire).unwrap();
}
