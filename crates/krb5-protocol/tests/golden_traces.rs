//! Decode checked-in `tests/traces/mit-*.der` with the shipped codec and
//! field-diff against a re-encode. Fails on encoder divergence.

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

macro_rules! round_trip {
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
            "{}: shipped encoder diverged (decode→encode→decode)",
            $name
        );
    }};
}

#[test]
fn mit_as_req_round_trips_through_encoder() {
    round_trip!(AsReq, "mit-as-req.der", 0x6a);
    round_trip!(AsReq, "mit-as-req-preauth.der", 0x6a);
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
}

#[test]
fn mit_tgs_req_round_trips_through_encoder() {
    round_trip!(TgsReq, "mit-tgs-req.der", 0x6c);
}

#[test]
fn mit_as_rep_round_trips_through_encoder() {
    round_trip!(AsRep, "mit-as-rep.der", 0x6b);
    let raw = load("mit-as-rep.der");
    let rep: AsRep = decode(&raw).unwrap();
    assert_eq!(rep.0.pvno, 5);
    assert_eq!(rep.0.msg_type, 11);
    assert_eq!(
        std::str::from_utf8(rep.0.crealm.as_bytes()).unwrap(),
        "KERBER.TEST"
    );
}

#[test]
fn mit_tgs_rep_round_trips_through_encoder() {
    round_trip!(TgsRep, "mit-tgs-rep.der", 0x6d);
}

#[test]
fn mit_krb_error_round_trips_through_encoder() {
    round_trip!(KrbError, "mit-krb-error-preauth.der", 0x7e);
    let raw = load("mit-krb-error-preauth.der");
    let e: KrbError = decode(&raw).unwrap();
    assert_eq!(e.pvno, 5);
    assert_eq!(e.msg_type, 30);
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
