//! DER round-trip and malformed-input tests for RFC 4120 core types.

use krb5_asn1::{
    decode, encode, types, ApReq, EncryptedData, Error, KdcRep, KdcReq, KrbError, PrincipalName,
    Realm, Ticket,
};
use krb5_types::{kerberos_time_from_utc_z, ApOptions, KdcOptions, KdcReqBody, OctetString};

fn install_json_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krb5_asn1=info")
        .json()
        .with_current_span(false)
        .try_init();
}

fn realm(s: &str) -> Realm {
    types::ascii(s)
}

fn enc_data() -> EncryptedData {
    EncryptedData {
        etype: 18,
        kvno: Some(1),
        cipher: OctetString::from(vec![0xde, 0xad, 0xbe, 0xef]),
    }
}

fn sample_time() -> types::KerberosTime {
    kerberos_time_from_utc_z("20260819120000Z").expect("sample KerberosTime")
}

fn sample_principal() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"])
}

fn sample_ticket() -> Ticket {
    Ticket {
        tkt_vno: Ticket::VNO,
        realm: realm("KERBER.TEST"),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "KERBER.TEST"]),
        enc_part: enc_data(),
    }
}

fn sample_kdc_req() -> KdcReq {
    KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_AS_REQ,
        padata: None,
        req_body: KdcReqBody {
            kdc_options: KdcOptions::none(),
            cname: Some(sample_principal()),
            realm: realm("KERBER.TEST"),
            sname: Some(PrincipalName::new(
                PrincipalName::NT_SRV_INST,
                ["krbtgt", "KERBER.TEST"],
            )),
            from: None,
            till: sample_time(),
            rtime: None,
            nonce: 0x0102_0304,
            etype: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    }
}

fn sample_kdc_rep() -> KdcRep {
    KdcRep {
        pvno: KdcRep::PVNO,
        msg_type: KdcRep::MSG_AS_REP,
        padata: None,
        crealm: realm("KERBER.TEST"),
        cname: sample_principal(),
        ticket: sample_ticket(),
        enc_part: enc_data(),
    }
}

fn sample_ap_req() -> ApReq {
    ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: sample_ticket(),
        authenticator: enc_data(),
    }
}

fn sample_krb_error() -> KrbError {
    KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: sample_time(),
        susec: 0,
        error_code: 6, // KDC_ERR_C_PRINCIPAL_UNKNOWN
        crealm: Some(realm("KERBER.TEST")),
        cname: Some(sample_principal()),
        realm: realm("KERBER.TEST"),
        sname: PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "KERBER.TEST"]),
        e_text: None,
        e_data: None,
    }
}

fn assert_round_trip<T>(value: &T)
where
    T: rasn::Encode + rasn::Decode + rasn::types::AsnType + PartialEq + std::fmt::Debug,
{
    let bytes = encode(value).expect("encode");
    assert!(!bytes.is_empty(), "DER must be non-empty");
    let decoded: T = decode(&bytes).expect("decode");
    assert_eq!(&decoded, value);
}

#[test]
fn round_trip_core_types() {
    install_json_tracing();
    assert_round_trip(&sample_principal());
    assert_round_trip(&realm("KERBER.TEST"));
    assert_round_trip(&enc_data());
    assert_round_trip(&sample_ticket());
    assert_round_trip(&sample_kdc_req());
    assert_round_trip(&sample_kdc_rep());
    assert_round_trip(&sample_ap_req());
    assert_round_trip(&sample_krb_error());
}

#[test]
fn truncated_principal_name_is_error() {
    install_json_tracing();
    let bytes = encode(&sample_principal()).unwrap();
    assert!(bytes.len() > 2);
    let truncated = &bytes[..bytes.len() / 2];
    let err = decode::<PrincipalName>(truncated).unwrap_err();
    assert!(matches!(err, Error::Decode(_)));
}

#[test]
fn truncated_ticket_is_error() {
    install_json_tracing();
    let bytes = encode(&sample_ticket()).unwrap();
    let err = decode::<Ticket>(&bytes[..3]).unwrap_err();
    assert!(matches!(err, Error::Decode(_)));
}

#[test]
fn truncated_kdc_req_is_error() {
    install_json_tracing();
    let bytes = encode(&sample_kdc_req()).unwrap();
    let err = decode::<KdcReq>(&bytes[..4]).unwrap_err();
    assert!(matches!(err, Error::Decode(_)));
}

#[test]
fn truncated_kdc_rep_is_error() {
    install_json_tracing();
    let bytes = encode(&sample_kdc_rep()).unwrap();
    let err = decode::<KdcRep>(&bytes[..5]).unwrap_err();
    assert!(matches!(err, Error::Decode(_)));
}

#[test]
fn truncated_ap_req_is_error() {
    install_json_tracing();
    let bytes = encode(&sample_ap_req()).unwrap();
    let err = decode::<ApReq>(&bytes[..4]).unwrap_err();
    assert!(matches!(err, Error::Decode(_)));
}

#[test]
fn truncated_krb_error_is_error() {
    install_json_tracing();
    let bytes = encode(&sample_krb_error()).unwrap();
    let err = decode::<KrbError>(&bytes[..4]).unwrap_err();
    assert!(matches!(err, Error::Decode(_)));
}

#[test]
fn malformed_bytes_are_errors_not_panics() {
    install_json_tracing();
    let junk = [0xff, 0x00, 0x01, 0x02, 0x03, 0x04];
    assert!(decode::<PrincipalName>(&junk).is_err());
    assert!(decode::<Ticket>(&junk).is_err());
    assert!(decode::<KdcReq>(&junk).is_err());
    assert!(decode::<KdcRep>(&junk).is_err());
    assert!(decode::<ApReq>(&junk).is_err());
    assert!(decode::<KrbError>(&junk).is_err());
    assert!(decode::<EncryptedData>(&junk).is_err());
    assert!(decode::<Realm>(&junk).is_err());
}

#[test]
fn empty_input_is_error() {
    install_json_tracing();
    assert!(decode::<PrincipalName>(&[]).is_err());
    assert!(decode::<Ticket>(&[]).is_err());
}
