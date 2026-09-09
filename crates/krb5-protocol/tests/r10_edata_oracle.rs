//! Parent-red fixtures for R10 e_data oracle (multiset / crealm presence).
//!
//! These call the shipped `compare_*` path. At the Round 3 parent they FAIL
//! because extras were tolerated and `stable_krb_error` was crealm-blind.
//! TYPED-DATA decode is covered by lib `diff_compare::typed_edata_types_must_match`
//! (needs the TypedData encode fix in the same commit).

use krb5_asn1::{decode, encode};
use krb5_protocol::{compare_krb_error, compare_preauth_e_data};
use krb5_types::{
    EtypeInfo2, EtypeInfo2Entry, KerberosTime, KrbError, MethodData, Microseconds, PaData,
    PrincipalName, err, pa,
};

fn method_edata(etypes: &[i32]) -> Vec<u8> {
    let info: EtypeInfo2 = etypes
        .iter()
        .map(|&etype| EtypeInfo2Entry {
            etype,
            salt: None,
            s2kparams: None,
        })
        .collect();
    let info_der = encode(&info).expect("ETYPE-INFO2");
    let md: MethodData = vec![
        PaData {
            padata_type: pa::FX_FAST,
            padata_value: vec![].into(),
        },
        PaData {
            padata_type: pa::ENC_TIMESTAMP,
            padata_value: vec![].into(),
        },
        PaData {
            padata_type: pa::ETYPE_INFO2,
            padata_value: info_der.into(),
        },
        PaData {
            padata_type: pa::FX_COOKIE,
            padata_value: b"MIT".to_vec().into(),
        },
    ];
    encode(&md).expect("METHOD-DATA")
}

fn sample_error(code: i32, stime_off: i64, text: &str) -> KrbError {
    let stime = KerberosTime::now()
        .add_seconds(stime_off)
        .unwrap_or_else(|_| KerberosTime::now());
    KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime,
        susec: Microseconds::ZERO,
        error_code: code,
        crealm: None,
        cname: None,
        realm: krb5_types::try_ascii("KERBER.TEST").unwrap(),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: krb5_types::try_ascii(text).ok(),
        e_data: None,
    }
}

#[test]
fn preauth_edata_type_multiset_rejects_extra_spake() {
    let base = method_edata(&[18]);
    let mut with_spake: MethodData = decode(&base).expect("METHOD-DATA");
    with_spake.push(PaData {
        padata_type: pa::SPAKE,
        padata_value: vec![].into(),
    });
    let with = encode(&with_spake).expect("METHOD-DATA");
    let err = compare_preauth_e_data(Some(&with), Some(&base))
        .expect_err("SPAKE on only one leg must fail the multiset");
    assert!(
        err.0.contains("multiset"),
        "compare must name the type multiset: {}",
        err.0
    );
}

#[test]
fn krb_error_crealm_cname_presence_is_compared() {
    let mut rust = sample_error(err::GENERIC, 0, "UNKNOWN_REASON");
    let mit = sample_error(err::GENERIC, 7, "UNKNOWN_REASON");
    compare_krb_error(&rust, &mit).expect("both omit client");
    rust.crealm = Some(krb5_types::try_ascii("KERBER.TEST").unwrap());
    let err = compare_krb_error(&rust, &mit).expect_err("crealm presence must fail");
    assert!(
        err.0.contains("stable mismatch"),
        "stable_krb_error must carry has_crealm: {}",
        err.0
    );
}
