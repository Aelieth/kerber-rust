//! The string-to-key inputs an error's padata sets.
//! MIT `k5_get_etype_info` (`lib/krb5/krb/preauth2.c:790-854`): etype-info2, else etype-info, else the salt elements `get_salt` reads.

use super::{S2kMaterial, select_s2k_after};
use crate::error::Error;
use krb5_asn1::encode;
use krb5_crypto::EncryptionType;
use krb5_types::{
    EtypeInfo2Entry, EtypeInfoEntry, KerberosString, KerberosTime, KrbError, MethodData,
    Microseconds, PaData, PrincipalName, ascii, err, pa,
};

const SHA384_FIRST: [i32; 4] = [20, 19, 18, 17];

fn error_with(method: Option<MethodData>) -> KrbError {
    KrbError {
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
        e_data: method.map(|m| encode(&m).unwrap().into()),
    }
}

fn pa_of(padata_type: i32, value: Vec<u8>) -> PaData {
    PaData {
        padata_type,
        padata_value: value.into(),
    }
}

fn info2(etypes: &[i32], salt: Option<&str>) -> PaData {
    let entries: Vec<EtypeInfo2Entry> = etypes
        .iter()
        .map(|&etype| EtypeInfo2Entry {
            etype,
            salt: salt.map(|s| KerberosString::try_from(s).unwrap()),
            s2kparams: None,
        })
        .collect();
    pa_of(pa::ETYPE_INFO2, encode(&entries).unwrap())
}

fn after(method: Option<MethodData>, prev: S2kMaterial) -> Result<S2kMaterial, Error> {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    select_s2k_after(
        &error_with(method),
        &cname,
        "KERBER.TEST",
        &SHA384_FIRST,
        prev,
    )
}

fn prev() -> S2kMaterial {
    (
        EncryptionType::Aes256CtsHmacSha196,
        b"PREVSALT".to_vec(),
        Some(vec![0, 0, 16, 0]),
    )
}

#[test]
fn etype_info2_names_the_first_requested_enctype_it_lists() {
    let got = after(Some(vec![info2(&[17, 18], Some("SALT"))]), prev()).unwrap();
    assert_eq!(
        got,
        (EncryptionType::Aes256CtsHmacSha196, b"SALT".to_vec(), None)
    );
    let got = after(Some(vec![info2(&[18], None)]), prev()).unwrap();
    assert_eq!(got.1, b"KERBER.TESTuser");
}

#[test]
fn etype_info_that_names_no_requested_enctype_fails_as_mit_does() {
    // A valid enctype the request did not ask for: KRB5_CONFIG_ETYPE_NOSUPP.
    let got = after(Some(vec![info2(&[23], None)]), prev());
    assert_eq!(got, Err(Error::ConfigEtypeNosupp));
    // No enctype this client has at all: KRB5_PROG_ETYPE_NOSUPP.
    let got = after(Some(vec![info2(&[999], None)]), prev());
    assert_eq!(got, Err(Error::ProgEtypeNosupp));
    // ETYPE-INFO is read the same way when there is no ETYPE-INFO2.
    let old = vec![EtypeInfoEntry {
        etype: 999,
        salt: None,
    }];
    let got = after(
        Some(vec![pa_of(pa::ETYPE_INFO, encode(&old).unwrap())]),
        prev(),
    );
    assert_eq!(got, Err(Error::ProgEtypeNosupp));
}

#[test]
fn without_etype_info_a_salt_element_sets_the_salt_alone() {
    let got = after(Some(vec![pa_of(pa::PW_SALT, b"PWSALT".to_vec())]), prev()).unwrap();
    assert_eq!(
        got,
        (
            EncryptionType::Aes256CtsHmacSha196,
            b"PWSALT".to_vec(),
            Some(vec![0, 0, 16, 0])
        )
    );
    // An afs3-salt ends at '@', drops a trailing NUL, and asks for AFS string-to-key.
    let got = after(
        Some(vec![pa_of(pa::AFS3_SALT, b"CELL@REALM\0".to_vec())]),
        prev(),
    )
    .unwrap();
    assert_eq!(got.1, b"CELL");
    assert_eq!(got.2, Some(vec![1]));
    let got = after(Some(vec![pa_of(pa::AFS3_SALT, b"CELL\0".to_vec())]), prev()).unwrap();
    assert_eq!(got.1, b"CELL");
}

#[test]
fn nothing_named_leaves_what_an_earlier_error_set() {
    assert_eq!(after(None, prev()).unwrap(), prev());
    assert_eq!(after(Some(Vec::new()), prev()).unwrap(), prev());
    // An etype-info element that does not decode counts as absent.
    let got = after(
        Some(vec![
            pa_of(pa::ETYPE_INFO2, Vec::new()),
            pa_of(pa::PW_SALT, b"PWSALT".to_vec()),
        ]),
        prev(),
    )
    .unwrap();
    assert_eq!(got.1, b"PWSALT");
}
