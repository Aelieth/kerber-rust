//! W1-Z Z1b.3: the KRB-ERROR encoder applies MIT `errcode_to_protocol`
//! (`kdc_util.c:691-697`, called at `do_as_req.c:804` / `do_tgs_req.c:199`):
//! only 0..=128 is a protocol error-code, anything else goes out as
//! `KRB_ERR_GENERIC` 60. Reachable only through a `KdcPolicy` handing back a
//! raw code (no in-tree path does). Compiles at `59c363b` (parent-red): the
//! parent put the raw code on the wire.

use std::sync::Arc;

use krb5_asn1::decode;
use krb5_kdc::{
    Error, KdcPolicy, PolicyAdjustment, Principal, PrincipalRead, TEST_REALM, TEST_USER,
    bootstrap_documented, clear_thread_policy, set_thread_policy,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::{KrbError, PrincipalName, err};

/// A third-party policy denying with a *library* code, not a protocol one.
struct RawCodePolicy(i32);

impl KdcPolicy for RawCodePolicy {
    fn check_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Err(Error::Protocol {
            code: self.0,
            text: Some("RAW_POLICY".into()),
            e_data: None,
            detail: None,
        })
    }
    fn check_tgs(
        &self,
        _store: &dyn PrincipalRead,
        _sname: &PrincipalName,
        _indicators: &[String],
    ) -> Result<PolicyAdjustment, Error> {
        Ok(PolicyAdjustment::default())
    }
}

fn wire_error_code(raw_policy_code: i32) -> i32 {
    set_thread_policy(Arc::new(RawCodePolicy(raw_policy_code)));
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user,
        TEST_REALM,
        0x1b03,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let raw = krb5_asn1::encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).expect("a KRB-ERROR reply");
    clear_thread_policy();
    decode::<KrbError>(&reply).expect("KRB-ERROR").error_code
}

#[test]
fn z1b_policy_raw_library_code_reaches_the_wire_as_generic_60() {
    // Outside 0..=128 (a com_err library value the module forgot to map).
    assert_eq!(wire_error_code(1_000_000), err::GENERIC);
    assert_eq!(wire_error_code(-1_765_328_361), err::GENERIC);
    // Inside the protocol range it is passed through (`:697`).
    assert_eq!(wire_error_code(err::POLICY), err::POLICY);
}

/// A third-party kdcpreauth module owning one private PA type; fails with
/// whatever its request's first byte says.
struct FailingModule;

const PA_PRIVATE: i32 = 30_000;

impl krb5_kdc::KdcPreauth for FailingModule {
    fn name(&self) -> &'static str {
        "z1b-failing"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[PA_PRIVATE]
    }
    fn advertise(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        _armor: bool,
        _requested: &[i32],
    ) -> Vec<krb5_types::PaData> {
        Vec::new()
    }
    fn process_as(
        &self,
        _store: &dyn PrincipalRead,
        _client: &Principal,
        padata: Option<&[krb5_types::PaData]>,
        _ikey: &krb5_crypto::ProtocolKey,
        _etype: krb5_crypto::EncryptionType,
        _as_req_der: &[u8],
        _body_der: &[u8],
        _cname: &PrincipalName,
    ) -> Result<Option<krb5_kdc::PreauthAction>, Error> {
        let Some(p) = padata.and_then(|p| p.iter().find(|p| p.padata_type == PA_PRIVATE)) else {
            return Ok(None);
        };
        Err(match p.padata_value.as_ref() {
            [0] => Error::Protocol {
                code: err::GENERIC,
                text: Some("MODULE_STATUS".into()),
                e_data: None,
                detail: None,
            },
            [1] => Error::Protocol {
                code: err::SKEW,
                text: Some("MODULE_SKEW_STATUS".into()),
                e_data: None,
                detail: None,
            },
            [2] => Error::Asn1("module decode".into()),
            [3] => Error::Protocol {
                code: err::POLICY,
                text: Some("MODULE_POLICY".into()),
                e_data: None,
                detail: None,
            },
            _ => Error::Protocol {
                code: err::PREAUTH_EXPIRED,
                text: Some("PREAUTH_FAILED".into()),
                e_data: None,
                detail: None,
            },
        })
    }
}

fn module_wire_error(selector: u8) -> (i32, Option<String>) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| krb5_kdc::register_preauth(Arc::new(FailingModule)));
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        user,
        TEST_REALM,
        0x1b05,
        Some(vec![krb5_types::PaData {
            padata_type: PA_PRIVATE,
            padata_value: vec![selector].into(),
        }]),
    )
    .unwrap();
    let raw = krb5_asn1::encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).expect("a KRB-ERROR reply");
    let e = decode::<KrbError>(&reply).expect("KRB-ERROR");
    (
        e.error_code,
        e.e_text
            .as_ref()
            .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned()),
    )
}

/// `filter_preauth_error` at the module boundary (`kdc_preauth.c:1206`): a
/// code off the pass-through list, or a non-protocol failure, is 24 under
/// the `PREAUTH_FAILED` status (`do_as_req.c:442`); a listed code keeps
/// itself. At `7a44ef8` the module's own code and status went on the wire.
#[test]
fn z1b_module_failures_pass_through_the_filter_like_kdc_preauth() {
    assert_eq!(
        module_wire_error(0),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "60 GENERIC is not on the list"
    );
    assert_eq!(
        module_wire_error(1),
        (err::SKEW, Some("PREAUTH_FAILED".into())),
        "37 SKEW passes; the status word is still finish_preauth's"
    );
    assert_eq!(
        module_wire_error(2),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "an ASN.1 failure is 24"
    );
    assert_eq!(
        module_wire_error(3),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "12 POLICY is not on the list"
    );
    assert_eq!(
        module_wire_error(4),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "90 PREAUTH_EXPIRED is not on the list"
    );
}
