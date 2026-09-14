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
