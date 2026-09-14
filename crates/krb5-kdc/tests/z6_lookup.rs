//! Z6.3: AS lookup `CANTLOCK_DB` is 29 with MIT's status word
//! (`do_as_req.c:579-590`, `:598-606`: remap to `SVC_UNAVAILABLE`, **then**
//! `LOOKING_UP_CLIENT` / `LOOKING_UP_SERVER`), and `KRB5KDC_ERR_DISCARD`
//! from a kdcpreauth module is passed through `filter_preauth_error`
//! (`kdc_preauth.c:1125`) and suppresses the reply (`do_as_req.c:371-372`).
//! Compiles at the parent: CANTLOCK was 29 with no e_text, and DISCARD was
//! rewritten to 24 `PREAUTH_FAILED`. Forge-only — no lockable KDB in tree.

use std::sync::Arc;

use krb5_asn1::decode;
use krb5_kdc::{
    Error, KdcEnv, KdcPreauth, Policy, Principal, PrincipalRead, PrincipalStore, TEST_REALM,
    TEST_USER, bootstrap_documented, register_preauth,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::pac::RpcSid;
use krb5_types::{KrbError, PrincipalName, err};

/// MIT `k5e1_err.et` `KRB5KDC_ERR_DISCARD` (table `k5e1` offset 3). A
/// library-local code, not an RFC 4120 wire number. Written as a literal so
/// this inject file compiles at the parent, which has no `err::DISCARD`.
const DISCARD: i32 = -1_750_600_189;

const PA_DISCARD: i32 = 30_001;

/// A store whose backend faults for one principal id.
struct Faulty<'a> {
    inner: &'a PrincipalStore,
    fail_id: String,
    fault: fn() -> Error,
}

impl PrincipalRead for Faulty<'_> {
    fn realm(&self) -> &str {
        <PrincipalStore as PrincipalRead>::realm(self.inner)
    }
    fn policy(&self) -> &Policy {
        <PrincipalStore as PrincipalRead>::policy(self.inner)
    }
    fn domain_sid(&self) -> &RpcSid {
        <PrincipalStore as PrincipalRead>::domain_sid(self.inner)
    }
    fn env(&self) -> &KdcEnv {
        <PrincipalStore as PrincipalRead>::env(self.inner)
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        if id == self.fail_id {
            return Err((self.fault)());
        }
        <PrincipalStore as PrincipalRead>::fetch(self.inner, id)
    }
    fn krbtgt_keys(&self) -> Result<Vec<krb5_crypto::ProtocolKey>, Error> {
        <PrincipalStore as PrincipalRead>::krbtgt_keys(self.inner)
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        <PrincipalStore as PrincipalRead>::list_ids(self.inner)
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        <PrincipalStore as PrincipalRead>::list_principals(self.inner)
    }
}

fn cantlock() -> Error {
    Error::Protocol {
        code: err::SVC_UNAVAILABLE,
        text: None,
        e_data: None,
        detail: Some("KRB5_KDB_CANTLOCK_DB".into()),
    }
}

/// AS-REQ with a valid PA-ENC-TIMESTAMP through a store that faults for
/// `fail_id`; returns (`error-code`, `e-text`).
fn as_error(fail_id: &str, fault: fn() -> Error) -> (i32, Option<String>) {
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
    let faulty = Faulty {
        inner: &store,
        fail_id: fail_id.to_owned(),
        fault,
    };
    let reply = krb5_kdc::handle_request(&faulty, &raw).expect("a KRB-ERROR reply");
    let e = decode::<KrbError>(&reply).expect("KRB-ERROR");
    (
        e.error_code,
        e.e_text
            .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned()),
    )
}

#[test]
fn z6_cantlock_on_client_is_29_looking_up_client() {
    let client_id = format!("{TEST_USER}@{TEST_REALM}");
    assert_eq!(
        as_error(&client_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_CLIENT".into()))
    );
}

#[test]
fn z6_cantlock_on_server_is_29_looking_up_server() {
    let tgs_id = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    assert_eq!(
        as_error(&tgs_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_SERVER".into()))
    );
}

struct DiscardMod;

impl KdcPreauth for DiscardMod {
    fn name(&self) -> &'static str {
        "z6-discard"
    }
    fn pa_types(&self) -> &'static [i32] {
        &[PA_DISCARD]
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
        let Some(p) = padata.and_then(|p| p.iter().find(|p| p.padata_type == PA_DISCARD)) else {
            return Ok(None);
        };
        let _ = p;
        Err(Error::Protocol {
            code: DISCARD,
            text: Some("DISCARD".into()),
            e_data: None,
            detail: None,
        })
    }
}

#[test]
fn z6_discard_module_failure_is_no_reply() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| register_preauth(Arc::new(DiscardMod)));
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(
        user,
        TEST_REALM,
        0x1b05,
        Some(vec![krb5_types::PaData {
            padata_type: PA_DISCARD,
            padata_value: b"x".to_vec().into(),
        }]),
    )
    .unwrap();
    let raw = krb5_asn1::encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(&store, &raw).expect("handle_request");
    assert!(
        reply.is_empty(),
        "DISCARD must suppress prepare_error_as; got {} bytes",
        reply.len()
    );
}
