//! W1-Z Z1b.3 follow-up: AS client/server lookup faults are labelled like
//! MIT `do_as_req.c:577-607` — `CANTLOCK_DB` is 29 `SVC_UNAVAILABLE` on
//! either lookup, any other backend fault is 60 with the lookup's own status
//! word (`LOOKING_UP_CLIENT` / `LOOKING_UP_SERVER`). No in-tree store fails a
//! lookup; a `PrincipalRead` wrapper stands in for a backend that does.
//! Compiles at `7a44ef8` (parent-red): the parent labelled a server-lookup
//! fault `LOOKING_UP_CLIENT` (the catch-all arm).

use krb5_asn1::decode;
use krb5_kdc::{
    Error, KdcEnv, Policy, Principal, PrincipalRead, PrincipalStore, TEST_REALM, TEST_USER,
    bootstrap_documented,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::pac::RpcSid;
use krb5_types::{KrbError, PrincipalName, err};

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

fn backend_fault() -> Error {
    Error::InvalidArgument("backend: disk read failed".into())
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
fn z1b_as_lookup_faults_are_labelled_like_do_as_req() {
    let client_id = format!("{TEST_USER}@{TEST_REALM}");
    let tgs_id = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    // :588-590 — a client-lookup fault is 60 LOOKING_UP_CLIENT.
    assert_eq!(
        as_error(&client_id, backend_fault),
        (err::GENERIC, Some("LOOKING_UP_CLIENT".into()))
    );
    // :604-606 — a server-lookup fault is 60 LOOKING_UP_SERVER (the parent
    // said LOOKING_UP_CLIENT for every fault after the decode).
    assert_eq!(
        as_error(&tgs_id, backend_fault),
        (err::GENERIC, Some("LOOKING_UP_SERVER".into()))
    );
    // :579-580, :598-599 — CANTLOCK_DB on either lookup is 29, no status.
    assert_eq!(as_error(&client_id, cantlock), (err::SVC_UNAVAILABLE, None));
    assert_eq!(as_error(&tgs_id, cantlock), (err::SVC_UNAVAILABLE, None));
}
