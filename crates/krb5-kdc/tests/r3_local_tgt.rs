//! Remaining `GET_LOCAL_TGT` sites (`ad.rs` S4U2Proxy PAC / U2U) wire 60,
//! and `kdc_rd_ap_req` kvno 0 decrypts the previous kvno (`kdc_util.c:325-346`).

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    Error, KdcEnv, Policy, Principal, PrincipalRead, PrincipalStore, S2K_ITERS, TEST_ADMIN,
    TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_host, pa_enc_timestamp,
};
use krb5_protocol::tgs_req_ex;
use krb5_types::pac::RpcSid;
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let salt = cname.default_salt(TEST_REALM);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap()
}

fn issue_tgt(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = password_key(name, password);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

/// Header decrypt uses `ticket.server`; PAC/U2U still call `fetch_krbtgt`.
struct HideLocalTgt<'a>(&'a PrincipalStore);

impl PrincipalRead for HideLocalTgt<'_> {
    fn realm(&self) -> &str {
        self.0.realm()
    }
    fn policy(&self) -> &Policy {
        self.0.policy()
    }
    fn domain_sid(&self) -> &RpcSid {
        self.0.domain_sid()
    }
    fn env(&self) -> &KdcEnv {
        self.0.env()
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        PrincipalRead::fetch(self.0, id)
    }
    fn fetch_krbtgt(&self) -> Result<Option<Principal>, Error> {
        Ok(None)
    }
    fn krbtgt_keys(&self) -> Result<Vec<ProtocolKey>, Error> {
        PrincipalRead::krbtgt_keys(self.0)
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        PrincipalRead::list_ids(self.0)
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        PrincipalRead::list_principals(self.0)
    }
}

#[test]
fn s4u2proxy_missing_local_tgt_is_get_local_tgt() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_to(&user, &documented_host().components_joined());
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 731);
    let evidence_tgs = krb5_protocol::tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        732,
    )
    .unwrap();
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).unwrap();
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 733);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        734,
        opts,
        Some(vec![evidence.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&HideLocalTgt(&store), &tgs).unwrap_err();
    let (code, text) = proto(&err);
    assert_eq!(code, err::GENERIC);
    assert_eq!(text, Some("GET_LOCAL_TGT"));
}

#[test]
fn u2u_missing_local_tgt_is_get_local_tgt() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 741);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 742);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        743,
        opts,
        Some(vec![admin_tgt.rep.0.ticket.clone()]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&HideLocalTgt(&store), &tgs).unwrap_err();
    let (code, text) = proto(&err);
    assert_eq!(code, err::GENERIC);
    assert_eq!(text, Some("GET_LOCAL_TGT"));
}

#[test]
fn tgs_header_kvno_zero_decrypts_previous_kvno() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let issued = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 751);
    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    store.chrand_keepold_n(&krbtgt, 1).unwrap();
    let mut ticket = issued.rep.0.ticket.clone();
    ticket.enc_part.kvno = Some(0);
    let tgs = krb5_protocol::tgs_req(
        ticket,
        &issued.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        752,
    )
    .unwrap();
    krb5_kdc::issue_tgs(&store, &tgs).expect("kvno 0 walks back to the previous key");
}
