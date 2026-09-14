//! Z1.4: every KDC long-term key lookup is MIT `krb5_dbe_find_enctype`
//! (`kdb_default.c:47-94`), which never returns a key whose enctype is outside
//! `permitted_enctypes` and, for the AS client key, looks only at the highest
//! kvno. Compiles at the parent `77d8a48` and fails there: `first_current_key`
//! / `key_for` took the first stored key regardless of `permitted_enctypes`
//! and `key_for` reached down to older kvnos.

use krb5_asn1::encode;
use krb5_crypto::EncryptionType;
use krb5_kdc::{
    KeyEntry, PrincipalStore, TEST_REALM, TEST_USER, as_req, bootstrap_documented, documented_host,
    pa_enc_timestamp, random_key,
};
use krb5_protocol::{as_req_sname, tgs_req};
use krb5_types::{PaData, PaPacRequest, PrincipalName, err, pa};

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha196;
const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

fn user_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn user_key(store: &PrincipalStore, etype: EncryptionType) -> krb5_crypto::ProtocolKey {
    store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .filter(|k| k.etype == etype)
        .max_by_key(|k| k.kvno)
        .expect("user key of that etype")
        .key
        .clone()
}

/// A realm whose KDC permits only aes256 (`[libdefaults] permitted_enctypes`).
fn store_permitting_aes256() -> PrincipalStore {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(store.policy().etype_permitted(AES256));
    assert!(!store.policy().etype_permitted(AES128));
    store
}

/// Replace `name`'s keys with fresh random keys of `etypes`, stored in that
/// order at one new kvno (kadmin `-e aes128:normal,aes256:normal`).
fn set_random_keys(store: &mut PrincipalStore, name: &PrincipalName, etypes: &[EncryptionType]) {
    let keys = etypes
        .iter()
        .map(|&e| KeyEntry::new(e, random_key(e).unwrap(), 0))
        .collect();
    store.set_keys(name, keys, 0).unwrap();
}

fn kinit(store: &PrincipalStore) -> krb5_kdc::IssuedAs {
    let padata = vec![pa_enc_timestamp(&user_key(store, AES256)).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0010, Some(padata)).unwrap();
    krb5_kdc::issue_as(store, &req).expect("AS issues")
}

fn kvno_host(
    store: &PrincipalStore,
    tgt: &krb5_kdc::IssuedAs,
) -> Result<krb5_kdc::IssuedTgs, krb5_kdc::Error> {
    let req = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user_name(),
        documented_host(),
        TEST_REALM,
        0x2600_0011,
    )
    .unwrap();
    krb5_kdc::issue_tgs(store, &req)
}

fn assert_finding_server_key<T: std::fmt::Debug>(got: Result<T, krb5_kdc::Error>) {
    match got {
        Err(krb5_kdc::Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::GENERIC, "KRB_ERR_GENERIC, got {text:?}");
            assert_eq!(text.as_deref(), Some("FINDING_SERVER_KEY"));
        }
        Err(other) => panic!("expected 60 FINDING_SERVER_KEY, got {other:?}"),
        Ok(v) => panic!("a server whose only keys are non-permitted must not get a ticket: {v:?}"),
    }
}

/// `do_tgs_req.c:1004` `get_first_current_key(server)`: the service ticket
/// is sealed with the first *permitted* key of the top kvno, so a server keyed
/// `-e aes128:normal,aes256:normal` under `permitted_enctypes = aes256` gets an
/// aes256 ticket, not the aes128 key stored first.
#[test]
fn z1_tgs_service_key_skips_a_non_permitted_first_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &documented_host(), &[AES128, AES256]);
    let tgt = kinit(&store);
    let tkt = kvno_host(&store, &tgt).expect("TGS issues under the aes256 key");
    assert_eq!(
        tkt.rep.0.ticket.enc_part.etype,
        AES256.to_iana(),
        "service ticket must be sealed with the permitted aes256 key, not the first-stored aes128"
    );
}

/// `kdb_default.c:92-94` `KRB5_KDB_NO_PERMITTED_KEY` → `do_tgs_req.c:1006`
/// `FINDING_SERVER_KEY`: a server with only non-permitted keys gets no ticket.
#[test]
fn z1_tgs_service_key_only_non_permitted_is_finding_server_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &documented_host(), &[AES128]);
    let tgt = kinit(&store);
    assert_finding_server_key(kvno_host(&store, &tgt));
}

/// `do_as_req.c:225` `get_first_current_key(server)`: the AS twin for the
/// TGT's own key — krbtgt keyed `[aes128, aes256]` seals TGTs with aes256.
#[test]
fn z1_as_server_key_skips_a_non_permitted_first_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(
        &mut store,
        &PrincipalName::krbtgt(TEST_REALM),
        &[AES128, AES256],
    );
    let tgt = kinit(&store);
    assert_eq!(
        tgt.rep.0.ticket.enc_part.etype,
        AES256.to_iana(),
        "TGT must be sealed with the permitted aes256 krbtgt key"
    );
}

/// `do_as_req.c:225-229`: krbtgt with only non-permitted keys →
/// 60 `FINDING_SERVER_KEY` (before `GET_LOCAL_TGT` is reached).
#[test]
fn z1_as_server_key_only_non_permitted_is_finding_server_key() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &PrincipalName::krbtgt(TEST_REALM), &[AES128]);
    let padata = vec![pa_enc_timestamp(&user_key(&store, AES256)).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0012, Some(padata)).unwrap();
    assert_finding_server_key(krb5_kdc::issue_as(&store, &req));
}

/// `do_as_req.c:119` `krb5_dbe_find_enctype(client, etype, -1, 0)`: a
/// requested etype the client has only at an *older* kvno does not select
/// that old key — the reply is 14 `CANT_FIND_CLIENT_KEY`.
#[test]
fn z1_as_client_key_is_chosen_at_the_highest_kvno_only() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let old_aes256 = user_key(&store, AES256);
    // cpw -keepold -e aes128:normal: the new top kvno holds aes128 only; the
    // aes256 key survives at the old kvno.
    let new = vec![KeyEntry::new(AES128, random_key(AES128).unwrap(), 0)];
    store.set_keys(&user_name(), new, 2).unwrap();
    let top = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(
        store
            .get_name(&user_name())
            .unwrap()
            .keys
            .iter()
            .any(|k| k.etype == AES256 && k.kvno < top),
        "the old aes256 key must still be stored below the top kvno"
    );
    let padata = vec![pa_enc_timestamp(&old_aes256).unwrap()];
    let req = as_req_sname(
        user_name(),
        TEST_REALM,
        0x2600_0013,
        Some(padata),
        PrincipalName::krbtgt(TEST_REALM),
        vec![AES256.to_iana()],
    )
    .unwrap();
    match krb5_kdc::issue_as(&store, &req) {
        Err(krb5_kdc::Error::Protocol { code, text, .. }) => {
            assert_eq!(
                code,
                err::ETYPE_NOSUPP,
                "KDC_ERR_ETYPE_NOSUPP, got {text:?}"
            );
            assert_eq!(text.as_deref(), Some("CANT_FIND_CLIENT_KEY"));
        }
        Err(other) => panic!("expected 14 CANT_FIND_CLIENT_KEY, got {other:?}"),
        Ok(_) => panic!("an etype present only at an older kvno must not select that key"),
    }
}

/// `kdc_preauth_encts.c:74-92` `krb5_dbe_search_enctype(client, etype, -1, 0)`:
/// the timestamp is tried against the keys of its etype at the client's
/// *highest* kvno only, so a stale keytab (the key kept by `cpw -keepold`)
/// is 24 `PREAUTH_FAILED` like a wrong password — MIT's familiar
/// "Preauthentication failed" for an outdated keytab.
#[test]
fn z1_enc_ts_under_a_retired_kvno_key_is_preauth_failed() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let stale = user_key(&store, AES256);
    // cpw -randkey -keepold: kvno 2 aes256 on top, the kvno-1 key retained.
    let new = vec![KeyEntry::new(AES256, random_key(AES256).unwrap(), 0)];
    store.set_keys(&user_name(), new, 2).unwrap();
    let p = store.get_name(&user_name()).unwrap();
    let top = p.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(
        p.keys.iter().any(|k| k.etype == AES256 && k.kvno < top),
        "the retired aes256 key must still be stored"
    );
    // Control: a timestamp under the current key issues.
    let padata = vec![pa_enc_timestamp(&user_key(&store, AES256)).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0015, Some(padata)).unwrap();
    krb5_kdc::issue_as(&store, &req).expect("current key issues");
    let padata = vec![pa_enc_timestamp(&stale).unwrap()];
    let req = as_req(user_name(), TEST_REALM, 0x2600_0016, Some(padata)).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let e: krb5_types::KrbError = krb5_asn1::decode(&bytes)
        .unwrap_or_else(|_| panic!("a timestamp under a retired kvno's key must be refused"));
    assert_eq!(e.error_code, err::PREAUTH_FAILED, "KDC_ERR_PREAUTH_FAILED");
}

/// `do_as_req.c:119` under `permitted_enctypes = aes256`: a requested aes128
/// the client *has* at the top kvno is skipped as non-permitted and the reply
/// is keyed with the next requested etype that is permitted.
#[test]
fn z1_as_client_key_skips_a_non_permitted_requested_etype() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &user_name(), &[AES128, AES256]);
    let padata = vec![
        pa_enc_timestamp(&user_key(&store, AES256)).unwrap(),
        PaData {
            padata_type: pa::PAC_REQUEST,
            padata_value: encode(&PaPacRequest { include_pac: false }).unwrap().into(),
        },
    ];
    let req = as_req_sname(
        user_name(),
        TEST_REALM,
        0x2600_0014,
        Some(padata),
        PrincipalName::krbtgt(TEST_REALM),
        vec![AES128.to_iana(), AES256.to_iana()],
    )
    .unwrap();
    let issued = krb5_kdc::issue_as(&store, &req).expect("AS issues with the aes256 client key");
    assert_eq!(
        issued.rep.0.enc_part.etype,
        AES256.to_iana(),
        "the AS-REP must be keyed with the permitted aes256 client key"
    );
}
