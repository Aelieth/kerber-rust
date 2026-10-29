//! Acceptor key selection uses the ticket kvno and etype, like MIT `rd_req_dec.c`
//! (`try_one_princ` → `krb5_kt_get_entry(..., tkt_kvno, tkt_etype)`): only the matching key
//! is tried, never every key.

#[path = "common/mod.rs"]
mod common;
use common::client_key;
use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::{
    ApVerifyParams, DEFAULT_SKEW, KeytabLookup, ReplayCache, address_search, build_ap_req,
    verify_ap_req_ex,
};
use krb5_types::{
    ApReq, EncTicketPart, HostAddress, KerberosTime, PrincipalName, TransitedEncoding, err,
    flag_bit, ku,
};
use std::collections::BTreeMap;

/// No `[capaths]`, for the parameters that outlive the function that makes them.
static NO_CAPATHS: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
static PERMITTED: [EncryptionType; 5] = [
    EncryptionType::Aes256CtsHmacSha196,
    EncryptionType::Aes128CtsHmacSha196,
    EncryptionType::Aes256CtsHmacSha384192,
    EncryptionType::Aes128CtsHmacSha256128,
    EncryptionType::Des3CbcSha1,
];

fn host_ap_req() -> (Vec<u8>, ProtocolKey, u32) {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        0x2000_0001,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2000_0002,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let ap = build_ap_req(
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &cname,
    )
    .expect("AP-REQ");
    let raw = encode(&ap).expect("encode");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .expect("keytab");
    let ent = kt.entries.into_iter().next().expect("host key");
    (raw, ent.key, ent.kvno)
}

/// The acceptor's parameters for a keytab walk: no server named, as MIT's `krb5_rd_req` with a
/// NULL server.
fn walk(keys: &[ProtocolKey], kvnos: &[u32]) -> ApVerifyParams<'static> {
    ApVerifyParams {
        keys: Box::leak(keys.to_vec().into_boxed_slice()),
        key_kvnos: Some(Box::leak(kvnos.to_vec().into_boxed_slice())),
        key_principals: None,
        kvno: None,
        permitted: &PERMITTED,
        expected_server: None,
        expected_realm: None,
        get_entry: None,
        skew: DEFAULT_SKEW,
        ignore_acceptor_hostname: false,
        capaths: &NO_CAPATHS,
        remote_addr: None,
        now: None,
    }
}

fn walk_code(raw: &[u8], keys: &[ProtocolKey], kvnos: &[u32]) -> (i32, String) {
    match verify_ap_req_ex(raw, &walk(keys, kvnos), &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, text }) => (code, text.unwrap_or_default()),
        other => panic!("expected a KRB-ERROR code, got {other:?}"),
    }
}

// MIT: `decrypt_try_server` (rd_req_dec.c:355-443)
/// with no server, every key of the ticket's enctype is tried, whatever its kvno.
#[test]
fn rd_req_keytab_walk_tries_every_kvno() {
    let (raw, key, kvno) = host_ap_req();
    assert_eq!(kvno, 1);
    let other = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[9u8; 32]).unwrap();
    verify_ap_req_ex(
        &raw,
        &walk(&[other, key], &[2, 2]),
        &ReplayCache::new(),
        None,
    )
    .expect("the right key at another kvno decrypts the ticket");
}

// MIT: `iteration_error` (rd_req_dec.c:264-270)
/// a key at the ticket's kvno and enctype that does not decrypt it is BAD_INTEGRITY.
#[test]
fn rd_req_keytab_walk_wrong_key_at_the_ticket_kvno_is_bad_integrity() {
    let (raw, _, kvno) = host_ap_req();
    let dummy = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
    let (code, text) = walk_code(&raw, &[dummy], &[kvno]);
    assert_eq!(code, err::BAD_INTEGRITY);
    assert!(
        text.contains("found in keytab but cannot decrypt ticket"),
        "{text}"
    );
}

// MIT: `iteration_error` (rd_req_dec.c:244-256)
/// no key at the ticket's kvno is BADKEYVER, and a higher one says the ticket is out of date.
#[test]
fn rd_req_keytab_walk_without_the_ticket_kvno_is_badkeyver() {
    let (raw, _, kvno) = host_ap_req();
    let dummy = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
    let (code, text) = walk_code(&raw, std::slice::from_ref(&dummy), &[kvno + 1]);
    assert_eq!(code, err::BADKEYVER);
    assert!(text.ends_with("ticket is likely out of date"), "{text}");
    let mut ap: ApReq = decode(&raw).expect("AP-REQ");
    ap.ticket.enc_part.kvno = Some(kvno + 5);
    let (code, text) = walk_code(&encode(&ap).expect("encode"), &[dummy], &[kvno]);
    assert_eq!(code, err::BADKEYVER);
    assert!(text.ends_with("keytab is likely out of date"), "{text}");
}

// MIT: `iteration_error` (rd_req_dec.c:257-263)
/// a key at the ticket's kvno but of another enctype is BADKEYVER.
#[test]
fn rd_req_keytab_walk_without_the_ticket_enctype_is_badkeyver() {
    let (raw, _, kvno) = host_ap_req();
    let aes128 = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[3u8; 16]).unwrap();
    let (code, text) = walk_code(&raw, &[aes128], &[kvno]);
    assert_eq!(code, err::BADKEYVER);
    assert!(
        text.contains("found in keytab but not with enctype"),
        "{text}"
    );
}

// MIT: `iteration_error` (rd_req_dec.c:239-243)
/// keys only for other principals are NOT_US.
#[test]
fn rd_req_keytab_walk_without_the_ticket_server_is_not_us() {
    let (raw, _, kvno) = host_ap_req();
    let dummy = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
    let keys = [dummy];
    let kvnos = [kvno];
    let other = [(
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "other.kerber.test"]),
        krb5_types::ascii(TEST_REALM),
    )];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&kvnos),
        key_principals: Some(&other),
        ..ApVerifyParams::single_key(&keys[0])
    };
    match verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, text }) => {
            assert_eq!(code, err::NOT_US);
            assert!(text.unwrap_or_default().contains("not found in keytab"));
        }
        other => panic!("expected NOT_US, got {other:?}"),
    }
}

#[test]
fn rd_req_authenticator_skew_is_skew() {
    let (raw, key, _) = host_ap_req();
    let now = KerberosTime::now();
    let far = KerberosTime::from_unix_seconds(now.unix_seconds().saturating_add(10_000));
    let keys = [key];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: None,
        key_principals: None,
        kvno: None,
        permitted: &PERMITTED,
        expected_server: None,
        expected_realm: None,
        get_entry: None,
        skew: DEFAULT_SKEW,
        ignore_acceptor_hostname: false,
        capaths: &NO_CAPATHS,
        remote_addr: None,
        now: Some(far),
    };
    match verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => assert_eq!(code, err::SKEW),
        other => panic!("expected SKEW, got {other:?}"),
    }
}

fn rewrite_ticket(raw: &[u8], key: &ProtocolKey, f: impl FnOnce(&mut EncTicketPart)) -> Vec<u8> {
    let mut ap: ApReq = decode(raw).expect("AP-REQ");
    let usage = KeyUsage::new(ku::TICKET).expect("ku");
    let plain = decrypt(key, usage, ap.ticket.enc_part.cipher.as_ref()).expect("dec");
    let mut part: EncTicketPart = decode(&plain).expect("EncTicketPart");
    f(&mut part);
    let new_plain = encode(&part).expect("enc part");
    ap.ticket.enc_part.cipher = encrypt(key, usage, &new_plain).expect("enc").into();
    encode(&ap).expect("AP-REQ")
}

fn verify(
    raw: &[u8],
    key: &ProtocolKey,
) -> Result<krb5_protocol::ApVerifyOk, krb5_protocol::Error> {
    let keys = [key.clone()];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: None,
        key_principals: None,
        kvno: None,
        permitted: &PERMITTED,
        expected_server: None,
        expected_realm: None,
        get_entry: None,
        skew: DEFAULT_SKEW,
        ignore_acceptor_hostname: false,
        capaths: &NO_CAPATHS,
        remote_addr: None,
        now: None,
    };
    verify_ap_req_ex(raw, &params, &ReplayCache::new(), None)
}

#[test]
fn rd_req_transited_unchecked_one_realm_is_no_tkt_in_rlm() {
    let (raw, key, _) = host_ap_req();
    let raw2 = rewrite_ticket(&raw, &key, |part| {
        part.flags = part
            .flags
            .clone()
            .with_bit(flag_bit::TRANSITED_POLICY_CHECKED, false);
        part.transited = TransitedEncoding::from_realms(&["EVIL.COM"]);
    });
    match verify(&raw2, &key) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => assert_eq!(code, err::NO_TKT_IN_RLM),
        other => panic!("expected NO_TKT_IN_RLM, got {other:?}"),
    }
}

fn host_ap_req_forged(mutate: impl FnOnce(&mut EncTicketPart)) -> (Vec<u8>, ProtocolKey) {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = client_key();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        0x2300_0001,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2300_0002,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let ap = build_ap_req(
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &cname,
    )
    .expect("AP-REQ");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .expect("keytab");
    let host_key = kt.entries.into_iter().next().expect("host key").key;

    let mut ap: ApReq = ap;
    let usage = KeyUsage::new(ku::TICKET).expect("usage");
    let plain = decrypt(&host_key, usage, ap.ticket.enc_part.cipher.as_ref()).expect("decrypt tkt");
    let mut part: EncTicketPart = decode(&plain).expect("EncTicketPart");
    mutate(&mut part);
    let der = encode(&part).expect("encode part");
    let cipher = encrypt(&host_key, usage, &der).expect("reseal");
    ap.ticket.enc_part.cipher = cipher.into();
    let raw = encode(&ap).expect("encode ap");
    (raw, host_key)
}

fn accept(raw: &[u8], key: &ProtocolKey) -> Result<(), krb5_protocol::Error> {
    let keys = [key.clone()];
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: None,
        key_principals: None,
        kvno: None,
        permitted: &PERMITTED,
        expected_server: None,
        expected_realm: None,
        get_entry: None,
        skew: DEFAULT_SKEW,
        ignore_acceptor_hostname: false,
        capaths: &NO_CAPATHS,
        remote_addr: None,
        now: None,
    };
    verify_ap_req_ex(raw, &params, &ReplayCache::new(), None).map(|_| ())
}

#[test]
fn no_starttime_future_authtime_is_nyv() {
    // MIT: `krb5int_validate_times` (valid_times.c:44-51)
    // starttime==0 falls back to authtime;
    // a ticket whose authtime is well beyond the skew is not yet valid.
    let far = KerberosTime::now()
        .add_seconds(DEFAULT_SKEW + 3600)
        .unwrap();
    let (raw, key) = host_ap_req_forged(|part| {
        part.starttime = None;
        part.authtime = far.clone();
    });
    match accept(&raw, &key) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => {
            assert_eq!(code, krb5_types::err::TKT_NYV);
        }
        other => panic!("expected NYV, got {other:?}"),
    }
}

#[test]
fn invalid_flag_is_tkt_invalid() {
    // MIT: `rd_req_decoded_opt` (rd_req_dec.c:634-638)
    // the INVALID flag yields
    // KRB5KRB_AP_ERR_TKT_INVALID (offset 145), distinct from TKT_NYV.
    let (raw, key) = host_ap_req_forged(|part| {
        part.flags = part.flags.clone().with_bit(flag_bit::INVALID, true);
    });
    match accept(&raw, &key) {
        Err(krb5_protocol::Error::KrbError { code, .. }) => {
            // 145 = MIT KRB5KRB_AP_ERR_TKT_INVALID (krb5_err.et offset), not 33
            // TKT_NYV.
            assert_eq!(code, 145, "KRB5KRB_AP_ERR_TKT_INVALID");
        }
        other => panic!("expected TKT_INVALID, got {other:?}"),
    }
}

#[test]
fn pinned_name_wrong_kvno_is_badkeyver() {
    // MIT: `decrypt_try_server` (rd_req_dec.c:374-376)
    // an explicit server goes to
    // try_one_princ → krb5_kt_get_entry(princ, kvno, etype).
    // MIT: `krb5_ktfile_get_entry` (kt_file.c:380-384)
    // an entry for the principal+enctype at
    // another kvno is KRB5_KT_KVNONOTFOUND.
    // MIT: `keytab_fetch_error` (rd_req_dec.c:139-148)
    // maps it to KRB5KRB_AP_ERR_BADKEYVER
    // (44) "Cannot find key for %s kvno %d in keytab" when the pinned name is the ticket's
    // server. Parent: 45 NOKEY.
    let (raw, key) = host_ap_req_forged(|_| {});
    let ap: ApReq = decode(&raw).expect("AP-REQ");
    let tkt_kvno = ap.ticket.enc_part.kvno.expect("ticket kvno");
    let keys = [key];
    let kvnos = [tkt_kvno + 1];
    let server = documented_host();
    let params = ApVerifyParams {
        keys: &keys,
        key_kvnos: Some(&kvnos),
        key_principals: None,
        kvno: None,
        permitted: &PERMITTED,
        expected_server: Some(&server),
        expected_realm: Some(TEST_REALM),
        get_entry: None,
        skew: DEFAULT_SKEW,
        ignore_acceptor_hostname: false,
        capaths: &NO_CAPATHS,
        remote_addr: None,
        now: None,
    };
    match verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, text }) => {
            assert_eq!(code, krb5_types::err::BADKEYVER, "KRB5KRB_AP_ERR_BADKEYVER");
            let text = text.unwrap_or_default();
            assert!(
                text.starts_with("Cannot find key for host/")
                    && text.ends_with(&format!("kvno {tkt_kvno} in keytab")),
                "MIT keytab_fetch_error text, got {text:?}"
            );
        }
        other => panic!("expected BADKEYVER, got {other:?}"),
    }
}

/// The sender's address is searched for in the ticket's address list as MIT searches it: a
/// ticket without a list, or whose list is one NetBIOS address, holds any address; an empty
/// list holds none; otherwise the address must be one of the list's.
// MIT: `krb5_address_search` (lib/krb5/krb/addr_srch.c:48-65)
/// the rules.
#[test]
fn a_sender_address_is_searched_for_in_the_ticket_addresses_as_mits() {
    let inet = |o: [u8; 4]| HostAddress {
        addr_type: HostAddress::ADDRTYPE_INET,
        address: o.to_vec().into(),
    };
    let netbios = HostAddress {
        addr_type: HostAddress::ADDRTYPE_NETBIOS,
        address: b"HOST            ".to_vec().into(),
    };
    let a = inet([10, 0, 0, 1]);
    assert!(address_search(&a, None), "no list");
    assert!(
        address_search(&a, Some(&vec![netbios.clone()])),
        "a lone NetBIOS address"
    );
    assert!(
        address_search(&a, Some(&vec![inet([10, 0, 0, 2]), a.clone()])),
        "one of two"
    );
    assert!(
        !address_search(&a, Some(&vec![inet([10, 0, 0, 2])])),
        "another address"
    );
    assert!(!address_search(&a, Some(&vec![])), "an empty list");
    assert!(
        !address_search(&a, Some(&vec![netbios, inet([10, 0, 0, 2])])),
        "NetBIOS beside another"
    );
}

/// The parameters of an acceptor that names its server and looks the key up in a keytab by principal, as
/// `krb5_rd_req` does with a server and the KDB keytab: `get_entry` is the lookup.
fn named<'a>(
    server: &'a PrincipalName,
    get_entry: krb5_protocol::KeytabGetEntry<'a>,
) -> ApVerifyParams<'a> {
    ApVerifyParams {
        keys: &[],
        key_kvnos: None,
        key_principals: None,
        kvno: None,
        permitted: &PERMITTED,
        expected_server: Some(server),
        expected_realm: Some(TEST_REALM),
        get_entry: Some(get_entry),
        skew: DEFAULT_SKEW,
        ignore_acceptor_hostname: false,
        capaths: &NO_CAPATHS,
        remote_addr: None,
        now: None,
    }
}

fn named_code(raw: &[u8], params: &ApVerifyParams<'_>) -> (i32, String) {
    match verify_ap_req_ex(raw, params, &ReplayCache::new(), None) {
        Err(krb5_protocol::Error::KrbError { code, text }) => (code, text.unwrap_or_default()),
        other => panic!("expected a KRB-ERROR code, got {other:?}"),
    }
}

/// A ticket that decrypts under the named server's keytab key is that server's, whatever server its
/// cleartext names: the keytab principal replaces it.
// MIT: `try_one_entry` (rd_req_dec.c:315-317)
/// the keytab principal becomes the ticket's server.
// MIT: `try_one_princ` (rd_req_dec.c:325-347)
/// never compares the cleartext one.
#[test]
fn rd_req_with_a_named_server_takes_the_keytab_principal_for_the_tickets() {
    let (raw, key, kvno) = host_ap_req();
    let other = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let asked = std::cell::RefCell::new((
        PrincipalName::new(0, [""]),
        String::new(),
        u32::MAX,
        i32::MAX,
    ));
    let lookup = |n: &PrincipalName, r: &str, k: u32, e: i32| {
        asked.replace((n.clone(), r.to_owned(), k, e));
        Ok(key.clone())
    };
    let ok = verify_ap_req_ex(&raw, &named(&other, &lookup), &ReplayCache::new(), None)
        .expect("the key decrypts it");
    assert_eq!(
        asked.into_inner(),
        (other.clone(), TEST_REALM.to_owned(), kvno, 18),
        "the lookup is for the named server, at the ticket's kvno and enctype"
    );
    assert_eq!(
        ok.sname, other,
        "the keytab principal is the ticket's server"
    );
    assert_eq!(ok.srealm.as_bytes(), TEST_REALM.as_bytes());
    // With bare keys no principal is known, so the ticket's own server must be the named one.
    let mut by_key = ApVerifyParams::single_key(&key);
    by_key.expected_server = Some(&other);
    by_key.expected_realm = Some(TEST_REALM);
    assert_eq!(
        named_code(&raw, &by_key).0,
        err::NOT_US,
        "a key slice keeps its pin on the ticket's server"
    );
}

// MIT: `keytab_fetch_error` (rd_req_dec.c:118-148)
/// an explicit server the keytab does not hold is
/// NOKEY; a kvno it does not hold is BADKEYVER when the named server is the ticket's and NOT_US when
/// not; any other code passes through.
#[test]
fn rd_req_with_a_named_server_maps_the_keytab_codes_as_keytab_fetch_error() {
    let (raw, _, _) = host_ap_req();
    let host = documented_host();
    let elsewhere =
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "elsewhere.kerber.test"]);
    let no_entry = |_: &PrincipalName, _: &str, _: u32, _: i32| Err(KeytabLookup::NotFound);
    assert_eq!(named_code(&raw, &named(&host, &no_entry)).0, err::NOKEY);
    let no_kvno = |_: &PrincipalName, _: &str, _: u32, _: i32| Err(KeytabLookup::KvnoNotFound);
    assert_eq!(named_code(&raw, &named(&host, &no_kvno)).0, err::BADKEYVER);
    assert_eq!(
        named_code(&raw, &named(&elsewhere, &no_kvno)).0,
        err::NOT_US
    );
    let other = |_: &PrincipalName, _: &str, _: u32, _: i32| {
        Err(KeytabLookup::Other(krb5_protocol::Error::KdbNoPermittedKey))
    };
    assert!(matches!(
        verify_ap_req_ex(&raw, &named(&host, &other), &ReplayCache::new(), None),
        Err(krb5_protocol::Error::KdbNoPermittedKey)
    ));
}

// MIT: `integrity_error` (rd_req_dec.c:162-181)
/// a keytab key that does not decrypt the ticket is BAD_INTEGRITY when the named server is the ticket's, NOT_US when not.
#[test]
fn rd_req_with_a_named_server_and_a_wrong_key_is_bad_integrity_or_not_us() {
    let (raw, _, _) = host_ap_req();
    let wrong = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
    let lookup = |_: &PrincipalName, _: &str, _: u32, _: i32| Ok(wrong.clone());
    let host = documented_host();
    let (code, text) = named_code(&raw, &named(&host, &lookup));
    assert_eq!(code, err::BAD_INTEGRITY);
    assert!(text.starts_with("Cannot decrypt ticket for "), "{text}");
    let elsewhere =
        PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "elsewhere.kerber.test"]);
    let (code, text) = named_code(&raw, &named(&elsewhere, &lookup));
    assert_eq!(code, err::NOT_US);
    assert!(text.starts_with("Cannot decrypt ticket for "), "{text}");
}

/// The parameters of an acceptor that names no server over a keytab it cannot walk (the KDB's):
/// `krb5_rd_req` with a NULL server, which looks the server the ticket names up.
fn unnamed(get_entry: krb5_protocol::KeytabGetEntry<'_>) -> ApVerifyParams<'_> {
    ApVerifyParams {
        expected_server: None,
        expected_realm: None,
        ..named(documented_host_static(), get_entry)
    }
}

fn documented_host_static() -> &'static PrincipalName {
    static HOST: std::sync::OnceLock<PrincipalName> = std::sync::OnceLock::new();
    HOST.get_or_init(documented_host)
}

/// With no server named and a keytab that cannot be walked, the principal looked up is the one the
/// ticket names, at the ticket's kvno and enctype, and it stays the ticket's server.
// MIT: `decrypt_try_server` (rd_req_dec.c:379-386)
/// a keytab with no `start_seq_get` takes `try_one_princ(tkt_server, FALSE)`.
#[test]
fn rd_req_with_no_server_looks_up_the_server_the_ticket_names() {
    let (raw, key, kvno) = host_ap_req();
    let host = documented_host();
    let asked = std::cell::RefCell::new((
        PrincipalName::new(0, [""]),
        String::new(),
        u32::MAX,
        i32::MAX,
    ));
    let lookup = |n: &PrincipalName, r: &str, k: u32, e: i32| {
        asked.replace((n.clone(), r.to_owned(), k, e));
        Ok(key.clone())
    };
    let ok = verify_ap_req_ex(&raw, &unnamed(&lookup), &ReplayCache::new(), None)
        .expect("the key decrypts it");
    assert_eq!(
        asked.into_inner(),
        (host.clone(), TEST_REALM.to_owned(), kvno, 18),
        "the lookup is for the ticket's server"
    );
    assert_eq!(ok.sname, host);
    assert_eq!(ok.srealm.as_bytes(), TEST_REALM.as_bytes());
}

/// For the ticket's own server `keytab_fetch_error` is NOT_US where the keytab has no entry (NOKEY for an
/// explicit server), BADKEYVER at a kvno it lacks (the server is always the ticket's), and BAD_INTEGRITY
/// for a key that does not decrypt; any other code passes through.
// MIT: `keytab_fetch_error` (rd_req_dec.c:118-148)
/// `KRB5_KT_NOTFOUND` is `explicit_server ? NOKEY : NOT_US`.
// MIT: `integrity_error` (rd_req_dec.c:162-181)
/// the server is the ticket's, so BAD_INTEGRITY.
#[test]
fn rd_req_with_no_server_maps_the_keytab_codes_for_the_tickets_server() {
    let (raw, _, _) = host_ap_req();
    let no_entry = |_: &PrincipalName, _: &str, _: u32, _: i32| Err(KeytabLookup::NotFound);
    assert_eq!(named_code(&raw, &unnamed(&no_entry)).0, err::NOT_US);
    let no_kvno = |_: &PrincipalName, _: &str, _: u32, _: i32| Err(KeytabLookup::KvnoNotFound);
    let (code, text) = named_code(&raw, &unnamed(&no_kvno));
    assert_eq!(code, err::BADKEYVER);
    assert!(text.starts_with("Cannot find key for "), "{text}");
    let other = |_: &PrincipalName, _: &str, _: u32, _: i32| {
        Err(KeytabLookup::Other(krb5_protocol::Error::KdbNoPermittedKey))
    };
    assert!(matches!(
        verify_ap_req_ex(&raw, &unnamed(&other), &ReplayCache::new(), None),
        Err(krb5_protocol::Error::KdbNoPermittedKey)
    ));
    let wrong = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
    let lookup = |_: &PrincipalName, _: &str, _: u32, _: i32| Ok(wrong.clone());
    assert_eq!(named_code(&raw, &unnamed(&lookup)).0, err::BAD_INTEGRITY);
}

/// A host-based server with no host over a keytab that cannot be walked matches the ticket's server by
/// service (and realm), and one that does not match is refused before any lookup.
// MIT: `decrypt_try_server` (rd_req_dec.c:379-386)
/// `krb5_sname_match(server, tkt_server)`, else `nomatch_error` (NOT_US).
#[test]
fn rd_req_with_a_server_pattern_must_match_the_tickets_server_before_the_lookup() {
    let (raw, key, _) = host_ap_req();
    let looked_up = std::cell::Cell::new(false);
    let lookup = |_: &PrincipalName, _: &str, _: u32, _: i32| {
        looked_up.set(true);
        Ok(key.clone())
    };
    let any_host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", ""]);
    let mut params = unnamed(&lookup);
    params.expected_realm = Some(TEST_REALM);
    params.expected_server = Some(&any_host);
    verify_ap_req_ex(&raw, &params, &ReplayCache::new(), None).expect("the host service matches");
    assert!(looked_up.get());
    looked_up.set(false);
    let any_nfs = PrincipalName::new(PrincipalName::NT_SRV_HST, ["nfs", ""]);
    params.expected_server = Some(&any_nfs);
    let (code, text) = named_code(&raw, &params);
    assert_eq!(code, err::NOT_US);
    assert!(
        text.starts_with(
            "Server principal nfs/@KERBER.TEST does not match request ticket server host/"
        ),
        "{text}"
    );
    assert!(!looked_up.get(), "refused before the keytab is asked");
}

/// An AP-REQ to a service whose key is des3, that key, and its version.
fn des3_host_ap_req() -> (Vec<u8>, ProtocolKey, u32) {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.allow_des3 = true;
    let key = ProtocolKey::random(EncryptionType::Des3CbcSha1).unwrap();
    store
        .set_keys(
            &documented_host(),
            vec![krb5_kdc::KeyEntry::new(
                EncryptionType::Des3CbcSha1,
                key.clone(),
                0,
            )],
            0,
        )
        .expect("setkey");
    let kvno = store
        .get_name(&documented_host())
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let ckey = client_key();
    let as_out = krb5_kdc::issue_as(
        &store,
        &as_req(
            cname.clone(),
            TEST_REALM,
            0x2000_0011,
            Some(vec![pa_enc_timestamp(&ckey).expect("pa")]),
        )
        .unwrap(),
    )
    .expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2000_0012,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    assert_eq!(
        tgs_out.rep.0.ticket.enc_part.etype, 16,
        "sealed under the des3 key"
    );
    let ap = build_ap_req(
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &cname,
    )
    .expect("AP-REQ");
    (encode(&ap).expect("encode"), key, kvno)
}

fn with_bad_parity(key: &ProtocolKey) -> ProtocolKey {
    let mut bytes = key.as_bytes().to_vec();
    bytes[3] ^= 1;
    ProtocolKey::from_bytes(EncryptionType::Des3CbcSha1, &bytes).expect("a 24-octet key loads")
}

/// An acceptor that names its server has the one keytab entry tried, and that entry's key, of bad parity, is refused with its own code.
// MIT: `try_one_entry` (rd_req_dec.c:290-320)
/// `krb5_decrypt_tkt_part` fails with `KRB5DES_BAD_KEYPAR`, which only `KRB5KRB_AP_ERR_BAD_INTEGRITY` is turned into another error (`:337-338`).
#[test]
fn rd_req_with_a_server_named_and_its_key_of_bad_parity_is_refused_with_the_keys_code() {
    let (raw, key, kvno) = des3_host_ap_req();
    let server = documented_host();
    let params = |keys: &'static [ProtocolKey]| ApVerifyParams {
        keys,
        key_kvnos: Some(Box::leak(vec![kvno].into_boxed_slice())),
        key_principals: None,
        kvno: None,
        permitted: &PERMITTED,
        expected_server: Some(Box::leak(Box::new(server.clone()))),
        expected_realm: Some(TEST_REALM),
        get_entry: None,
        skew: DEFAULT_SKEW,
        ignore_acceptor_hostname: false,
        capaths: &NO_CAPATHS,
        remote_addr: None,
        now: None,
    };
    verify_ap_req_ex(
        &raw,
        &params(Box::leak(vec![key.clone()].into_boxed_slice())),
        &ReplayCache::new(),
        None,
    )
    .expect("the key as it is");
    let r = verify_ap_req_ex(
        &raw,
        &params(Box::leak(vec![with_bad_parity(&key)].into_boxed_slice())),
        &ReplayCache::new(),
        None,
    );
    assert!(
        matches!(r, Err(krb5_protocol::Error::DesBadParity)),
        "{r:?}"
    );
}

/// With no server named the keytab is walked, an entry that does not decrypt is passed over, and the walk's end is chosen by what it found: a key at the ticket's kvno and enctype that cannot decrypt it is BAD_INTEGRITY.
// MIT: `decrypt_try_server` (rd_req_dec.c:355-443)
/// `try_one_entry`'s failure, whatever it is, moves the walk on; `iteration_error` (`:264-270`) then gives `KRB5KRB_AP_ERR_BAD_INTEGRITY`.
#[test]
fn rd_req_keytab_walk_over_a_key_of_bad_parity_is_bad_integrity() {
    let (raw, key, kvno) = des3_host_ap_req();
    walk_ok(&raw, &key, kvno);
    let (code, text) = walk_code(&raw, &[with_bad_parity(&key)], &[kvno]);
    assert_eq!(code, err::BAD_INTEGRITY);
    assert!(
        text.contains("found in keytab but cannot decrypt ticket"),
        "{text}"
    );
}

fn walk_ok(raw: &[u8], key: &ProtocolKey, kvno: u32) {
    verify_ap_req_ex(
        raw,
        &walk(std::slice::from_ref(key), &[kvno]),
        &ReplayCache::new(),
        None,
    )
    .expect("the key as it is");
}
