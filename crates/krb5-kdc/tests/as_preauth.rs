//! AS preauthentication: the hint-list order, encrypted challenge outside FAST, PAC-OPTIONS
//! in `enc_padata`, and the codes and e_data of the AS errors, with the ACL, issue and
//! AP-REQ negatives beside them.
//! The tests drive the shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry points of a
//! bootstrapped realm.
//! AS e_data-bearing errors carry PA-FX-COOKIE; PKINIT 65 is TYPED-DATA; FAST inner
//! FX-ERROR has no e_data.
// MIT: `prepare_error_as` (do_as_req.c:785-814)
//! an error with e_data gets a PA-FX-COOKIE
//! added, and typed e_data is encoded as TYPED-DATA.
// MIT: `pkinit_server_get_flags` (pkinit_srv.c:932-932)
//! PKINIT sets `PA_TYPED_E_DATA`.
// MIT: `kdc_fast_handle_error` (fast_util.c:384-386)
//! the inner FX-ERROR carries no e_data.
//! Every KDC long-term key lookup works like MIT `krb5_dbe_find_enctype`.
// MIT: `krb5_dbe_def_search_enctype` (kdb_default.c:47-94)
//! the lookup never returns a key
//! whose enctype is outside `permitted_enctypes` and, for the AS client key, looks only at
//! the highest kvno.
//! AS client/server lookup faults are labelled like MIT.
// MIT: `process_as_req` (do_as_req.c:577-607)
//! `CANTLOCK_DB` is 29 `SVC_UNAVAILABLE` on
//! either lookup **with** the lookup's status word (`LOOKING_UP_CLIENT` /
//! `LOOKING_UP_SERVER`), any other backend fault is 60 with the same
//! words. No in-tree store fails a lookup; a `PrincipalRead` wrapper stands
//! in for a backend that does. A server-lookup fault is never labelled
//! `LOOKING_UP_CLIENT`, and the CANTLOCK `e_text` matches MIT.
// MIT: `filter_preauth_error` (kdc_preauth.c:1092-1133)
//! applied at the kdcpreauth module
//! boundary (`finish_check_padata` `:1206`). A module failure whose code is not on the
//! pass-through list reaches the client as 24 `PREAUTH_FAILED`.
// MIT: `finish_preauth` (do_as_req.c:442-442)
//! the status is `PREAUTH_FAILED` for every
//! module failure, never the module's own code (`differential-gate.sh`
//! `as-optimistic-encts-wrong-etype` exercises the first cell live).
//! The KRB-ERROR encoder applies MIT `errcode_to_protocol`.
// MIT: `errcode_to_protocol` (kdc_util.c:691-697)
//! only 0..=128 is a protocol error-code,
//! anything else goes out as `KRB_ERR_GENERIC` 60.
// MIT: `prepare_error_as` (do_as_req.c:804-804)
//! the AS KRB-ERROR's code goes through
//! `errcode_to_protocol`.
// MIT: `prepare_error_tgs` (do_tgs_req.c:199-199)
//! the TGS KRB-ERROR's code goes through
//! `errcode_to_protocol`. Reachable only through a `KdcPolicy` handing back a
//! raw code (no in-tree path does).
//! ENC-TS (2) / ENC-CHALLENGE (138) are advertised only when `have_client_keys` is true.
// MIT: `have_client_keys` (kdc_preauth.c:434-447)
//! true when there is a permitted key of
//! a requested etype at the top kvno.
// MIT: `spake_edata` (spake_kdc.c:309-314)
//! SPAKE (151) uses the same condition via
//! `client_keyblock`. A preauth-required client with no usable key gets 25, not 14
//! `CANT_FIND_CLIENT_KEY`.
//! AS lookup `CANTLOCK_DB` is 29 with MIT's status word, and `KRB5KDC_ERR_DISCARD`
//! from a kdcpreauth module is passed through `filter_preauth_error` and suppresses the
//! reply.
// MIT: `process_as_req` (do_as_req.c:579-590)
//! remap to `SVC_UNAVAILABLE`, **then**
//! `LOOKING_UP_CLIENT`; `:598-606` does the same for the server with `LOOKING_UP_SERVER`.
// MIT: `filter_preauth_error` (kdc_preauth.c:1125-1125)
//! `KRB5KDC_ERR_DISCARD` is on the
//! pass-through list.
// MIT: `finish_process_as_req` (do_as_req.c:371-372)
//! a `KRB5KDC_ERR_DISCARD` builds no
//! error reply.
//! DISCARD is never rewritten to 24 `PREAUTH_FAILED`. Forge-only: no in-tree KDB can be
//! locked.

#[path = "common/mod.rs"]
mod common;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{
    Error, KdcEnv, KdcPolicy, KdcPreauth, KeyEntry, Policy, PolicyAdjustment, Principal,
    PrincipalRead, PrincipalStore, S2K_ITERS, random_key, register_preauth,
};
use krb5_protocol::{as_req, pa_enc_timestamp};

use krb5_protocol::{
    armor_key, as_req_sname, attach_fast, build_fast_armor, pa_pk_as_req_spki, unwrap_fast_rep,
};
use krb5_testkit::{expect_status, password_key, pref_etypes, user};
use krb5_types::pac::RpcSid;
use krb5_types::{
    EncKdcRepPart, EncryptedData, KerberosTime, KrbError, MethodData, PaData, PaPacRequest,
    PrincipalName, ascii, err, ku, pa,
};
use std::sync::Arc;

#[test]
fn as_hint_list_is_136_info2_modules_cookie() {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let req = as_req(cname, TEST_REALM, 15001, None).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: MethodData = decode(&e_data).unwrap();
    let types: Vec<i32> = method.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        types,
        vec![
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::SPAKE,
            pa::ENC_TIMESTAMP,
            pa::FX_COOKIE,
        ]
    );
}

fn decode_enc_part(plain: &[u8]) -> EncKdcRepPart {
    krb5_asn1::decode_enc_kdc_rep_part(plain).expect("enc-part")
}

#[test]
// oracle: differential-gate.sh unknown-sname
fn as_unknown_sname_is_server_not_found() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let sname = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "no-such.kerber.test"]);
    let req = as_req_sname(cname, TEST_REALM, 0x1000_0006, None, sname, pref_etypes()).unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert_eq!(c, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text.as_deref(), Some("SERVER_NOT_FOUND"));
}

#[test]
fn wrong_password_yields_preauth_failed_bytes() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let wrong = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        b"not-the-password",
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let req = as_req(
        cname,
        TEST_REALM,
        5,
        Some(vec![pa_enc_timestamp(&wrong).expect("pa")]),
    )
    .unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_ne!(bytes, [] as [u8; 0]);
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::PREAUTH_FAILED);
}

fn user_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

fn assert_krb_error(bytes: &[u8], code: i32, e_text: &str) {
    assert_eq!(bytes.first(), Some(&0x7e), "expected KRB-ERROR");
    let e: KrbError = decode(bytes).expect("KrbError");
    assert_eq!(e.error_code, code);
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
    assert_eq!(text, Some(e_text));
}

#[test]
fn every_ticket_sets_enc_pa_rep_flag_without_padata() {
    // MIT get_ticket_flags sets TKT_FLG_ENC_PA_REP on every ticket; the
    // enc-pa-rep padata is added only when the client asked (PA 149).
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&cname).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(
            &cname,
            krb5_kdc::AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    let key = user_key();
    let req = as_req(cname, TEST_REALM, 207, None).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let rep: krb5_types::AsRep = decode(&bytes).expect("AS-REP");
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage, rep.0.enc_part.cipher.as_ref()).expect("enc");
    let enc = decode_enc_part(&plain);
    assert!(
        enc.flags.enc_pa_rep(),
        "enc-pa-rep flag set on every ticket"
    );
    assert!(
        enc.encrypted_pa_data.is_none(),
        "no enc-pa-rep padata without PA 149"
    );
}

#[test]
fn as_rep_enc_part_carries_no_kvno_like_mit() {
    // MIT: `finish_process_as_req` (do_as_req.c:329-329)
    // reply.enc_part.kvno is set only
    // after krb5_encode_kdc_rep, so the wire AS-REP enc-part has no kvno.
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    // A no-preauth AS keeps skip_timestamp false, so it exercises the reply kvno.
    let attrs = store.get_name(&cname).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(
            &cname,
            krb5_kdc::AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    let req = as_req(cname, TEST_REALM, 206, None).unwrap();
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).expect("reply");
    let rep: krb5_types::AsRep = decode(&bytes).expect("AS-REP");
    assert!(
        rep.0.enc_part.kvno.is_none(),
        "AS-REP enc-part must carry no kvno"
    );
    // The ticket's own enc-part keeps the server key kvno.
    assert!(rep.0.ticket.enc_part.kvno.is_some());
}

#[test]
// oracle: differential-gate.sh as-bad-msg-type
fn as_bad_msg_type_is_validate_message_type() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 410, None).unwrap();
    req.0.msg_type = krb5_types::KdcReq::MSG_TGS_REQ;
    let err = krb5_kdc::issue_as(&store, &req).expect_err("bad msg_type");
    match err {
        Error::Protocol {
            code, text, e_data, ..
        } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("VALIDATE_MESSAGE_TYPE"));
            assert!(e_data.is_none(), "no cookie");
        }
        other => panic!("expected 60 VALIDATE_MESSAGE_TYPE, got {other:?}"),
    }
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    assert_krb_error(&bytes, err::GENERIC, "VALIDATE_MESSAGE_TYPE");
    let e: KrbError = decode(&bytes).expect("KRB-ERROR");
    assert!(e.cname.is_some(), "requested cname echoed");
    assert!(e.e_data.is_none(), "no cookie");
}

#[test]
// oracle: differential-gate.sh wrong-realm
fn as_wrong_realm_is_chaseable() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(cname, TEST_REALM, 50, None).unwrap();
    req.0.req_body.realm = ascii("OTHER.TEST");
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).expect("der")).expect("reply");
    let e: krb5_types::KrbError = decode(&bytes).expect("KRB-ERROR");
    assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
    assert_eq!(
        std::str::from_utf8(e.realm.as_bytes()).unwrap(),
        "OTHER.TEST"
    );
}

fn first_ctx_tag(der: &[u8]) -> Option<u8> {
    let inner = |b: &[u8]| {
        let (len, hlen) = krb5_types::der::read_len(b.get(1..)?)?;
        b.get(1 + hlen..1 + hlen + len).map(<[u8]>::to_vec)
    };
    inner(&inner(der)?)?.first().copied()
}

fn pkinit_as_req(
    cname: PrincipalName,
    nonce: u32,
    make_pa: impl FnOnce(&[u8]) -> krb5_types::PaData,
) -> krb5_types::AsReq {
    let mut req = as_req(cname, TEST_REALM, nonce, None).unwrap();
    let body = encode(&req.0.req_body).expect("body");
    let cksum = krb5_types::pkinit::kdc_req_body_checksum(&body);
    req.0.padata = Some(vec![make_pa(&cksum)]);
    req
}

fn edata_int_types(ed: &[u8]) -> Vec<i32> {
    fn read_len(buf: &[u8], i: usize) -> Option<(usize, usize)> {
        let n = *buf.get(i)? as usize;
        if n < 0x80 {
            return Some((n, i + 1));
        }
        let count = n & 0x7f;
        let mut val = 0usize;
        for j in 0..count {
            val = (val << 8) | *buf.get(i + 1 + j)? as usize;
        }
        Some((val, i + 1 + count))
    }
    fn tlv(buf: &[u8], i: usize) -> Option<(u8, &[u8], usize)> {
        let tag = *buf.get(i)?;
        let (ln, j) = read_len(buf, i + 1)?;
        let end = j.checked_add(ln)?;
        Some((tag, buf.get(j..end)?, end))
    }
    fn parse_int(val: &[u8]) -> i32 {
        let mut n: i32 = 0;
        for b in val {
            n = (n << 8) | i32::from(*b);
        }
        n
    }
    let Ok((_, seq, _)) = tlv(ed, 0).ok_or(()) else {
        return Vec::new();
    };
    let mut types = Vec::new();
    let mut i = 0;
    while i < seq.len() {
        let Some((_, pa, next)) = tlv(seq, i) else {
            break;
        };
        i = next;
        let mut j = 0;
        while j < pa.len() {
            let Some((ptag, pval, n)) = tlv(pa, j) else {
                break;
            };
            j = n;
            if ptag & 0xc0 != 0x80 {
                continue;
            }
            let inner = if ptag & 0x20 != 0 {
                tlv(pval, 0).map_or(pval, |(_, v, _)| v)
            } else {
                pval
            };
            let num = ptag & 0x1f;
            if num == 0 || num == 1 {
                types.push(parse_int(inner));
                break;
            }
        }
    }
    types
}

#[test]
fn pkinit_unknown_dh_is_typed_edata_with_cookie() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let ca = krb5_testkit::enable_pkinit(&mut store);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut spki = krb5_types::pkinit::KxKey::generate(krb5_types::pkinit::KxGroup::Modp2048)
        .expect("DH key")
        .spki();
    spki[64] ^= 0x01;
    let req = pkinit_as_req(cname, 901, |ck| {
        pa_pk_as_req_spki(&spki, &ca, Some(ck)).expect("PA-PK-AS-REQ")
    });
    let bytes = krb5_kdc::handle_request(&store, &encode(&req).unwrap()).unwrap();
    let e: KrbError = decode(&bytes).unwrap();
    assert_eq!(e.error_code, err::DH_KEY_PARAMETERS_NOT_ACCEPTED);
    let ed = e.e_data.as_ref().expect("e_data");
    assert_eq!(
        first_ctx_tag(ed.as_ref()),
        Some(0xa0),
        "PKINIT 65 e_data is TYPED-DATA [0]/[1], not METHOD-DATA [1]/[2]"
    );
    let method = match decode::<MethodData>(ed.as_ref()) {
        Ok(m) if !m.is_empty() => m,
        _ => Vec::new(),
    };
    assert!(
        method.is_empty(),
        "TYPED-DATA must not decode as PA-DATA: {:?}",
        method.iter().map(|p| p.padata_type).collect::<Vec<_>>()
    );
    let types = edata_int_types(ed.as_ref());
    assert_eq!(types, vec![pa::TD_DH_PARAMETERS, pa::FX_COOKIE]);
}

const AES128: EncryptionType = EncryptionType::Aes128CtsHmacSha196;

const AES256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

fn user_name() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn user_key_z1_permitted_key(
    store: &PrincipalStore,
    etype: EncryptionType,
) -> krb5_crypto::ProtocolKey {
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

fn set_random_keys(store: &mut PrincipalStore, name: &PrincipalName, etypes: &[EncryptionType]) {
    let keys = etypes
        .iter()
        .map(|&e| KeyEntry::new(e, random_key(e).unwrap(), 0))
        .collect();
    store.set_keys(name, keys, 0).unwrap();
}

// MIT: `select_client_key` (do_as_req.c:103-131)
/// an etype held only at a lower kvno selects no
/// client key, so the request is keyless.
// MIT: `enc_ts_verify` (kdc_preauth_encts.c:115-116)
/// the miss is `KRB5_KDB_NO_MATCHING_KEY`,
/// which becomes 24 with the preauth hints. Preauth runs before the 14 of `CANT_FIND_CLIENT_KEY`.
#[test]
fn as_client_key_is_chosen_at_the_highest_kvno_only() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let old_aes256 = user_key_z1_permitted_key(&store, AES256);
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
        Err(krb5_kdc::Error::Protocol {
            code, text, e_data, ..
        }) => {
            assert_eq!(
                code,
                err::PREAUTH_FAILED,
                "KDC_ERR_PREAUTH_FAILED, got {text:?}"
            );
            assert_eq!(text.as_deref(), Some("PREAUTH_FAILED"));
            assert!(e_data.is_some(), "the 24 carries the preauth hints");
        }
        Err(other) => panic!("expected 24 PREAUTH_FAILED, got {other:?}"),
        Ok(_) => panic!("an etype present only at an older kvno must not select that key"),
    }
}

#[test]
fn as_client_key_skips_a_non_permitted_requested_etype() {
    let mut store = store_permitting_aes256();
    set_random_keys(&mut store, &user_name(), &[AES128, AES256]);
    let padata = vec![
        pa_enc_timestamp(&user_key_z1_permitted_key(&store, AES256)).unwrap(),
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
fn as_lookup_faults_are_labelled_like_do_as_req() {
    let client_id = format!("{TEST_USER}@{TEST_REALM}");
    let tgs_id = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    // :588-590 — a client-lookup fault is 60 LOOKING_UP_CLIENT.
    assert_eq!(
        as_error(&client_id, backend_fault),
        (err::GENERIC, Some("LOOKING_UP_CLIENT".into()))
    );
    // :604-606 — a server-lookup fault is 60 LOOKING_UP_SERVER, not the
    // LOOKING_UP_CLIENT of a client-lookup fault.
    assert_eq!(
        as_error(&tgs_id, backend_fault),
        (err::GENERIC, Some("LOOKING_UP_SERVER".into()))
    );
    // :579-590, :598-606 — CANTLOCK_DB is remapped to 29, then the
    // `else if (errcode)` chain sets the lookup status.
    assert_eq!(
        as_error(&client_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_CLIENT".into()))
    );
    assert_eq!(
        as_error(&tgs_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_SERVER".into()))
    );
}

fn user_key_z1b_preauth_filter(store: &PrincipalStore, etype: EncryptionType) -> ProtocolKey {
    store
        .get_name(&user())
        .unwrap()
        .keys
        .iter()
        .filter(|k| k.etype == etype)
        .max_by_key(|k| k.kvno)
        .expect("user key of that etype")
        .key
        .clone()
}

fn wire(store: &PrincipalStore, nonce: u32, padata: Vec<PaData>) -> (i32, Option<String>) {
    let req = as_req(user(), TEST_REALM, nonce, Some(padata)).unwrap();
    let raw = encode(&req).unwrap();
    let reply = krb5_kdc::handle_request(store, &raw).expect("a KRB-ERROR reply");
    let e = decode::<KrbError>(&reply).expect("KRB-ERROR");
    (
        e.error_code,
        e.e_text
            .as_ref()
            .map(|t| String::from_utf8_lossy(t.as_bytes()).into_owned()),
    )
}

#[test]
fn encts_under_a_non_permitted_etype_is_24_like_filter_preauth_error() {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(
        !store
            .policy()
            .etype_permitted(EncryptionType::Aes128CtsHmacSha196)
    );
    // The user's real aes128 key: a *correct* timestamp under a non-permitted
    // enctype, so nothing but the permitted-enctype walk can refuse it.
    let aes128 = user_key_z1b_preauth_filter(&store, EncryptionType::Aes128CtsHmacSha196);
    let padata = vec![pa_enc_timestamp(&aes128).unwrap()];
    assert_eq!(
        wire(&store, 0x1b06, padata),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into()))
    );
}

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
    let (mut store, _) = bootstrap_documented().unwrap();
    store
        .policy
        .plugins
        .set_policy(Arc::new(RawCodePolicy(raw_policy_code)));
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
    decode::<KrbError>(&reply).expect("KRB-ERROR").error_code
}

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
        rock: &krb5_kdc::PreauthRock<'_>,
    ) -> Result<Option<krb5_kdc::PreauthAction>, Error> {
        let krb5_kdc::PreauthRock {
            store: _store,
            client: _client,
            padata,
            ikey: _ikey,
            etype: _etype,
            armor_key: _armor_key,
            as_req_der: _as_req_der,
            body_der: _body_der,
            cname: _cname,
        } = *rock;
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
            [5] => Error::Protocol {
                code: err::REPEAT,
                text: Some("MODULE_REPEAT".into()),
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

#[test]
fn policy_raw_library_code_reaches_the_wire_as_generic_60() {
    // Outside 0..=128 (a com_err library value the module forgot to map).
    assert_eq!(wire_error_code(1_000_000), err::GENERIC);
    assert_eq!(wire_error_code(-1_765_328_361), err::GENERIC);
    // Inside the protocol range it is passed through (`:697`).
    assert_eq!(wire_error_code(err::POLICY), err::POLICY);
}

#[test]
// oracle: differential-gate.sh skewed-timestamp
fn module_failures_pass_through_the_filter_like_kdc_preauth() {
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
    assert_eq!(
        module_wire_error(5),
        (err::PREAUTH_FAILED, Some("PREAUTH_FAILED".into())),
        "34 REPEAT is not on the list"
    );
}

fn store_permitting_aes256_z6_hints() -> PrincipalStore {
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    store
}

fn set_user_aes128_only(store: &mut PrincipalStore) {
    store
        .set_keys(
            &user_name(),
            vec![KeyEntry::new(AES128, random_key(AES128).unwrap(), 0)],
            0,
        )
        .unwrap();
}

fn hint_types(err: Error) -> Vec<i32> {
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PREAUTH_REQUIRED, got {err:?}");
    };
    let method: MethodData = decode(&e_data).expect("METHOD-DATA");
    method.iter().map(|p| p.padata_type).collect()
}

#[test]
fn hint_omits_enc_ts_when_the_only_key_is_not_permitted() {
    let mut store = store_permitting_aes256_z6_hints();
    set_user_aes128_only(&mut store);
    assert!(store.get_name(&user_name()).unwrap().requires_preauth());
    let req = as_req(user_name(), TEST_REALM, 0x2600_0062, None).unwrap();
    let types = hint_types(krb5_kdc::issue_as(&store, &req).unwrap_err());
    assert!(
        types.contains(&pa::FX_FAST),
        "25 still advertises FAST: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS must be omitted when have_client_keys is false: {types:?}"
    );
    assert!(
        !types.contains(&pa::ETYPE_INFO2),
        "no selected client key → no ETYPE-INFO2: {types:?}"
    );
    assert!(
        !types.contains(&pa::SPAKE),
        "SPAKE must be omitted when client_keyblock is NULL: {types:?}"
    );
}

#[test]
fn fast_hint_omits_enc_challenge_when_have_client_keys_is_false() {
    let mut store = store_permitting_aes256_z6_hints();
    let key = store
        .get_name(&user_name())
        .unwrap()
        .keys
        .iter()
        .find(|k| k.etype == AES256)
        .expect("user aes256")
        .key
        .clone();
    let req = as_req(
        user_name(),
        TEST_REALM,
        0x2600_0064,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let armor = krb5_kdc::issue_as(&store, &req).expect("armor TGT");
    set_user_aes128_only(&mut store);
    let sub = ProtocolKey::from_bytes(AES256, &[0x61u8; 32]).unwrap();
    let armor_ap = build_fast_armor(
        armor.rep.0.ticket.clone(),
        &armor.session_key,
        &ascii(TEST_REALM),
        &user_name(),
        Some(&sub),
    )
    .unwrap();
    let akey = armor_key(&armor.session_key, Some(&sub)).unwrap();
    let mut req = as_req(user_name(), TEST_REALM, 0x2600_0065, None).unwrap();
    attach_fast(&mut req, &armor_ap, &akey, vec![]).unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let Error::PreauthRequired { e_data } = err else {
        panic!("expected PREAUTH_REQUIRED, got {err:?}");
    };
    let outer: MethodData = decode(&e_data).expect("outer METHOD-DATA");
    let fast = unwrap_fast_rep(&akey, &Some(outer)).expect("FAST unwrap");
    let types: Vec<i32> = fast.padata.iter().map(|p| p.padata_type).collect();
    assert!(
        !types.contains(&pa::ENCRYPTED_CHALLENGE),
        "ENC-CHALLENGE must be omitted when have_client_keys is false: {types:?}"
    );
    assert!(
        !types.contains(&pa::ENC_TIMESTAMP),
        "ENC-TS stays omitted under armor: {types:?}"
    );
}

const DISCARD: i32 = -1_750_600_189;

const PA_DISCARD: i32 = 30_001;

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
        rock: &krb5_kdc::PreauthRock<'_>,
    ) -> Result<Option<krb5_kdc::PreauthAction>, Error> {
        let krb5_kdc::PreauthRock {
            store: _store,
            client: _client,
            padata,
            ikey: _ikey,
            etype: _etype,
            armor_key: _armor_key,
            as_req_der: _as_req_der,
            body_der: _body_der,
            cname: _cname,
        } = *rock;
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
fn cantlock_on_client_is_29_looking_up_client() {
    let client_id = format!("{TEST_USER}@{TEST_REALM}");
    assert_eq!(
        as_error(&client_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_CLIENT".into()))
    );
}

#[test]
fn cantlock_on_server_is_29_looking_up_server() {
    let tgs_id = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    assert_eq!(
        as_error(&tgs_id, cantlock),
        (err::SVC_UNAVAILABLE, Some("LOOKING_UP_SERVER".into()))
    );
}

#[test]
fn discard_module_failure_is_no_reply() {
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

fn traced_as(store: &PrincipalStore, nonce: u32, padata: Vec<PaData>) -> (i32, Vec<String>) {
    let req = as_req(user(), TEST_REALM, nonce, Some(padata)).unwrap();
    let raw = encode(&req).unwrap();
    let (reply, log) = common::kdc_log(|| krb5_kdc::handle_request(store, &raw));
    let e = decode::<KrbError>(&reply.expect("a KRB-ERROR reply")).expect("KRB-ERROR");
    (e.error_code, common::failure_trace(&log))
}

#[test]
fn enc_ts_wrong_password_logs_its_verify_failure_before_the_as_req_line() {
    // MIT: `finish_verify_padata` (kdc/kdc_preauth.c:1224-1228)
    // the module's failure is its own log line, ahead of the `AS_REQ` line `finish_process_as_req` writes.
    let (store, _) = bootstrap_documented().unwrap();
    let wrong = password_key(TEST_USER, b"not-the-password");
    let (code, trace) = traced_as(&store, 0x4b01, vec![pa_enc_timestamp(&wrong).unwrap()]);
    assert_eq!(code, err::PREAUTH_FAILED);
    assert_eq!(
        trace,
        [
            "preauth (encrypted_timestamp) verify failure: Preauthentication failed",
            "AS_REQ PREAUTH_FAILED, Preauthentication failed",
        ]
    );
}

#[test]
fn enc_ts_skew_logs_clock_skew_on_both_lines() {
    // MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:97-99)
    // a timestamp outside the skew is `KRB5KRB_AP_ERR_SKEW`, which `filter_preauth_error` lets through.
    let (store, _) = bootstrap_documented().unwrap();
    let stale = KerberosTime::now().add_seconds(-10_000).unwrap();
    let padata = vec![krb5_protocol::pa_enc_timestamp_at(&user_key(), &stale).unwrap()];
    let (code, trace) = traced_as(&store, 0x4b02, padata);
    assert_eq!(code, err::SKEW);
    assert_eq!(
        trace,
        [
            "preauth (encrypted_timestamp) verify failure: Clock skew too great",
            "AS_REQ PREAUTH_FAILED, Clock skew too great",
        ]
    );
}

#[test]
fn enc_ts_under_an_etype_nothing_permits_logs_the_walk_error() {
    // MIT: `krb5_dbe_def_search_enctype` (lib/kdb/kdb_default.c:60-61)
    // an etype `krb5_is_permitted_enctype` refuses is `KRB5_KDB_NO_PERMITTED_KEY`, and the AS_REQ line says what the wire's 24 says.
    krb5_config::isolate_test_krb5();
    let (mut store, _) = bootstrap_documented().unwrap();
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    let aes128 = user_key_z1b_preauth_filter(&store, EncryptionType::Aes128CtsHmacSha196);
    let unknown = EncryptedData {
        etype: 99,
        kvno: None,
        cipher: vec![0u8; 32].into(),
    };
    let unknown = PaData {
        padata_type: pa::ENC_TIMESTAMP,
        padata_value: encode(&unknown).unwrap().into(),
    };
    for (nonce, padata) in [
        (0x4b03, pa_enc_timestamp(&aes128).unwrap()),
        (0x4b04, unknown),
    ] {
        let (code, trace) = traced_as(&store, nonce, vec![padata]);
        assert_eq!(code, err::PREAUTH_FAILED);
        assert_eq!(
            trace,
            [
                "preauth (encrypted_timestamp) verify failure: No matching key in entry having a permitted enctype",
                "AS_REQ PREAUTH_FAILED, Preauthentication failed",
            ],
            "nonce {nonce:#x}"
        );
    }
}

#[test]
fn ec_outside_fast_logs_its_verify_failure() {
    // MIT: `ec_verify` (kdc/kdc_preauth_ec.c:71-76)
    // outside a FAST tunnel the module fails with `ENOENT` and this message.
    let (store, _) = bootstrap_documented().unwrap();
    let padata = PaData {
        padata_type: pa::ENCRYPTED_CHALLENGE,
        padata_value: b"outside-fast".to_vec().into(),
    };
    let (code, trace) = traced_as(&store, 0x4b06, vec![padata]);
    assert_eq!(code, err::PREAUTH_FAILED);
    assert_eq!(
        trace,
        [
            "preauth (encrypted_challenge) verify failure: Encrypted Challenge used outside of FAST tunnel",
            "AS_REQ PREAUTH_FAILED, Preauthentication failed",
        ]
    );
}

fn module_trace(selector: u8) -> (i32, Vec<String>) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| krb5_kdc::register_preauth(Arc::new(FailingModule)));
    let (store, _) = bootstrap_documented().unwrap();
    let padata = PaData {
        padata_type: PA_PRIVATE,
        padata_value: vec![selector].into(),
    };
    traced_as(&store, 0x4b07, vec![padata])
}

#[test]
fn a_module_failure_is_logged_under_its_name_and_the_as_req_line_stays_mits() {
    // MIT: `finish_verify_padata` (kdc/kdc_preauth.c:1224-1228)
    // any module's failure, under the module's name, with the message of its code.
    // MIT: `filter_preauth_error` (kdc/kdc_preauth.c:1092-1133)
    // 90 is off the pass-through list, so the wire and the `AS_REQ` line say 24 and nothing of the module's own words.
    assert_eq!(
        module_trace(4),
        (
            err::PREAUTH_FAILED,
            vec![
                "preauth (z1b-failing) verify failure: Preauthentication expired".to_owned(),
                "AS_REQ PREAUTH_FAILED, Preauthentication failed".to_owned(),
            ]
        )
    );
    // 37 is on the list: both lines say it.
    assert_eq!(
        module_trace(1),
        (
            err::SKEW,
            vec![
                "preauth (z1b-failing) verify failure: Clock skew too great".to_owned(),
                "AS_REQ PREAUTH_FAILED, Clock skew too great".to_owned(),
            ]
        )
    );
    // 34 and 12 are off the list as well.
    for (selector, message) in [
        (5, "Request is a replay"),
        (3, "KDC policy rejects request"),
    ] {
        assert_eq!(
            module_trace(selector),
            (
                err::PREAUTH_FAILED,
                vec![
                    format!("preauth (z1b-failing) verify failure: {message}"),
                    "AS_REQ PREAUTH_FAILED, Preauthentication failed".to_owned(),
                ]
            ),
            "selector {selector}"
        );
    }
}
