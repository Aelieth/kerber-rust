//! In-crate GSS tests (private-bound; moved out of `lib.rs`).

use super::context::{
    FLAG_ACCEPTOR_SUBKEY, KRB5_GSS_FOR_CREDS, TOK_AP_REP, TOK_AP_REQ, authenticator_checksum,
    random_subkey,
};
use super::deleg::krb_cred_for_deleg;
use super::oid::{der_tlv, gss_unwrap_app, gss_wrap_app};
use super::spnego::parse_neg_init;
use super::wrap::{FLAG_SEALED, TOK_WRAP, mit_shaped_wrap_flags};
use super::*;
use krb5_asn1::{decode, encode};
use krb5_crypto::{KeyUsage, decrypt, encrypt};
use krb5_protocol::build_ap_req_with_cksum;
use krb5_types::{
    ApOptions, ApRep, Checksum, EncKrbCredPart, EncryptedData, EncryptionKey, KerberosTime,
    KrbCred, KrbCredInfo, Microseconds, PrincipalName, TicketFlags, ku,
};

use krb5_crypto::{EncryptionType, string_to_key};

use krb5_kdc::S2K_ITERS;
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_types::ascii;

struct WrappedIov {
    header: Vec<u8>,
    data: Vec<u8>,
    padding: Vec<u8>,
    trailer: Vec<u8>,
    sign: Vec<u8>,
}

fn contexts() -> (GssContext, GssContext) {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        2,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let (init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        false,
        None,
        None,
    )
    .unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    let skey = &host.best_key().unwrap().key;
    let (acc, _) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    (init, acc)
}

fn user_host() -> (
    krb5_kdc::IssuedAs,
    krb5_kdc::IssuedTgs,
    ProtocolKey,
    PrincipalName,
) {
    krb5_config::isolate_test_krb5();
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        41,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        42,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    let skey = host.best_key().unwrap().key.clone();
    (as_out, tgs_out, skey, cname)
}

fn wrap_iov_once(ctx: &mut GssContext, msg: &[u8], assoc: Option<&[u8]>) -> WrappedIov {
    let mut header = Vec::new();
    let mut data = msg.to_vec();
    let mut padding = vec![0xff];
    let mut trailer = Vec::new();
    let mut sign = assoc.unwrap_or(&[]).to_vec();
    let mut iov = vec![
        IovBuf {
            kind: IovType::Header,
            data: &mut header,
        },
        IovBuf {
            kind: IovType::Data,
            data: &mut data,
        },
        IovBuf {
            kind: IovType::Padding,
            data: &mut padding,
        },
        IovBuf {
            kind: IovType::Trailer,
            data: &mut trailer,
        },
    ];
    if assoc.is_some() {
        iov.insert(
            1,
            IovBuf {
                kind: IovType::SignOnly,
                data: &mut sign,
            },
        );
    }
    ctx.wrap_iov(true, &mut iov).unwrap();
    WrappedIov {
        header,
        data,
        padding,
        trailer,
        sign,
    }
}

fn unwrap_iov_once(
    ctx: &mut GssContext,
    header: &mut Vec<u8>,
    data: &mut Vec<u8>,
    padding: &mut Vec<u8>,
    trailer: &mut Vec<u8>,
    assoc: Option<&mut Vec<u8>>,
) -> Result<(), Error> {
    let mut iov = Vec::new();
    iov.push(IovBuf {
        kind: IovType::Header,
        data: header,
    });
    if let Some(s) = assoc {
        iov.push(IovBuf {
            kind: IovType::SignOnly,
            data: s,
        });
    }
    iov.push(IovBuf {
        kind: IovType::Data,
        data,
    });
    iov.push(IovBuf {
        kind: IovType::Padding,
        data: padding,
    });
    iov.push(IovBuf {
        kind: IovType::Trailer,
        data: trailer,
    });
    ctx.unwrap_iov(&mut iov)
}

fn bare_ctx(key: ProtocolKey, initiator: bool) -> GssContext {
    GssContext {
        session: key,
        acceptor_subkey: None,
        send_seq: 0,
        recv_seq: 0,
        recv_seen: false,
        recv_window: std::collections::HashSet::new(),
        initiator,
        rpcsec_init_window: false,
        replay: krb5_protocol::ReplayCache::new(),
        client: None,
        delegated: None,
        spnego_mech_list: None,
        lifetime_end: 0,
        gss_flags: GSS_C_INTEG | GSS_C_CONF,
        ticket_initial: false,
        acceptor: None,
        ticket_realm: None,
        ap_rep_key: None,
        dce_style: false,
        ap_req_time: None,
    }
}

#[test]
fn wrap_integ_round_trip_is_unsealed() {
    let (mut init, mut acc) = contexts();
    let tok = init.wrap_integ(&1u32.to_be_bytes()).unwrap();
    assert_eq!(tok[2] & FLAG_SEALED, 0);
    let plain = acc.unwrap(&tok).unwrap();
    assert_eq!(plain, 1u32.to_be_bytes());
}

#[test]
fn accept_short_8003_is_channel_bindings() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let cksum = Checksum {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum: vec![0u8; 8].into(),
    };
    let ap = build_ap_req_with_cksum(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::none(),
        Some(cksum),
        None,
    )
    .unwrap();
    let token = gss_wrap_app(TOK_AP_REQ, &encode(&ap).unwrap());
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) {
        Err(Error::ChannelBindings) => {}
        Err(err) => panic!("short 0x8003 must be ChannelBindings, got {err}"),
        Ok(_) => panic!("short 0x8003 must be ChannelBindings"),
    }
}

#[test]
fn accept_non_8003_over_data_is_bad_sig() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let ap = krb5_protocol::build_ap_req_opts(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::none(),
        Some(b"not-empty"),
    )
    .unwrap();
    let token = gss_wrap_app(TOK_AP_REQ, &encode(&ap).unwrap());
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) {
        Err(Error::Integrity) => {}
        Err(err) => panic!("non-0x8003 over data must be Integrity, got {err}"),
        Ok(_) => panic!("non-0x8003 over data must be Integrity"),
    }
}

#[test]
fn mit_shaped_wrap_token_is_accepted() {
    let (init, mut acc) = contexts();
    let tok = mit_shaped_wrap(init.session_key(), true, 0, b"mit-layout").unwrap();
    assert_eq!(&tok[..2], &TOK_WRAP);
    assert_eq!(tok[2] & FLAG_SEALED, FLAG_SEALED);
    let plain = acc.unwrap(&tok).unwrap();
    assert_eq!(plain, b"mit-layout");
}

#[test]
fn spnego_long_form_length_round_trips() {
    let krb = vec![0x60; 200];
    let tok = spnego_init(&krb);
    assert_eq!(tok[0], 0x60);
    assert_ne!(
        tok[1], 0x80,
        "indefinite / overflow byte is not a DER length"
    );
    assert!(
        tok[1] >= 0x81,
        "200-byte inner token needs long-form length"
    );
    let inner = spnego_inner(&tok).unwrap();
    assert_eq!(inner, krb.as_slice());
    let raw = der_tlv(0x60, &[der_tlv(0x06, KRB5_OID), vec![0x01, 0x00]].concat());
    assert_eq!(spnego_inner(&raw).unwrap(), raw.as_slice());
}

#[test]
fn spnego_accept_rejects_mech_list_without_krb5() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let (_init, krb) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        true,
        None,
        None,
    )
    .unwrap();
    let ntlm: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    let oid = der_tlv(0x06, ntlm);
    let mech_types = der_tlv(0xa0, &der_tlv(0x30, &oid));
    let mech_token = der_tlv(0xa2, &der_tlv(0x04, &krb));
    let mut seq = mech_types;
    seq.extend_from_slice(&mech_token);
    let neg = der_tlv(0xa0, &der_tlv(0x30, &seq));
    let mut app = der_tlv(0x06, SPNEGO_OID);
    app.extend_from_slice(&neg);
    let tok = der_tlv(0x60, &app);
    assert!(matches!(
        spnego_accept(
            &tok,
            std::slice::from_ref(&skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
            &ReplayCache::new(),
        ),
        Err(Error::Truncated)
    ));
}

#[test]
fn spnego_duplicate_mech_types_is_truncated() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let (_init, krb) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        true,
        None,
        None,
    )
    .unwrap();
    let oid = der_tlv(0x06, KRB5_OID);
    let mech_types = der_tlv(0xa0, &der_tlv(0x30, &oid));
    let mech_token = der_tlv(0xa2, &der_tlv(0x04, &krb));
    let mut seq = mech_types.clone();
    seq.extend_from_slice(&mech_types);
    seq.extend_from_slice(&mech_token);
    let neg = der_tlv(0xa0, &der_tlv(0x30, &seq));
    let mut app = der_tlv(0x06, SPNEGO_OID);
    app.extend_from_slice(&neg);
    let tok = der_tlv(0x60, &app);
    assert!(matches!(
        spnego_accept(
            &tok,
            std::slice::from_ref(&skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
            &ReplayCache::new(),
        ),
        Err(Error::Truncated)
    ));
}

#[test]
fn spnego_hostile_length_is_truncated_not_panic() {
    let mut tok = vec![0x60, 0x82, 0xff, 0xff, 0x06, 0x06];
    tok.extend_from_slice(SPNEGO_OID);
    tok.extend_from_slice(&[0xa0, 0x03, 0x30, 0x01, 0x00]);
    let r = std::panic::catch_unwind(|| parse_neg_init(&tok));
    assert!(r.is_ok(), "hostile SPNEGO length must not panic");
    assert!(matches!(r.unwrap(), Err(Error::Truncated)));
    assert!(matches!(
        spnego_accept(&tok, &[], None, None, None, &ReplayCache::new()),
        Err(Error::Truncated)
    ));
}

#[test]
fn hostile_gss_oid_length_is_truncated_not_panic() {
    // APPLICATION 0 wrapping OID with attacker-controlled length 255.
    let mut tok = vec![0x60, 13, 0x06, 255];
    tok.extend_from_slice(&[0u8; 11]);
    let r = std::panic::catch_unwind(|| gss_unwrap_app(&tok));
    assert!(r.is_ok(), "hostile OID length must not panic");
    assert!(matches!(r.unwrap(), Err(Error::Truncated)));
    assert!(gss_unwrap_app(&[0x60, 2, 0x06, 0xff]).is_err());
}

#[test]
fn process_ap_rep_acceptor_subkey_unwrap() {
    use krb5_types::{EncApRepPart, EncryptedData, EncryptionKey};

    let (mut init, _acc) = contexts();
    let et = init.session_key().etype();
    let mut ticket_raw = vec![0u8; et.key_len()];
    getrandom::getrandom(&mut ticket_raw).unwrap();
    let ticket = ProtocolKey::from_bytes(et, &ticket_raw).unwrap();
    let mut raw = vec![0u8; et.key_len()];
    getrandom::getrandom(&mut raw).unwrap();
    let sub = ProtocolKey::from_bytes(et, &raw).unwrap();
    let (ctime, cusec) = init.ap_req_time.clone().unwrap();
    let part = EncApRepPart {
        ctime,
        cusec,
        subkey: Some(EncryptionKey {
            keytype: et.to_iana(),
            keyvalue: sub.as_bytes().to_vec().into(),
        }),
        seq_number: Some(0),
    };
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
    let cipher = encrypt(&ticket, usage, &der).unwrap();
    let ap = ApRep {
        pvno: ApRep::PVNO,
        msg_type: ApRep::MSG_TYPE,
        enc_part: EncryptedData {
            etype: et.to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let tok = gss_wrap_app(TOK_AP_REP, &encode(&ap).unwrap());
    init.process_ap_rep(&tok, &ticket).unwrap();
    let wrapped = mit_shaped_wrap_flags(&sub, false, 0, b"subkey", FLAG_ACCEPTOR_SUBKEY).unwrap();
    assert_eq!(init.unwrap(&wrapped).unwrap(), b"subkey");
}

#[test]
fn deleg_checksum_carries_krb_cred() {
    let (as_out, tgs_out, _skey, cname) = user_host();
    let deleg = DelegCred {
        ticket: as_out.rep.0.ticket.clone(),
        session: as_out.session_key.clone(),
        crealm: ascii(TEST_REALM),
        cname: cname.clone(),
        flags: TicketFlags::none(),
        authtime: None,
        starttime: None,
        endtime: None,
        renew_till: None,
    };
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        false,
        None,
        Some(&deleg),
    )
    .unwrap();
    let inner = gss_unwrap_app(&token).unwrap();
    let ap: krb5_types::ApReq = decode(&inner[2..]).unwrap();
    let usage = KeyUsage::new(ku::AP_REQ_AUTHENTICATOR).unwrap();
    let plain = decrypt(
        &tgs_out.session_key,
        usage,
        ap.authenticator.cipher.as_ref(),
    )
    .unwrap();
    let auth: krb5_types::Authenticator = decode(&plain).unwrap();
    let ck = auth.cksum.expect("0x8003");
    assert_eq!(ck.cksumtype, GSS_CHECKSUM_TYPE);
    let b = ck.checksum.as_ref();
    assert!(b.len() > 28, "deleg trailer missing: len={}", b.len());
    let flags = u32::from_le_bytes(b[20..24].try_into().unwrap());
    assert_ne!(flags & GSS_C_DELEG, 0);
    assert_eq!(&b[24..26], &KRB5_GSS_FOR_CREDS.to_le_bytes());
}

#[test]
fn accept_hostile_dlgth_is_truncated() {
    let (as_out, tgs_out, skey, cname) = user_host();
    let deleg = DelegCred {
        ticket: as_out.rep.0.ticket.clone(),
        session: as_out.session_key.clone(),
        crealm: ascii(TEST_REALM),
        cname: cname.clone(),
        flags: TicketFlags::none(),
        authtime: None,
        starttime: None,
        endtime: None,
        renew_till: None,
    };
    let der = krb_cred_for_deleg(&tgs_out.session_key, &deleg).unwrap();
    let mut ck = authenticator_checksum(None, GSS_C_DELEG | GSS_C_INTEG, Some(&der));
    ck[26..28].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let cksum = Checksum {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum: ck.into(),
    };
    let sub = random_subkey(&tgs_out.session_key).unwrap();
    let enc_sub = EncryptionKey {
        keytype: sub.etype().to_iana(),
        keyvalue: sub.as_bytes().to_vec().into(),
    };
    let ap = build_ap_req_with_cksum(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::none(),
        Some(cksum),
        Some(enc_sub),
    )
    .unwrap();
    let token = gss_wrap_app(TOK_AP_REQ, &encode(&ap).unwrap());
    let Err(err) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) else {
        panic!("hostile Dlgth must not accept")
    };
    assert!(
        matches!(&err, Error::Inner(s) if s.contains("gss failure")),
        "hostile Dlgth must be gss failure, got {err}"
    );
}

#[test]
fn accept_plaintext_krb_cred_is_refused() {
    let (as_out, tgs_out, skey, cname) = user_host();
    let realm = ascii(TEST_REALM);
    let info = KrbCredInfo {
        key: EncryptionKey {
            keytype: as_out.session_key.etype().to_iana(),
            keyvalue: as_out.session_key.as_bytes().to_vec().into(),
        },
        prealm: Some(realm.clone()),
        pname: Some(cname.clone()),
        flags: None,
        authtime: None,
        starttime: None,
        endtime: None,
        renew_till: None,
        srealm: Some(realm.clone()),
        sname: Some(PrincipalName::krbtgt(TEST_REALM)),
        caddr: None,
    };
    let now = KerberosTime::now();
    let part = EncKrbCredPart {
        ticket_info: vec![info],
        nonce: None,
        timestamp: Some(now.clone()),
        usec: Some(Microseconds::from_subsec_micros(
            now.0.timestamp_subsec_micros(),
        )),
        s_address: None,
        r_address: None,
    };
    let cred = KrbCred {
        pvno: KrbCred::PVNO,
        msg_type: KrbCred::MSG_TYPE,
        tickets: vec![as_out.rep.0.ticket.clone()],
        enc_part: EncryptedData {
            etype: tgs_out.session_key.etype().to_iana(),
            kvno: None,
            cipher: encode(&part).unwrap().into(),
        },
    };
    let der = encode(&cred).unwrap();
    let ck = authenticator_checksum(None, GSS_C_DELEG | GSS_C_INTEG, Some(&der));
    let cksum = Checksum {
        cksumtype: GSS_CHECKSUM_TYPE,
        checksum: ck.into(),
    };
    let sub = random_subkey(&tgs_out.session_key).unwrap();
    let enc_sub = EncryptionKey {
        keytype: sub.etype().to_iana(),
        keyvalue: sub.as_bytes().to_vec().into(),
    };
    let ap = build_ap_req_with_cksum(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &realm,
        &cname,
        ApOptions::none(),
        Some(cksum),
        Some(enc_sub),
    )
    .unwrap();
    let token = gss_wrap_app(TOK_AP_REQ, &encode(&ap).unwrap());
    let Err(err) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) else {
        panic!("plaintext EncKrbCredPart must not populate delegated()")
    };
    assert!(
        matches!(err, Error::Inner(ref m) if m == "gss failure"),
        "plaintext KRB-CRED is GSS_S_FAILURE like accept_sec_context.c:571-574, got {err}"
    );
}

#[test]
fn wrap_iov_slices_match_wrap_token() {
    let (mut init, mut acc) = contexts();
    let w = wrap_iov_once(&mut init, b"iov-hello", None);
    assert_eq!(w.header.len(), 32, "GSS 16 + AES confounder 16");
    assert_eq!(w.padding.len(), 0, "AES padding empty");
    assert_eq!(w.trailer.len(), 16 + 12, "E(header)+HMAC-SHA1-96");
    assert_eq!(&w.header[..2], &TOK_WRAP);
    assert_eq!(&w.header[6..8], &[0, 0], "RRC=0");
    let tok: Vec<u8> = [&w.header[..], &w.data[..], &w.padding[..], &w.trailer[..]].concat();
    assert_eq!(acc.unwrap(&tok).unwrap(), b"iov-hello");
    let (mut init, mut acc) = contexts();
    let mut h = Vec::new();
    let mut d = b"iov-hello".to_vec();
    let mut p = Vec::new();
    let mut t = Vec::new();
    init.wrap_iov(
        true,
        &mut [
            IovBuf {
                kind: IovType::Header,
                data: &mut h,
            },
            IovBuf {
                kind: IovType::Data,
                data: &mut d,
            },
            IovBuf {
                kind: IovType::Padding,
                data: &mut p,
            },
            IovBuf {
                kind: IovType::Trailer,
                data: &mut t,
            },
        ],
    )
    .unwrap();
    unwrap_iov_once(&mut acc, &mut h, &mut d, &mut p, &mut t, None).unwrap();
    assert_eq!(d, b"iov-hello");
}

#[test]
fn wrap_iov_rfc8009_sign_only_round_trips() {
    let et = EncryptionType::Aes256CtsHmacSha384192;
    let key = ProtocolKey::from_bytes(et, &[0x5au8; 32]).unwrap();
    let mut init = bare_ctx(key.clone(), true);
    let mut acc = bare_ctx(key, false);
    let mut w = wrap_iov_once(&mut init, b"sha2-body", Some(b"rpc-hdr"));
    assert_eq!(w.trailer.len(), 16 + 24, "E(header)+HMAC-SHA384-192");
    assert_eq!(w.sign, b"rpc-hdr");
    unwrap_iov_once(
        &mut acc,
        &mut w.header,
        &mut w.data,
        &mut w.padding,
        &mut w.trailer,
        Some(&mut w.sign),
    )
    .unwrap();
    assert_eq!(w.data, b"sha2-body");
}

#[test]
fn unwrap_iov_integ_rejects_non_aes() {
    let key = ProtocolKey::from_bytes(EncryptionType::Des3CbcSha1, &[0x11u8; 24]).unwrap();
    let mut ctx = bare_ctx(key, false);
    let mut header = vec![0x05, 0x04, 0x00, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut data = b"x".to_vec();
    let mut padding = Vec::new();
    let mut trailer = Vec::new();
    let err = unwrap_iov_once(
        &mut ctx,
        &mut header,
        &mut data,
        &mut padding,
        &mut trailer,
        None,
    );
    assert!(
        matches!(err, Err(Error::Inner(ref s)) if s.contains("aes")),
        "non-AES unwrap_iov_integ must fail, got {err:?}"
    );
}

/// The EncAPRepPart of an acceptor's AP-REP token, framed or raw (DCE).
fn acceptor_ap_rep(tok: &[u8], ticket_session: &ProtocolKey) -> krb5_types::EncApRepPart {
    let der = if tok.first() == Some(&0x60) {
        let inner = gss_unwrap_app(tok).unwrap();
        assert_eq!(inner[..2], TOK_AP_REP);
        inner[2..].to_vec()
    } else {
        tok.to_vec()
    };
    let ap: ApRep = decode(&der).unwrap();
    let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
    decode(&decrypt(ticket_session, usage, ap.enc_part.cipher.as_ref()).unwrap()).unwrap()
}

fn token_seq(tok: &[u8]) -> u64 {
    u64::from_be_bytes(tok[8..16].try_into().unwrap())
}

#[test]
fn mutual_ap_rep_carries_a_fresh_subkey_and_a_random_seq_that_key_both_sides() {
    let (mut init, mut acc, rep, session) = mutual_pair();
    let part = acceptor_ap_rep(&rep, &session);
    let subkey = part.subkey.unwrap();
    assert_ne!(
        subkey.keyvalue.as_ref(),
        init.session_key().as_bytes(),
        "fresh"
    );
    let seq = part.seq_number.unwrap();
    assert!(seq != 0 && seq < 1 << 30, "random 30-bit seq, got {seq}");
    assert_eq!(acc.send_seq, u64::from(seq));
    assert_eq!(
        acc.acceptor_subkey.as_ref().map(ProtocolKey::as_bytes),
        Some(subkey.keyvalue.as_ref())
    );
    init.process_ap_rep(&rep, &session).unwrap();
    assert_eq!(init.recv_seq, u64::from(seq));

    let up = init.wrap(b"to-acceptor").unwrap();
    assert_eq!(up[2], FLAG_ACCEPTOR_SUBKEY | FLAG_SEALED);
    assert_eq!(acc.unwrap(&up).unwrap(), b"to-acceptor");
    let down = acc.wrap(b"to-initiator").unwrap();
    assert_eq!(down[2], FLAG_ACCEPTOR_SUBKEY | FLAG_SEALED | 0x01);
    assert_eq!(
        token_seq(&down),
        u64::from(seq),
        "the AP-REP's seq comes first"
    );
    assert_eq!(init.unwrap(&down).unwrap(), b"to-initiator");
    let mic = init.get_mic(b"m").unwrap();
    assert_eq!(mic[2], FLAG_ACCEPTOR_SUBKEY);
    acc.verify_mic(b"m", &mic).unwrap();
    let mic = acc.get_mic(b"n").unwrap();
    assert_eq!(mic[2], FLAG_ACCEPTOR_SUBKEY | 0x01);
    init.verify_mic(b"n", &mic).unwrap();
    let integ = acc.wrap_integ(b"i").unwrap();
    assert_eq!(integ[2], FLAG_ACCEPTOR_SUBKEY | 0x01);
    assert_eq!(init.unwrap(&integ).unwrap(), b"i");
}

#[test]
fn without_mutual_the_acceptor_sends_from_the_initiators_seq() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let flags = GSS_C_INTEG | GSS_C_CONF | GSS_C_REPLAY | GSS_C_SEQUENCE;
    let now = KerberosTime::now();
    let authenticator = krb5_types::Authenticator {
        authenticator_vno: krb5_types::Authenticator::VNO,
        crealm: ascii(TEST_REALM),
        cname,
        cksum: Some(Checksum {
            cksumtype: GSS_CHECKSUM_TYPE,
            checksum: authenticator_checksum(None, flags, None).into(),
        }),
        cusec: Microseconds::from_subsec_micros(0),
        ctime: now,
        subkey: None,
        seq_number: Some(4242),
        authorization_data: None,
    };
    let ap = krb5_protocol::build_ap_req_from_authenticator(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        ApOptions::none(),
        &authenticator,
    )
    .unwrap();
    let token = gss_wrap_app(TOK_AP_REQ, &encode(&ap).unwrap());
    let (mut acc, rep) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    assert!(rep.is_none());
    assert!(acc.acceptor_subkey.is_none());
    assert_eq!(token_seq(&acc.wrap(b"x").unwrap()), 4242);
}

#[test]
fn an_ap_rep_that_does_not_echo_the_authenticator_is_not_mutual_authentication() {
    let (mut init, _acc, rep, session) = mutual_pair();
    let (ctime, _) = init.ap_req_time.clone().unwrap();
    init.ap_req_time = Some((ctime, Microseconds::from_subsec_micros(1)));
    match init.process_ap_rep(&rep, &session) {
        Err(Error::Inner(m)) => assert_eq!(m, "Mutual authentication failed"),
        other => panic!("want Mutual authentication failed, got {other:?}"),
    }
    assert!(init.acceptor_subkey.is_none());
}

#[test]
fn dce_third_leg_carries_the_acceptors_random_seq() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let flags = GSS_C_INTEG | GSS_C_CONF | GSS_C_MUTUAL | GSS_C_DCE;
    let subkey = random_subkey(&tgs_out.session_key).unwrap();
    let ap = build_ap_req_with_cksum(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        ApOptions::mutual_required(),
        Some(Checksum {
            cksumtype: GSS_CHECKSUM_TYPE,
            checksum: authenticator_checksum(None, flags, None).into(),
        }),
        Some(EncryptionKey {
            keytype: subkey.etype().to_iana(),
            keyvalue: subkey.as_bytes().to_vec().into(),
        }),
    )
    .unwrap();
    let (mut acc, rep) = GssContext::accept_sec_context(
        &encode(&ap).unwrap(),
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    let part = acceptor_ap_rep(&rep.unwrap(), &tgs_out.session_key);
    assert!(part.subkey.is_some(), "DCE implies an acceptor subkey");
    let seq = part.seq_number.unwrap();
    let third_leg = |nonce: u32| {
        let now = KerberosTime::now();
        let leg = krb5_types::EncApRepPart {
            ctime: now,
            cusec: Microseconds::from_subsec_micros(0),
            subkey: None,
            seq_number: Some(nonce),
        };
        let usage = KeyUsage::new(ku::AP_REP_ENC_PART).unwrap();
        let cipher = encrypt(&tgs_out.session_key, usage, &encode(&leg).unwrap()).unwrap();
        encode(&ApRep {
            pvno: ApRep::PVNO,
            msg_type: ApRep::MSG_TYPE,
            enc_part: EncryptedData {
                etype: tgs_out.session_key.etype().to_iana(),
                kvno: None,
                cipher: cipher.into(),
            },
        })
        .unwrap()
    };
    assert!(matches!(
        acc.accept_dce(&third_leg(seq.wrapping_add(1))),
        Err(Error::Integrity)
    ));
    acc.accept_dce(&third_leg(seq)).unwrap();
}

/// A mutual context and the acceptor's AP-REP token, as `user_host` issues them.
fn mutual_pair() -> (GssContext, GssContext, Vec<u8>, ProtocolKey) {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let (init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        true,
        None,
        None,
    )
    .unwrap();
    let (acc, rep) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    (init, acc, rep.unwrap(), tgs_out.session_key)
}

/// MIT `krb5_decrypt_tkt_part` (`decrypt_tk.c:46-50`): the ticket's own enctype is refused first, with the error table's text alone; once the ticket's is permitted, `negotiate_etype` names the session key's or the subkey's.
#[test]
fn the_acceptor_refuses_ticket_and_session_enctypes_it_does_not_permit() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    assert_eq!(
        tgs_out.session_key.etype(),
        EncryptionType::Aes256CtsHmacSha196
    );
    assert_eq!(
        tgs_out.rep.0.ticket.enc_part.etype,
        EncryptionType::Aes256CtsHmacSha196.to_iana()
    );
    // The same ticket sealed under an aes128-cts service key.
    let aes128 = ProtocolKey::random(EncryptionType::Aes128CtsHmacSha196).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut resealed = tgs_out.rep.0.ticket.clone();
    let plain = decrypt(&skey, usage, resealed.enc_part.cipher.as_ref()).unwrap();
    resealed.enc_part.cipher = encrypt(&aes128, usage, &plain).unwrap().into();
    resealed.enc_part.etype = aes128.etype().to_iana();
    let dir = krb5_testkit::scratch_dir("p15a-gss-permitted");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        "[libdefaults]\n    permitted_enctypes = aes128-cts-hmac-sha1-96\n",
    )
    .unwrap();
    krb5_config::set_test_krb5_paths(Some(vec![conf]));
    let accept = |ticket: &krb5_types::Ticket, key: &ProtocolKey| {
        let (_init, token) = GssContext::init_sec_context(
            ticket.clone(),
            &tgs_out.session_key,
            &ascii(TEST_REALM),
            &cname,
            true,
            None,
            None,
        )
        .unwrap();
        GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(key),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
            &ReplayCache::new(),
        )
        .map(|_| ())
    };
    let ticket_first = accept(&tgs_out.rep.0.ticket, &skey);
    let session_next = accept(&resealed, &aes128);
    krb5_config::set_test_krb5_paths(None);
    let _ = std::fs::remove_dir_all(&dir);
    for (got, want) in [
        (ticket_first, "Encryption type not permitted"),
        (
            session_next,
            "Encryption type aes256-cts-hmac-sha1-96 not permitted",
        ),
    ] {
        match got {
            Err(Error::Inner(m)) => assert_eq!(m, want),
            Err(e) => panic!("want {want:?}, got {e}"),
            Ok(()) => panic!("an aes256 enctype outside permitted_enctypes was accepted"),
        }
    }
}

#[test]
fn wrap_iov_both_ways_under_the_acceptor_subkey() {
    let (mut init, mut acc, rep, session) = mutual_pair();
    init.process_ap_rep(&rep, &session).unwrap();
    let mut up = wrap_iov_once(&mut init, b"iov-up", Some(b"rpc-hdr"));
    assert_eq!(up.header[2], FLAG_ACCEPTOR_SUBKEY | FLAG_SEALED);
    unwrap_iov_once(
        &mut acc,
        &mut up.header,
        &mut up.data,
        &mut up.padding,
        &mut up.trailer,
        Some(&mut up.sign),
    )
    .unwrap();
    assert_eq!(up.data, b"iov-up");
    let mut down = wrap_iov_once(&mut acc, b"iov-down", None);
    assert_eq!(down.header[2], FLAG_ACCEPTOR_SUBKEY | FLAG_SEALED | 0x01);
    unwrap_iov_once(
        &mut init,
        &mut down.header,
        &mut down.data,
        &mut down.padding,
        &mut down.trailer,
        None,
    )
    .unwrap();
    assert_eq!(down.data, b"iov-down");
}
