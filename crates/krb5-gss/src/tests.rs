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

use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_kdc::{S2K_ITERS, as_req, pa_enc_timestamp, tgs_req};

use krb5_types::ascii;

struct WrappedIov {
    header: Vec<u8>,
    data: Vec<u8>,
    padding: Vec<u8>,
    trailer: Vec<u8>,
    sign: Vec<u8>,
}

fn contexts() -> (GssContext, GssContext) {
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
    use krb5_types::{EncApRepPart, EncryptedData, EncryptionKey, KerberosTime, Microseconds};

    let (mut init, _acc) = contexts();
    let et = init.session_key().etype();
    let mut ticket_raw = vec![0u8; et.key_len()];
    getrandom::getrandom(&mut ticket_raw).unwrap();
    let ticket = ProtocolKey::from_bytes(et, &ticket_raw).unwrap();
    let mut raw = vec![0u8; et.key_len()];
    getrandom::getrandom(&mut raw).unwrap();
    let sub = ProtocolKey::from_bytes(et, &raw).unwrap();
    let part = EncApRepPart {
        ctime: KerberosTime::now(),
        cusec: Microseconds::new(0).unwrap(),
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
