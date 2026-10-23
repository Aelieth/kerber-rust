use super::context::TOK_AP_REQ;
use super::oid::{gss_unwrap_app, gss_wrap_app};
use super::wrap::TOK_WRAP;
use super::*;
use krb5_asn1::encode;
use krb5_protocol::{AcceptorConfig, ReplayCache};
use krb5_types::{ApOptions, PrincipalName};

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
        crate::GSS_C_REPLAY | crate::GSS_C_SEQUENCE,
        None,
        None,
        None,
        0,
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
        &AcceptorConfig::default(),
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
        &AcceptorConfig::default(),
    ) {
        Err(Error::Integrity) => {}
        Err(err) => panic!("non-0x8003 over data must be Integrity, got {err}"),
        Ok(_) => panic!("non-0x8003 over data must be Integrity"),
    }
}

#[test]
fn eight_octet_length_is_truncated_not_panic() {
    let ff = [0xff; 8];
    let outer = [&[0x60, 0x88][..], &ff, &[0x06]].concat();
    let oid = [&[0x60, 0x0a, 0x06, 0x88][..], &ff].concat();
    let key = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).unwrap();
    let (rc, conf) = (ReplayCache::new(), AcceptorConfig::default());
    assert!(matches!(spnego_inner(&outer), Err(Error::Truncated)));
    assert!(matches!(
        spnego_accept(&outer, &[], None, None, None, &rc, &conf),
        Err(Error::Truncated)
    ));
    assert!(matches!(gss_unwrap_app(&oid), Err(Error::Truncated)));
    assert!(matches!(
        GssContext::accept_sec_context(&oid, &[key], None, None, None, &rc, &conf),
        Err(Error::Truncated)
    ));
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
