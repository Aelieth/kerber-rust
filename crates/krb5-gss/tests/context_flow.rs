//! GSS init/accept whole-flow tests (public API).

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_gss::{
    ChannelBindings, DelegCred, Error, GSS_C_CONF, GSS_C_INTEG, GSS_C_TRANS, GssContext, IovBuf,
    IovType, is_spnego, mit_shaped_wrap, spnego_accept, spnego_init,
};
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::ReplayCache;
use krb5_types::{PrincipalName, TicketFlags, ascii};

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

#[test]
fn accept_same_token_twice_is_repeat() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        false,
        None,
        None,
    )
    .unwrap();
    let rcache = ReplayCache::new();
    GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &rcache,
    )
    .expect("first accept");
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &rcache,
    ) {
        Err(err) => {
            assert_eq!(err.to_string(), "KRB-ERROR 34: authenticator replay");
        }
        Ok(_) => panic!("replayed AP-REQ must be 34"),
    }
}

#[test]
fn wrap_unwrap_mic_round_trip() {
    let (mut init, mut acc) = contexts();
    let wrapped = init.wrap(b"hello gss").unwrap();
    assert_eq!(&wrapped[6..8], &[0, 0], "MIT wrap uses RRC=0");
    let plain = acc.unwrap(&wrapped).unwrap();
    assert_eq!(plain, b"hello gss");
    let mic = init.get_mic(b"hello gss").unwrap();
    acc.verify_mic(b"hello gss", &mic).unwrap();
    assert!(acc.unwrap(&wrapped).is_err());
}

#[test]
fn garbage_mac_does_not_consume_seq() {
    let (mut init, mut acc) = contexts();
    let good = init.wrap(b"keep-seq").unwrap();
    let mut bad = good.clone();
    let last = bad.last_mut().expect("wrap token");
    *last ^= 0xff;
    assert!(acc.unwrap(&bad).is_err(), "garbage MAC must fail");
    assert_eq!(
        acc.unwrap(&good).unwrap(),
        b"keep-seq",
        "in-window seq must still accept a later good MAC"
    );
    let (mut init, mut acc) = contexts();
    let mic = init.get_mic(b"keep-seq").unwrap();
    let mut bad = mic.clone();
    let last = bad.last_mut().expect("mic token");
    *last ^= 0xff;
    assert!(matches!(
        acc.verify_mic(b"keep-seq", &bad),
        Err(Error::Integrity)
    ));
    acc.verify_mic(b"keep-seq", &mic).unwrap();
}

#[test]
fn wrap_integ_wrong_ec_is_truncated() {
    let (mut init, mut acc) = contexts();
    let mut tok = init.wrap_integ(b"ec").unwrap();
    tok[5] = tok[5].wrapping_add(1);
    assert!(matches!(acc.unwrap(&tok), Err(Error::Truncated)));
}

#[test]
fn verify_mic_bad_filler_is_truncated() {
    let (mut init, mut acc) = contexts();
    let mut mic = init.get_mic(b"mic").unwrap();
    mic[3] = 0x00;
    assert!(matches!(
        acc.verify_mic(b"mic", &mic),
        Err(Error::Truncated)
    ));
}

#[test]
fn channel_bindings_must_match() {
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
        7,
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
        8,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let cb = ChannelBindings {
        application_data: b"tls-unique-test".to_vec(),
        ..ChannelBindings::default()
    };
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        false,
        Some(&cb),
        None,
    )
    .unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    let skey = &host.best_key().unwrap().key;
    GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(skey),
        Some(&cb),
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    let other = ChannelBindings {
        application_data: b"other".to_vec(),
        ..ChannelBindings::default()
    };
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(skey),
        Some(&other),
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) {
        Err(Error::ChannelBindings) => {}
        Err(e) => panic!("expected channel bindings error, got {e}"),
        Ok(_) => panic!("expected channel bindings error"),
    }
    GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .expect("acceptor GSS_C_NO_CHANNEL_BINDINGS ignores token CB");
}

#[test]
fn spnego_accept_emits_neg_token_resp() {
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
    let tok = spnego_init(&krb);
    assert!(is_spnego(&tok));
    let (acc, resp) = spnego_accept(
        &tok,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    assert_eq!(
        resp.first().copied(),
        Some(0xa1),
        "MIT wants bare NegTokenResp"
    );
    assert!(acc.client.is_some());
}

#[test]
fn acceptor_rejects_wrong_service_name() {
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
        9,
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
        10,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let (_init, token) = GssContext::init_sec_context(
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
    let wrong = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "other.example"]);
    let Err(err) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(skey),
        None,
        Some(&wrong),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) else {
        panic!("wrong service accepted")
    };
    assert!(
        err.to_string().contains("NOT_US")
            || err.to_string().contains("sname")
            || err.to_string().contains("35")
            || err.to_string().contains("does not match"),
        "got {err}"
    );
    assert!(
        GssContext::accept_sec_context(
            &token,
            std::slice::from_ref(skey),
            None,
            Some(&documented_host()),
            Some(TEST_REALM),
            &ReplayCache::new(),
        )
        .is_ok(),
        "matching service"
    );
}

#[test]
fn first_seq_must_match_authenticator_base() {
    let (init, mut acc) = contexts();
    let bad = mit_shaped_wrap(init.session_key(), true, 5, b"skip").unwrap();
    assert!(matches!(acc.unwrap(&bad), Err(Error::Sequence)));
    let good = mit_shaped_wrap(init.session_key(), true, 0, b"ok").unwrap();
    assert_eq!(acc.unwrap(&good).unwrap(), b"ok");
}

#[test]
fn rpcsec_init_window_accepts_seq_gap_default_rejects() {
    let (mut strict, acc) = contexts();
    let gap = mit_shaped_wrap(acc.session_key(), false, 1, b"init-win").unwrap();
    assert!(
        matches!(strict.unwrap(&gap), Err(Error::Sequence)),
        "default first-recv must match authenticator base"
    );
    let (mut iprop, acc) = contexts();
    iprop.allow_rpcsec_init_window();
    let gap = mit_shaped_wrap(acc.session_key(), false, 1, b"init-win").unwrap();
    assert_eq!(iprop.unwrap(&gap).unwrap(), b"init-win");
}

#[test]
fn mutual_ap_rep_decrypts_with_ticket_session() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let (mut init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        true,
        None,
        None,
    )
    .unwrap();
    let (_acc, ap_rep) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    let tok = ap_rep.expect("mutual AP-REP");
    init.process_ap_rep(&tok, &tgs_out.session_key).unwrap();
}

#[test]
fn wrap_mic_replay_inside_window_is_rejected() {
    let (mut init, mut acc) = contexts();
    let w = init.wrap(b"one").unwrap();
    acc.unwrap(&w).unwrap();
    // Gap inside the window is accepted (seq 0 then seq 2).
    let gap = mit_shaped_wrap(init.session_key(), true, 2, b"gap").unwrap();
    assert_eq!(acc.unwrap(&gap).unwrap(), b"gap");
    assert!(matches!(acc.unwrap(&w), Err(Error::Sequence)));
    let mic = init.get_mic(b"one").unwrap();
    acc.verify_mic(b"one", &mic).unwrap();
    assert!(matches!(acc.verify_mic(b"one", &mic), Err(Error::Sequence)));
}

#[test]
fn rrc_nonzero_round_trip_pins_rotate_direction() {
    let (mut init, mut acc) = contexts();
    let tok = init.wrap_with_rrc(b"rrc-payload", 16).unwrap();
    assert_ne!(&tok[6..8], &[0, 0], "RRC field must be non-zero");
    let plain = acc.unwrap(&tok).unwrap();
    assert_eq!(plain, b"rrc-payload");
}

#[test]
fn accept_extracts_delegated_client() {
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
    let (acc, _) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .unwrap();
    let want = format!("{TEST_USER}@{TEST_REALM}");
    assert_eq!(acc.delegated(), Some(want.as_str()));
}

#[test]
fn wrap_iov_sign_only_is_checksummed_not_encrypted() {
    let (mut init, mut acc) = contexts();
    let assoc = b"rpc-hdr";
    let mut w = wrap_iov_once(&mut init, b"body", Some(assoc));
    assert_eq!(w.sign, assoc, "SIGN_ONLY is not encrypted");
    assert_ne!(w.data, b"body", "DATA is ciphertext");
    unwrap_iov_once(
        &mut acc,
        &mut w.header,
        &mut w.data,
        &mut w.padding,
        &mut w.trailer,
        Some(&mut w.sign),
    )
    .unwrap();
    assert_eq!(w.data, b"body");
    let (mut init, mut acc) = contexts();
    let mut w = wrap_iov_once(&mut init, b"body", Some(assoc));
    let mut bad = assoc.to_vec();
    bad[0] ^= 1;
    assert!(matches!(
        unwrap_iov_once(
            &mut acc,
            &mut w.header,
            &mut w.data,
            &mut w.padding,
            &mut w.trailer,
            Some(&mut bad)
        ),
        Err(Error::Integrity)
    ));
}

#[test]
fn wrap_iov_integ_aes_round_trips() {
    let (mut init, mut acc) = contexts();
    let mut h = Vec::new();
    let mut d = b"integ-only".to_vec();
    let mut p = Vec::new();
    let mut t = Vec::new();
    init.wrap_iov(
        false,
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
    assert_eq!(d, b"integ-only");
}

#[test]
fn export_import_wrap_still_works() {
    let (mut init, acc) = contexts();
    let w = init.wrap(b"keep").unwrap();
    let tok = acc.export_sec_context().unwrap();
    let mut acc2 = GssContext::import_sec_context(&tok).unwrap();
    assert_eq!(acc2.unwrap(&w).unwrap(), b"keep");
    let w2 = init.wrap(b"again").unwrap();
    assert_eq!(acc2.unwrap(&w2).unwrap(), b"again");
    assert!(matches!(
        GssContext::import_sec_context(&tok[..8]),
        Err(Error::Truncated)
    ));
    assert!(matches!(
        GssContext::import_sec_context(b"XXXX"),
        Err(Error::Truncated)
    ));
}

#[test]
fn inquire_reports_lifetime_and_flags() {
    let (_init, acc) = contexts();
    let q = acc.inquire_context();
    assert!(!q.initiator);
    assert_ne!(q.flags & GSS_C_INTEG, 0);
    assert_ne!(q.flags & GSS_C_CONF, 0);
    assert_ne!(q.flags & GSS_C_TRANS, 0);
    assert!(q.lifetime > 0, "ticket endtime must be stashed");
    assert!(q.client.is_some());
    let (init, _) = contexts();
    assert!(init.inquire_context().initiator);
    assert_ne!(init.gss_flags() & GSS_C_INTEG, 0);
}

#[test]
fn wrap_iov_hostile_header_is_truncated() {
    let (mut init, _acc) = contexts();
    let mut data = b"x".to_vec();
    let mut trailer = Vec::new();
    let r = init.wrap_iov(
        true,
        &mut [
            IovBuf {
                kind: IovType::Data,
                data: &mut data,
            },
            IovBuf {
                kind: IovType::Trailer,
                data: &mut trailer,
            },
        ],
    );
    assert!(matches!(r, Err(Error::Truncated)));
    let (h, pad, t) = init.wrap_iov_length(true).unwrap();
    assert_eq!((h, pad, t), (32, 0, 28));
}
