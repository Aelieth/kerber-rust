//! kadm5 rpcsec tests (private-bound; regrouped in place).

use super::*;

#[test]
fn rpcsec_bad_version_is_auth_badcred() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(99);
    cred.u32(RPG_INIT);
    cred.u32(0);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(13);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(KADM_PROG);
    w.u32(KADM_VERS);
    w.u32(0);
    w.u32(FLAVOR_GSS);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: "KERBER.TEST",
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 13);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_BADCRED);
}

#[test]
fn rpcsec_init_reply_mic_is_window() {
    use krb5_crypto::EncryptionType;
    use krb5_kdc::testrealm::TEST_REALM;

    use krb5_kdc::principals::kadmin_admin;

    use krb5_protocol::{as_req_sname, pa_enc_timestamp};
    use krb5_types::ascii;

    krb5_config::isolate_test_krb5();

    let (store, acl, _) = setup();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let kadm = kadmin_admin();
    let admin_key = {
        let g = store.read().unwrap();
        g.get_name(&admin).unwrap().best_key().unwrap().key.clone()
    };
    let as_req = as_req_sname(
        admin.clone(),
        TEST_REALM,
        7,
        Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        kadm.clone(),
        EncryptionType::preferred()
            .iter()
            .map(|e| e.to_iana())
            .collect(),
    )
    .unwrap();
    let as_out = {
        let g = store.read().unwrap();
        krb5_kdc::issue_as(&*g, &as_req).unwrap()
    };
    let (mut ctx, token) = GssContext::init_sec_context(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &ascii(TEST_REALM),
        &admin,
        krb5_gss::GSS_C_MUTUAL | krb5_gss::GSS_C_REPLAY | krb5_gss::GSS_C_SEQUENCE,
        None,
        None,
        None,
        0,
    )
    .unwrap();
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_INIT);
    cred.u32(0);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut arg = XdrW::default();
    arg.opaque(&token);
    let mut w = XdrW::default();
    w.u32(12);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(IPROP_PROG);
    w.u32(IPROP_VERS);
    w.u32(IPROP_NULL);
    w.u32(FLAVOR_GSS);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.b.extend_from_slice(&arg.b);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 12);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let verf = r.opaque().unwrap();
    assert!(!verf.is_empty(), "INIT verifier must be MIC of the window");
    assert_eq!(r.u32().unwrap(), SUCCESS);
    let _handle = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), 0);
    let _minor = r.u32().unwrap();
    let window = r.u32().unwrap();
    assert_eq!(window, RPCSEC_SEQ_WINDOW);
    let out_tok = r.opaque().unwrap();
    let part = ap_rep_part(&out_tok, &as_out.session_key);
    let subkey = part.subkey.expect("the AP-REP carries an acceptor subkey");
    assert_ne!(
        subkey.keyvalue.as_ref(),
        ctx.session_key().as_bytes(),
        "a fresh key, not the initiator's subkey"
    );
    let seq = part.seq_number.expect("the AP-REP carries a seq-number");
    assert!(seq != 0 && seq < 1 << 30, "a random 30-bit seq, got {seq}");
    assert_eq!(verf[2], 0x05, "sent by the acceptor under its subkey");
    let verf_seq = u64::from_be_bytes(verf[8..16].try_into().unwrap());
    assert_eq!(verf_seq, u64::from(seq) + 1);
    ctx.process_ap_rep(&out_tok, &as_out.session_key).unwrap();
    ctx.verify_mic(&window.to_be_bytes(), &verf)
        .expect("INIT xp_verf is MIC(htonl(window))");
}

fn ap_rep_part(tok: &[u8], session: &krb5_crypto::ProtocolKey) -> krb5_types::EncApRepPart {
    let hdr = if tok[1] & 0x80 == 0 {
        2
    } else {
        2 + usize::from(tok[1] & 0x7f)
    };
    let body = &tok[hdr + 11..];
    assert_eq!(&body[..2], &[0x02, 0x00]);
    let ap: krb5_types::ApRep = krb5_asn1::decode(&body[2..]).unwrap();
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::AP_REP_ENC_PART).unwrap();
    let plain = krb5_crypto::decrypt(session, usage, ap.enc_part.cipher.as_ref()).unwrap();
    krb5_asn1::decode(&plain).unwrap()
}

#[test]
fn rpcsec_bad_mic_is_credproblem() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, _ctx, handle, mut gss) = admin_rpcsec_init();
    let cred = rpcsec_cred(RPG_DATA, 1, GSS_PRIVACY, &handle);
    let rec = rpcsec_call(
        RpcCallId {
            xid: 25,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc: GET_PRIVS,
        },
        &cred,
        FLAVOR_GSS,
        b"not-a-mic",
        &[],
    );
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        &peer(),
    )
    .unwrap();
    let (xid, why) = decode_denied(&out);
    assert_eq!(xid, 25);
    assert_eq!(why, RPCSEC_GSS_CREDPROBLEM);
}

#[test]
fn rpcsec_wrong_handle_data_is_dispatched() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, _handle, mut gss) = admin_rpcsec_init();
    let rec = rpcsec_data_rec(
        &mut ctx,
        RpcCallId {
            xid: 50,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc: GET_PRIVS,
        },
        1,
        b"WRONGHDL",
        &[],
        true,
    );
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 50);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let _verf = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
}

#[test]
fn rpcsec_seq_over_maxseq_is_ctxproblem() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let rec = rpcsec_data_rec(
        &mut ctx,
        RpcCallId {
            xid: 26,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc: GET_PRIVS,
        },
        MAXSEQ.saturating_add(1),
        &handle,
        &[],
        true,
    );
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        &peer(),
    )
    .unwrap();
    let (xid, why) = decode_denied(&out);
    assert_eq!(xid, 26);
    assert_eq!(why, RPCSEC_GSS_CTXPROBLEM);
}

#[test]
fn rpcsec_seq_replay_is_ctxproblem() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let rec1 = rpcsec_data_rec(
        &mut ctx,
        RpcCallId {
            xid: 27,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc: GET_PRIVS,
        },
        1,
        &handle,
        &[],
        true,
    );
    let mut agss = None;
    let out1 = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec1,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out1);
    assert_eq!(r.u32().unwrap(), 27);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    let rec2 = rpcsec_data_rec(
        &mut ctx,
        RpcCallId {
            xid: 28,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc: GET_PRIVS,
        },
        1,
        &handle,
        &[],
        true,
    );
    let out2 = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec2,
        &peer(),
    )
    .unwrap();
    let (xid, why) = decode_denied(&out2);
    assert_eq!(xid, 28);
    assert_eq!(why, RPCSEC_GSS_CTXPROBLEM);
}

#[test]
fn rpcsec_unwrap_fail_is_garbage_args_with_verf() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let cred = rpcsec_cred(RPG_DATA, 1, GSS_PRIVACY, &handle);
    let mut header = XdrW::default();
    header.u32(32);
    header.u32(MSG_CALL);
    header.u32(RPC_VERSION);
    header.u32(KADM_PROG);
    header.u32(KADM_VERS);
    header.u32(GET_PRIVS);
    header.u32(FLAVOR_GSS);
    header.opaque(&cred);
    let mic = ctx.get_mic(&header.b).unwrap();
    let mut arg = XdrW::default();
    arg.opaque(b"\x00\x01");
    let rec = rpcsec_call(
        RpcCallId {
            xid: 32,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc: GET_PRIVS,
        },
        &cred,
        FLAVOR_GSS,
        &mic,
        &arg.b,
    );
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 32);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let verf = r.opaque().unwrap();
    assert_ne!(verf, [] as [u8; 0]);
    assert_eq!(r.u32().unwrap(), GARBAGE_ARGS);
}

#[test]
fn rpcsec_integrity_bad_checksum_is_garbage_args() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init_svc(GSS_INTEGRITY);
    let rec = rpcsec_integ_rec(&mut ctx, 41, GET_PRINCS, 1, &handle, &list_args(), true);
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
            expected_realm: TEST_REALM,
            conf: &AcceptorConfig::default(),
            programs: Programs::BOTH,
            iprop_resync: None,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 41);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let _verf = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), GARBAGE_ARGS);
}

#[test]
fn rpcsec_privacy_body_sequence_must_match_the_credential() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let call = |ctx: &mut GssContext, xid: u32, seq: u32, body_seq: u32| {
        rpcsec_priv_rec(
            ctx,
            RpcCallId {
                xid,
                prog: KADM_PROG,
                vers: KADM_VERS,
                proc: GET_PRINCS,
            },
            seq,
            body_seq,
            &handle,
            &list_args(),
        )
    };
    let mut accepted = |rec: &[u8]| -> u32 {
        let mut agss = None;
        let out = handle_rpc(
            RpcCtx {
                store: &store,
                authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
                expected_realm: TEST_REALM,
                conf: &AcceptorConfig::default(),
                programs: Programs::BOTH,
                iprop_resync: None,
            },
            b"hdl",
            &mut gss,
            &mut agss,
            &krb5_protocol::ReplayCache::new(),
            rec,
            &peer(),
        )
        .unwrap();
        let mut r = XdrR::new(&out);
        r.u32().unwrap();
        assert_eq!(r.u32().unwrap(), MSG_REPLY);
        assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
        assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
        let _verf = r.opaque().unwrap();
        r.u32().unwrap()
    };
    let spliced = call(&mut ctx, 50, 2, 1);
    assert_eq!(accepted(&spliced), GARBAGE_ARGS);
    let matching = call(&mut ctx, 51, 3, 3);
    assert_eq!(accepted(&matching), SUCCESS);
}
