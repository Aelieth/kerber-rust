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
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
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
fn rpcsec_unknown_program_bad_version_is_auth_badcred() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(99);
    cred.u32(RPG_INIT);
    cred.u32(0);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(15);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(99_999);
    w.u32(1);
    w.u32(0);
    w.u32(FLAVOR_GSS);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 15);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_BADCRED);
}

#[test]
fn rpcsec_init_non_nullproc_is_auth_failed() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_INIT);
    cred.u32(0);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(21);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(KADM_PROG);
    w.u32(KADM_VERS);
    w.u32(12);
    w.u32(FLAVOR_GSS);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 21);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_FAILED);
}

#[test]
fn rpcsec_data_without_context_is_credproblem() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_DATA);
    cred.u32(1);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(14);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(KADM_PROG);
    w.u32(KADM_VERS);
    w.u32(12);
    w.u32(FLAVOR_GSS);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 14);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), RPCSEC_GSS_CREDPROBLEM);
}

#[test]
fn rpcsec_unknown_program_data_without_context_is_credproblem() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_DATA);
    cred.u32(1);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(16);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(99_999);
    w.u32(1);
    w.u32(12);
    w.u32(FLAVOR_GSS);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 16);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), RPCSEC_GSS_CREDPROBLEM);
}

#[test]
fn rpc_reply_gss_verf_is_rpcsec_gss_mic() {
    let out = rpc_reply_gss_verf(3, b"mic-bytes", b"init-body");
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 3);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    assert_eq!(r.opaque().unwrap(), b"mic-bytes");
    assert_eq!(r.u32().unwrap(), SUCCESS);
    assert_eq!(r.rest(), b"init-body");
}

#[test]
fn rpcsec_init_reply_mic_is_window() {
    use krb5_crypto::EncryptionType;
    use krb5_kdc::{TEST_REALM, documented_kadmin};
    use krb5_protocol::{as_req_sname, pa_enc_timestamp};
    use krb5_types::ascii;

    let (store, acl, _) = setup();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let kadm = documented_kadmin();
    let (admin_key, kadm_key) = {
        let g = store.read().unwrap();
        (
            g.get_name(&admin).unwrap().best_key().unwrap().key.clone(),
            g.get_name(&kadm).unwrap().best_key().unwrap().key.clone(),
        )
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
        true,
        None,
        None,
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
        &store,
        &acl,
        &[kadm_key],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
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
    let _out_tok = r.opaque().unwrap();
    ctx.verify_mic(&window.to_be_bytes(), &verf)
        .expect("INIT xp_verf is MIC(htonl(window))");
}

#[test]
fn rpcsec_unknown_gc_proc_is_rejectedcred() {
    let (store, acl, _) = setup();
    let cred = rpcsec_cred(99, 0, GSS_PRIVACY, &[]);
    let rec = rpcsec_call(22, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_NONE, &[], &[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let (xid, why) = decode_denied(&out);
    assert_eq!(xid, 22);
    assert_eq!(why, AUTH_REJECTEDCRED);
}

#[test]
fn rpcsec_init_garbage_token_is_rejectedcred() {
    let (store, acl, _) = setup();
    let cred = rpcsec_cred(RPG_INIT, 0, GSS_PRIVACY, &[]);
    let mut arg = XdrW::default();
    arg.opaque(&[0xff, 0x00]);
    let rec = rpcsec_call(23, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_NONE, &[], &arg.b);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let (xid, why) = decode_denied(&out);
    assert_eq!(xid, 23);
    assert_eq!(why, AUTH_REJECTEDCRED);
    assert!(gss.is_none());
}

#[test]
fn rpcsec_destroy_without_context_is_credproblem() {
    let (store, acl, _) = setup();
    let cred = rpcsec_cred(RPG_DESTROY, 1, GSS_PRIVACY, &[]);
    let rec = rpcsec_call(24, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_NONE, &[], &[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        "KERBER.TEST",
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let (xid, why) = decode_denied(&out);
    assert_eq!(xid, 24);
    assert_eq!(why, RPCSEC_GSS_CREDPROBLEM);
}

#[test]
fn rpcsec_bad_mic_is_credproblem() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, _ctx, handle, mut gss) = admin_rpcsec_init();
    let cred = rpcsec_cred(RPG_DATA, 1, GSS_PRIVACY, &handle);
    let rec = rpcsec_call(
        25,
        KADM_PROG,
        KADM_VERS,
        GET_PRIVS,
        &cred,
        FLAVOR_GSS,
        b"not-a-mic",
        &[],
    );
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let (xid, why) = decode_denied(&out);
    assert_eq!(xid, 25);
    assert_eq!(why, RPCSEC_GSS_CREDPROBLEM);
}

#[test]
fn rpcsec_wrong_handle_data_is_dispatched() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, _handle, mut gss) = admin_rpcsec_init();
    let rec = rpcsec_data_rec(
        &mut ctx,
        50,
        KADM_PROG,
        KADM_VERS,
        GET_PRIVS,
        1,
        b"WRONGHDL",
        &[],
        true,
    );
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
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
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let rec = rpcsec_data_rec(
        &mut ctx,
        26,
        KADM_PROG,
        KADM_VERS,
        GET_PRIVS,
        MAXSEQ.saturating_add(1),
        &handle,
        &[],
        true,
    );
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let (xid, why) = decode_denied(&out);
    assert_eq!(xid, 26);
    assert_eq!(why, RPCSEC_GSS_CTXPROBLEM);
}

#[test]
fn rpcsec_seq_replay_is_ctxproblem() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let rec1 = rpcsec_data_rec(
        &mut ctx,
        27,
        KADM_PROG,
        KADM_VERS,
        GET_PRIVS,
        1,
        &handle,
        &[],
        true,
    );
    let mut agss = None;
    let out1 = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec1,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out1);
    assert_eq!(r.u32().unwrap(), 27);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    let rec2 = rpcsec_data_rec(
        &mut ctx,
        28,
        KADM_PROG,
        KADM_VERS,
        GET_PRIVS,
        1,
        &handle,
        &[],
        true,
    );
    let out2 = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec2,
        "127.0.0.1",
    )
    .unwrap();
    let (xid, why) = decode_denied(&out2);
    assert_eq!(xid, 28);
    assert_eq!(why, RPCSEC_GSS_CTXPROBLEM);
}

#[test]
fn rpcsec_destroy_then_data_is_credproblem() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let cred = rpcsec_cred(RPG_DESTROY, 1, GSS_PRIVACY, &handle);
    let mut header = XdrW::default();
    header.u32(29);
    header.u32(MSG_CALL);
    header.u32(RPC_VERSION);
    header.u32(KADM_PROG);
    header.u32(KADM_VERS);
    header.u32(0);
    header.u32(FLAVOR_GSS);
    header.opaque(&cred);
    let mic = ctx.get_mic(&header.b).unwrap();
    let rec = rpcsec_call(29, KADM_PROG, KADM_VERS, 0, &cred, FLAVOR_GSS, &mic, &[]);
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 29);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert!(gss.is_none(), "DESTROY drops the context");
    let rec2 = rpcsec_data_rec(
        &mut ctx,
        30,
        KADM_PROG,
        KADM_VERS,
        GET_PRIVS,
        2,
        &handle,
        &[],
        true,
    );
    let out2 = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec2,
        "127.0.0.1",
    )
    .unwrap();
    let (xid, why) = decode_denied(&out2);
    assert_eq!(xid, 30);
    assert_eq!(why, RPCSEC_GSS_CREDPROBLEM);
}

#[test]
fn rpcsec_unknown_program_data_carries_xp_verf() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init();
    let rec = rpcsec_data_rec(&mut ctx, 31, 99_999, 1, 0, 1, &handle, &[], true);
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 31);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let verf = r.opaque().unwrap();
    assert!(!verf.is_empty(), "PROG_UNAVAIL carries xp_verf");
    assert_eq!(r.u32().unwrap(), PROG_UNAVAIL);
    ctx.verify_mic(&1u32.to_be_bytes(), &verf)
        .expect("DATA xp_verf is MIC(htonl(seq))");
}

#[test]
fn rpcsec_unwrap_fail_is_garbage_args_with_verf() {
    use krb5_kdc::TEST_REALM;
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
        32, KADM_PROG, KADM_VERS, GET_PRIVS, &cred, FLAVOR_GSS, &mic, &arg.b,
    );
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 32);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let verf = r.opaque().unwrap();
    assert!(!verf.is_empty());
    assert_eq!(r.u32().unwrap(), GARBAGE_ARGS);
}

#[test]
fn rpcsec_integrity_data_round_trips() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init_svc(GSS_INTEGRITY);
    let rec = rpcsec_integ_rec(&mut ctx, 40, GET_PRINCS, 1, &handle, &list_args(), false);
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 40);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let verf = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
    ctx.verify_mic(&1u32.to_be_bytes(), &verf).unwrap();
    let databody = r.opaque().unwrap();
    let checksum = r.opaque().unwrap();
    ctx.verify_mic(&databody, &checksum).unwrap();
    assert_eq!(databody[..4], 1u32.to_be_bytes()[..]);
    let mut body = XdrR::new(&databody[4..]);
    assert_eq!(body.u32().unwrap(), API_V2);
    assert_eq!(body.u32().unwrap(), 0);
}

#[test]
fn rpcsec_integrity_bad_checksum_is_garbage_args() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init_svc(GSS_INTEGRITY);
    let rec = rpcsec_integ_rec(&mut ctx, 41, GET_PRINCS, 1, &handle, &list_args(), true);
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
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
fn rpcsec_none_service_data_is_plain_body() {
    use krb5_kdc::TEST_REALM;
    let (store, acl, mut ctx, handle, mut gss) = admin_rpcsec_init_svc(GSS_NONE);
    let cred = rpcsec_cred(RPG_DATA, 1, GSS_NONE, &handle);
    let mut header = XdrW::default();
    header.u32(43);
    header.u32(MSG_CALL);
    header.u32(RPC_VERSION);
    header.u32(KADM_PROG);
    header.u32(KADM_VERS);
    header.u32(GET_PRINCS);
    header.u32(FLAVOR_GSS);
    header.opaque(&cred);
    let mic = ctx.get_mic(&header.b).unwrap();
    let rec = rpcsec_call(
        43,
        KADM_PROG,
        KADM_VERS,
        GET_PRINCS,
        &cred,
        FLAVOR_GSS,
        &mic,
        &list_args(),
    );
    let mut agss = None;
    let out = handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 43);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let verf = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
    ctx.verify_mic(&1u32.to_be_bytes(), &verf).unwrap();
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
}
