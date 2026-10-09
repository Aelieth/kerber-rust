//! kadm5 auth_gssapi tests (private-bound; regrouped in place).

use super::*;

#[test]
fn auth_gssapi_on_iprop_data_is_auth_failed() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(AUTH_GSSAPI_CREDS_VERS);
    cred.u32(0);
    cred.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(11);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(IPROP_PROG);
    w.u32(IPROP_VERS);
    w.u32(IPROP_GET_UPDATES);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
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
    assert_eq!(r.u32().unwrap(), 11);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_FAILED);
}

#[test]
fn auth_gssapi_on_iprop_init_is_success() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(AUTH_GSSAPI_CREDS_VERS);
    cred.u32(1);
    cred.opaque(&[]);
    let mut args = XdrW::default();
    args.u32(2);
    args.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(12);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(IPROP_PROG);
    w.u32(IPROP_VERS);
    w.u32(AUTH_GSSAPI_INIT);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.b.extend_from_slice(&args.b);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
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
    assert_eq!(r.u32().unwrap(), 12);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
    let _verf = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
}

/// GSSAPI_DESTROY is the auth layer's on any program, once the record's verifier checks out: one
/// that does not unseal is AUTH_BADVERF and the record stays; the next sequence number is
/// answered under the reply verifier with the reply's sequence number sealed as the body, and the
/// record is gone.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:516-524`): a verifier that does not unseal is
/// AUTH_BADVERF.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:616-625`): GSSAPI_DESTROY is answered, then
/// the record goes; settled live, a destroy from MIT's kadmin answered so.
#[test]
fn auth_gssapi_destroy_on_iprop_is_auth_layer() {
    let mut c = Established::new(IPROP_PROG, IPROP_VERS);
    let s = c.seq;
    let cred = c.cred(true);
    let out = c
        .send(&agss_call(
            14,
            IPROP_PROG,
            IPROP_VERS,
            AUTH_GSSAPI_DESTROY,
            &cred,
            None,
            &[],
        ))
        .unwrap();
    assert_eq!(decode_denied(&out), (14, AUTH_BADVERF));
    assert!(c.agss.is_some(), "the record stays");
    let verf = c.verf(s.wrapping_add(1));
    let rec = agss_call(
        15,
        IPROP_PROG,
        IPROP_VERS,
        AUTH_GSSAPI_DESTROY,
        &cred,
        Some(&verf),
        &[],
    );
    let out = c.send(&rec).unwrap();
    let body = c.success(&out, 15, s.wrapping_add(2));
    assert_eq!(c.unseal(&body), s.wrapping_add(2).to_be_bytes());
    assert!(c.agss.is_none(), "the record is gone");
}

#[test]
fn auth_gssapi_creds_and_init_res_xdr() {
    let mut w = XdrW::default();
    w.u32(2);
    w.u32(1); // auth_msg TRUE
    w.opaque(&[]);
    let mut r = XdrR::new(&w.b);
    assert_eq!(r.u32().unwrap(), 2);
    assert!(r.bool().unwrap());
    assert_eq!(r.opaque().unwrap(), [] as [u8; 0]);

    let mut body = XdrW::default();
    encode_init_res(&mut body, 4, &1u32.to_le_bytes(), 0, 0, b"tok", b"isn");
    let mut r = XdrR::new(&body.b);
    assert_eq!(r.u32().unwrap(), 4);
    assert_eq!(r.opaque().unwrap(), 1u32.to_le_bytes());
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.opaque().unwrap(), b"tok");
    assert_eq!(r.opaque().unwrap(), b"isn");
}

#[test]
fn kadm5_auth_gssapi_ok_requires_store_realm() {
    let admin = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
    let realm = "KERBER.TEST";
    assert!(acceptor_realm_ok(
        Some(&admin),
        Some(realm),
        realm,
        kadm5_auth_gssapi_ok
    ));
    assert!(!acceptor_realm_ok(
        Some(&admin),
        Some("OTHER.REALM"),
        realm,
        kadm5_auth_gssapi_ok
    ));
}

/// An established AUTH_GSSAPI call on the iprop program is authenticated first: without iprop
/// the program is not registered, so the call is PROG_UNAVAIL under its verifier (MIT
/// `svc_do_xprt`); once the update log is mapped the iprop dispatcher refuses the flavor.
#[cfg(feature = "test-hooks")]
#[test]
fn an_established_auth_gssapi_call_on_iprop_is_prog_unavail_until_iprop_is_on() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, token, kadm_key, session) = admin_gss_token();
    let keys = [kadm_key];
    let rc = krb5_protocol::ReplayCache::new();
    let mut gss = None;
    let mut agss = None;
    let call = |xid: u32, proc: u32, cred: &[u8], verf: (u32, &[u8]), args: &[u8]| {
        let mut w = XdrW::default();
        w.u32(xid);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(IPROP_PROG);
        w.u32(IPROP_VERS);
        w.u32(proc);
        w.u32(FLAVOR_AUTH_GSSAPI);
        w.opaque(cred);
        w.u32(verf.0);
        w.opaque(verf.1);
        w.b.extend_from_slice(args);
        w.b
    };
    let mut init_cred = XdrW::default();
    init_cred.u32(AUTH_GSSAPI_CREDS_VERS);
    init_cred.u32(1);
    init_cred.opaque(&[]);
    let mut init_args = XdrW::default();
    init_args.u32(2);
    init_args.opaque(&token);
    let rec = call(
        21,
        AUTH_GSSAPI_INIT,
        &init_cred.b,
        (FLAVOR_NONE, &[]),
        &init_args.b,
    );
    let ctx_for = |store| RpcCtx {
        store,
        acl: &acl,
        service_keys: &keys,
        expected_realm: TEST_REALM,
    };
    let out = handle_rpc(
        ctx_for(&store),
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 21);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
    let _ = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
    let _version = r.u32().unwrap();
    let handle = r.opaque().unwrap();
    assert_eq!((r.u32().unwrap(), r.u32().unwrap()), (0, 0));
    let out_tok = r.opaque().unwrap();
    let signed_isn = r.opaque().unwrap();
    if !out_tok.is_empty() {
        ctx.process_ap_rep(&out_tok, &session).unwrap();
    }
    let isn = ctx.unwrap(&signed_isn).unwrap();
    let seq = u32::from_be_bytes(isn[..4].try_into().unwrap());
    let mut data_cred = XdrW::default();
    data_cred.u32(AUTH_GSSAPI_CREDS_VERS);
    data_cred.u32(0);
    data_cred.opaque(&handle);
    let mut data_args = XdrW::default();
    data_args.opaque(b"not read");
    let verf = ctx.wrap_integ(&seq.wrapping_add(1).to_be_bytes()).unwrap();
    let rec = call(
        22,
        IPROP_GET_UPDATES,
        &data_cred.b,
        (FLAVOR_AUTH_GSSAPI, &verf),
        &data_args.b,
    );
    let out = handle_rpc(
        ctx_for(&store),
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 22);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_AUTH_GSSAPI);
    let reply_verf = r.opaque().unwrap();
    assert_eq!(
        ctx.unwrap(&reply_verf).unwrap(),
        seq.wrapping_add(2).to_be_bytes()
    );
    assert_eq!(r.u32().unwrap(), PROG_UNAVAIL, "not served with iprop off");
    store.write().unwrap().set_ulog(
        krb5_kdc::Ulog::memory(10).unwrap(),
        krb5_kdc::IpropRole::Primary,
    );
    let verf = ctx.wrap_integ(&seq.wrapping_add(3).to_be_bytes()).unwrap();
    let rec = call(
        23,
        IPROP_GET_UPDATES,
        &data_cred.b,
        (FLAVOR_AUTH_GSSAPI, &verf),
        &data_args.b,
    );
    let out = handle_rpc(
        ctx_for(&store),
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &rec,
        &peer(),
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 23);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_TOOWEAK, "dispatched with iprop on");
}

/// An AUTH_GSSAPI credential: version 2, `auth_msg`, the client handle.
fn agss_cred(auth_msg: bool, handle: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(AUTH_GSSAPI_CREDS_VERS);
    w.u32(u32::from(auth_msg));
    w.opaque(handle);
    w.b
}

/// A call with an AUTH_GSSAPI credential and verifier (AUTH_NONE when there is none).
fn agss_call(
    xid: u32,
    prog: u32,
    vers: u32,
    proc: u32,
    cred: &[u8],
    verf: Option<&[u8]>,
    args: &[u8],
) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(prog);
    w.u32(vers);
    w.u32(proc);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(cred);
    w.u32(if verf.is_some() {
        FLAVOR_AUTH_GSSAPI
    } else {
        FLAVOR_NONE
    });
    w.opaque(verf.unwrap_or_default());
    w.b.extend_from_slice(args);
    w.b
}

/// An `authgssapi_init_arg`: version 4 and the token.
fn init_arg(token: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(4);
    w.opaque(token);
    w.b
}

/// A reply's words.
fn reply_words(out: &[u8]) -> Vec<u32> {
    out.chunks(4)
        .map(|w| u32::from_be_bytes(w.try_into().unwrap()))
        .collect()
}

/// A connection's AUTH_GSSAPI record established by GSSAPI_INIT with the documented admin's
/// ticket for kadmin/admin, beside the client's side of it: the context, the handle, and the
/// sequence number the record expects one past (MIT's client `seq_num`).
struct Established {
    store: krb5_kdc::SharedDump,
    acl: Acl,
    keys: [ProtocolKey; 1],
    rc: krb5_protocol::ReplayCache,
    gss: Option<RpcsecGss>,
    agss: Option<Agss>,
    ctx: GssContext,
    handle: Vec<u8>,
    seq: u32,
}

impl Established {
    fn new(prog: u32, vers: u32) -> Self {
        let (store, acl, ctx, token, kadm_key, session) = admin_gss_token();
        let mut c = Self {
            store,
            acl,
            keys: [kadm_key],
            rc: krb5_protocol::ReplayCache::new(),
            gss: None,
            agss: None,
            ctx,
            handle: Vec::new(),
            seq: 0,
        };
        let rec = agss_call(
            1,
            prog,
            vers,
            AUTH_GSSAPI_INIT,
            &agss_cred(true, &[]),
            None,
            &init_arg(&token),
        );
        let out = c.send(&rec).unwrap();
        let mut r = XdrR::new(&out);
        let head: Vec<u32> = (0..4).map(|_| r.u32().unwrap()).collect();
        assert_eq!(head, [1, MSG_REPLY, MSG_ACCEPTED, FLAVOR_NONE]);
        assert_eq!(r.opaque().unwrap(), [] as [u8; 0]);
        assert_eq!(r.u32().unwrap(), SUCCESS);
        assert_eq!(r.u32().unwrap(), 4, "init_res version");
        c.handle = r.opaque().unwrap();
        assert_eq!(c.handle, 1u32.to_le_bytes(), "MIT's first key");
        assert_eq!(
            (r.u32().unwrap(), r.u32().unwrap()),
            (0, 0),
            "GSS_S_COMPLETE"
        );
        let tok = r.opaque().unwrap();
        let signed_isn = r.opaque().unwrap();
        if !tok.is_empty() {
            c.ctx.process_ap_rep(&tok, &session).unwrap();
        }
        let isn = c.ctx.unwrap(&signed_isn).unwrap();
        c.seq = u32::from_be_bytes(isn.as_slice().try_into().unwrap());
        c
    }

    fn send(&mut self, rec: &[u8]) -> Result<Vec<u8>, Error> {
        handle_rpc(
            RpcCtx {
                store: &self.store,
                acl: &self.acl,
                service_keys: &self.keys,
                expected_realm: krb5_kdc::testrealm::TEST_REALM,
            },
            b"hdl",
            &mut self.gss,
            &mut self.agss,
            &self.rc,
            rec,
            &peer(),
        )
    }

    fn cred(&self, auth_msg: bool) -> Vec<u8> {
        agss_cred(auth_msg, &self.handle)
    }

    /// A verifier: `seq` sealed without confidentiality (`auth_gssapi_seal_seq`).
    fn verf(&mut self, seq: u32) -> Vec<u8> {
        self.ctx.wrap_integ(&seq.to_be_bytes()).unwrap()
    }

    /// Arguments sealed after `seq` (`auth_gssapi_wrap_data`).
    fn sealed(&mut self, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut inner = seq.to_be_bytes().to_vec();
        inner.extend_from_slice(body);
        let mut w = XdrW::default();
        w.opaque(&self.ctx.wrap_with_rrc(&inner, 0).unwrap());
        w.b
    }

    /// A kadm5 call (not an auth message) under `seq`: its verifier and its sealed arguments.
    fn data(&mut self, xid: u32, vers: u32, proc: u32, seq: u32, body: &[u8]) -> Vec<u8> {
        let cred = self.cred(false);
        let verf = self.verf(seq);
        let args = self.sealed(seq, body);
        agss_call(xid, KADM_PROG, vers, proc, &cred, Some(&verf), &args)
    }

    /// An accepted reply to `xid` under the AUTH_GSSAPI verifier sealing `reply_seq`: its status,
    /// and what follows it.
    fn accepted(&mut self, out: &[u8], xid: u32, reply_seq: u32) -> (u32, Vec<u8>) {
        let mut r = XdrR::new(out);
        let head: Vec<u32> = (0..4).map(|_| r.u32().unwrap()).collect();
        assert_eq!(head, [xid, MSG_REPLY, MSG_ACCEPTED, FLAVOR_AUTH_GSSAPI]);
        let verf = r.opaque().unwrap();
        assert_eq!(self.ctx.unwrap(&verf).unwrap(), reply_seq.to_be_bytes());
        let stat = r.u32().unwrap();
        (stat, r.rest().to_vec())
    }

    /// A SUCCESS reply to `xid` under the verifier sealing `reply_seq`: its sealed body.
    fn success(&mut self, out: &[u8], xid: u32, reply_seq: u32) -> Vec<u8> {
        let (stat, rest) = self.accepted(out, xid, reply_seq);
        assert_eq!(stat, SUCCESS);
        XdrR::new(&rest).opaque().unwrap()
    }

    fn unseal(&mut self, sealed: &[u8]) -> Vec<u8> {
        self.ctx.unwrap(sealed).unwrap()
    }
}

/// A call's xid and procedure, its AUTH_GSSAPI credential and arguments, and the `auth_stat`.
type CredCase = (u32, u32, Vec<u8>, Vec<u8>, u32);

/// A call's xid, program, version and flavor, its credential, and the reply's words after the
/// xid and REPLY.
type FlavorCase = (u32, u32, u32, u32, Vec<u8>, Vec<u32>);

/// A call whose AUTH_GSSAPI credential does not check out is answered with MIT's `auth_stat`, as
/// MIT's kadmind answered each of these when settled live: an empty credential, one that does not
/// decode, or one of version 1 is AUTH_BADCRED; GSSAPI_INIT carrying a handle, or another call
/// carrying none, AUTH_FAILED; a handle that names no record AUTH_BADCRED; an init argument that
/// does not decode or is version 5 AUTH_BADCRED.
/// MIT `gssrpc__svcauth_gssapi` (`lib/rpc/svc_auth_gssapi.c:191-275`): the credential's whys.
/// MIT `gssrpc__svcauth_gssapi` (`lib/rpc/svc_auth_gssapi.c:308-342`): the init argument's.
#[test]
fn an_auth_gssapi_credential_that_does_not_check_out_is_answered_with_mits_why() {
    let (store, acl, _) = setup();
    let (mut gss, mut agss) = (None, None);
    let rc = krb5_protocol::ReplayCache::new();
    let unknown = [0xde, 0xad, 0xbe, 0xef];
    let bad_version = {
        let mut w = XdrW::default();
        w.u32(5);
        w.opaque(&[]);
        w.b
    };
    let cases: [CredCase; 10] = [
        (1, INIT, Vec::new(), Vec::new(), AUTH_BADCRED),
        (
            2,
            INIT,
            2u32.to_be_bytes().to_vec(),
            Vec::new(),
            AUTH_BADCRED,
        ),
        (
            3,
            INIT,
            {
                let mut w = XdrW::default();
                w.u32(1);
                w.u32(0);
                w.opaque(&[1, 0, 0, 0]);
                w.b
            },
            Vec::new(),
            AUTH_BADCRED,
        ),
        (
            4,
            AUTH_GSSAPI_INIT,
            agss_cred(true, &[1, 0, 0, 0]),
            init_arg(&[]),
            AUTH_FAILED,
        ),
        (5, INIT, agss_cred(false, &[]), Vec::new(), AUTH_FAILED),
        (
            6,
            INIT,
            agss_cred(false, &unknown),
            Vec::new(),
            AUTH_BADCRED,
        ),
        (
            7,
            AUTH_GSSAPI_CONTINUE_INIT,
            agss_cred(true, &[]),
            init_arg(&[]),
            AUTH_FAILED,
        ),
        (
            8,
            AUTH_GSSAPI_DESTROY,
            agss_cred(true, &unknown),
            Vec::new(),
            AUTH_BADCRED,
        ),
        (
            10,
            AUTH_GSSAPI_INIT,
            agss_cred(true, &[]),
            Vec::new(),
            AUTH_BADCRED,
        ),
        (
            11,
            AUTH_GSSAPI_INIT,
            agss_cred(true, &[]),
            bad_version,
            AUTH_BADCRED,
        ),
    ];
    for (xid, proc, cred, args, why) in cases {
        let mut w = XdrW::default();
        w.u32(xid);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(KADM_PROG);
        w.u32(KADM_VERS);
        w.u32(proc);
        w.u32(FLAVOR_AUTH_GSSAPI);
        w.opaque(&cred);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        w.b.extend_from_slice(&args);
        let out = handle_rpc(
            RpcCtx {
                store: &store,
                acl: &acl,
                service_keys: &[],
                expected_realm: "KERBER.TEST",
            },
            b"hdl",
            &mut gss,
            &mut agss,
            &rc,
            &w.b,
            &peer(),
        )
        .unwrap();
        assert_eq!(decode_denied(&out), (xid, why), "call {xid}");
    }
}

/// The flavor's authenticator runs before the program is looked up, and a program not served
/// is PROG_UNAVAIL or PROG_MISMATCH only for a call that passed it: AUTH_UNIX passes once its
/// credential decodes (a machine name of at most 255 bytes, at most 16 groups, all inside the
/// credential) and then meets kadm5's AUTH_TOOWEAK; AUTH_SHORT and an unknown flavor are
/// AUTH_REJECTEDCRED on any program; an AUTH_GSSAPI handle that names no record is AUTH_BADCRED on
/// any program; an RPCSEC_GSS credential without its context handle is AUTH_BADCRED. All as MIT's
/// kadmind answered them when settled live.
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:487-520`): authenticated, then the program.
/// MIT `gssrpc__authenticate` (`svc_auth.c:84-106`): the flavor picks the authenticator.
/// MIT `gssrpc__svcauth_unix` (`svc_auth_unix.c:55-126`): the Unix credential's bounds.
/// MIT `xdr_rpc_gss_cred` (`authgss_prot.c:72-90`): the context handle closes the credential.
#[test]
fn a_call_is_authenticated_by_its_flavor_before_its_program() {
    let (store, acl, _) = setup();
    let (mut gss, mut agss) = (None, None);
    let rc = krb5_protocol::ReplayCache::new();
    let unix = |name: usize, groups: u32| {
        let mut w = XdrW::default();
        w.u32(0);
        w.opaque(&vec![b'm'; name]);
        w.u32(0);
        w.u32(0);
        w.u32(groups);
        for g in 0..groups {
            w.u32(g);
        }
        w.b
    };
    let denied = |why: u32| vec![MSG_DENIED, REJECT_AUTH_ERROR, why];
    let cases: [FlavorCase; 15] = [
        (
            12,
            KADM_PROG,
            KADM_VERS,
            1,
            vec![0; 12],
            denied(AUTH_BADCRED),
        ),
        (
            13,
            KADM_PROG,
            KADM_VERS,
            1,
            unix(256, 0),
            denied(AUTH_BADCRED),
        ),
        (
            14,
            KADM_PROG,
            KADM_VERS,
            1,
            unix(4, 17),
            denied(AUTH_BADCRED),
        ),
        (
            15,
            KADM_PROG,
            KADM_VERS,
            1,
            unix(255, 16),
            denied(AUTH_TOOWEAK),
        ),
        (
            16,
            KADM_PROG,
            KADM_VERS,
            1,
            Vec::new(),
            denied(AUTH_BADCRED),
        ),
        (
            17,
            KADM_PROG,
            KADM_VERS,
            2,
            vec![0, 0, 0, 1],
            denied(AUTH_REJECTEDCRED),
        ),
        (
            18,
            KADM_PROG,
            KADM_VERS,
            99,
            vec![0, 0, 0, 1],
            denied(AUTH_REJECTEDCRED),
        ),
        (
            19,
            12345,
            1,
            99,
            vec![0, 0, 0, 1],
            denied(AUTH_REJECTEDCRED),
        ),
        (
            20,
            12345,
            1,
            FLAVOR_NONE,
            Vec::new(),
            vec![MSG_ACCEPTED, FLAVOR_NONE, 0, PROG_UNAVAIL],
        ),
        (
            21,
            KADM_PROG,
            3,
            FLAVOR_NONE,
            Vec::new(),
            vec![
                MSG_ACCEPTED,
                FLAVOR_NONE,
                0,
                PROG_MISMATCH,
                KADM_VERS,
                KADM_VERS,
            ],
        ),
        (
            22,
            12345,
            1,
            FLAVOR_AUTH_GSSAPI,
            agss_cred(false, &[1, 0, 0, 9]),
            denied(AUTH_BADCRED),
        ),
        (
            23,
            KADM_PROG,
            3,
            FLAVOR_AUTH_GSSAPI,
            agss_cred(false, &[1, 0, 0, 9]),
            denied(AUTH_BADCRED),
        ),
        (
            24,
            KADM_PROG,
            KADM_VERS,
            FLAVOR_GSS,
            {
                let mut w = XdrW::default();
                for v in [RPCSEC_GSS_VERS, RPG_INIT, 0, GSS_NONE] {
                    w.u32(v);
                }
                w.b
            },
            denied(AUTH_BADCRED),
        ),
        (
            25,
            KADM_PROG,
            KADM_VERS,
            FLAVOR_NONE,
            vec![b'c'; 400],
            denied(AUTH_TOOWEAK),
        ),
        (
            26,
            IPROP_PROG,
            IPROP_VERS,
            FLAVOR_NONE,
            Vec::new(),
            vec![MSG_ACCEPTED, FLAVOR_NONE, 0, PROG_UNAVAIL],
        ),
    ];
    for (xid, prog, vers, flavor, cred, want) in cases {
        let mut w = XdrW::default();
        w.u32(xid);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(prog);
        w.u32(vers);
        w.u32(13);
        w.u32(flavor);
        w.opaque(&cred);
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
        let out = handle_rpc(
            RpcCtx {
                store: &store,
                acl: &acl,
                service_keys: &[],
                expected_realm: "KERBER.TEST",
            },
            b"hdl",
            &mut gss,
            &mut agss,
            &rc,
            &w.b,
            &peer(),
        )
        .unwrap();
        let words = reply_words(&out);
        assert_eq!(&words[..2], [xid, MSG_REPLY], "call {xid}");
        assert_eq!(&words[2..], want.as_slice(), "call {xid}");
    }
}

/// A call whose credential or verifier is longer than `MAX_AUTH_BYTES` does not decode, and is not
/// answered, as MIT's (settled live: the connection answered the next call).
/// MIT `xdr_callmsg` (`lib/rpc/rpc_callmsg.c:119-158`): the credential's and verifier's bounds.
#[test]
fn a_credential_or_verifier_past_400_bytes_does_not_decode() {
    let (store, acl, _) = setup();
    let (mut gss, mut agss) = (None, None);
    let rc = krb5_protocol::ReplayCache::new();
    for (cred, verf) in [(401, 0), (0, 401)] {
        let mut w = XdrW::default();
        w.u32(30);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(KADM_PROG);
        w.u32(KADM_VERS);
        w.u32(INIT);
        w.u32(FLAVOR_NONE);
        w.opaque(&vec![b'c'; cred]);
        w.u32(FLAVOR_NONE);
        w.opaque(&vec![b'v'; verf]);
        let out = handle_rpc(
            RpcCtx {
                store: &store,
                acl: &acl,
                service_keys: &[],
                expected_realm: "KERBER.TEST",
            },
            b"hdl",
            &mut gss,
            &mut agss,
            &rc,
            &w.b,
            &peer(),
        );
        assert!(
            matches!(out, Err(Error::GarbageArgs)),
            "{cred}/{verf}: {out:?}"
        );
    }
}

/// A GSSAPI_INIT whose token does not establish a context is answered with an init_res under the
/// new record's handle (GSS_S_DEFECTIVE_TOKEN for a token that does not frame), and the record
/// stays unestablished: a call that is not an auth message is AUTH_REJECTEDCRED, a GSSAPI_DESTROY
/// AUTH_FAILED, and a CONTINUE_INIT under its handle with a good token establishes it. As MIT's
/// kadmind answered an unestablished record's handle when settled live.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:284-305`): an unestablished record's calls.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:453-467`): a failed accept's init_res.
#[test]
fn a_failed_gssapi_init_keeps_an_unestablished_record() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, _ctx, token, kadm_key, _session) = admin_gss_token();
    let keys = [kadm_key];
    let rc = krb5_protocol::ReplayCache::new();
    let (mut gss, mut agss) = (None, None);
    let mut send = |rec: &[u8]| {
        handle_rpc(
            RpcCtx {
                store: &store,
                acl: &acl,
                service_keys: &keys,
                expected_realm: TEST_REALM,
            },
            b"hdl",
            &mut gss,
            &mut agss,
            &rc,
            rec,
            &peer(),
        )
        .unwrap()
    };
    let out = send(&agss_call(
        40,
        KADM_PROG,
        KADM_VERS,
        AUTH_GSSAPI_INIT,
        &agss_cred(true, &[]),
        None,
        &init_arg(&[0x60, 0x00]),
    ));
    let words = reply_words(&out);
    // xid, REPLY, ACCEPTED, AUTH_NONE verifier, SUCCESS; version 4, a 4-byte handle 1, the major
    // and minor, no token, no signed sequence number.
    assert_eq!(
        words,
        [
            40,
            MSG_REPLY,
            MSG_ACCEPTED,
            FLAVOR_NONE,
            0,
            SUCCESS,
            4,
            4,
            u32::from_be_bytes(1u32.to_le_bytes()),
            GSS_S_DEFECTIVE_TOKEN,
            0,
            0,
            0
        ]
    );
    let handle = 1u32.to_le_bytes();
    let out = send(&agss_call(
        41,
        KADM_PROG,
        KADM_VERS,
        INIT,
        &agss_cred(false, &handle),
        None,
        &[],
    ));
    assert_eq!(decode_denied(&out), (41, AUTH_REJECTEDCRED));
    let out = send(&agss_call(
        42,
        KADM_PROG,
        KADM_VERS,
        AUTH_GSSAPI_DESTROY,
        &agss_cred(true, &handle),
        None,
        &[],
    ));
    assert_eq!(decode_denied(&out), (42, AUTH_FAILED));
    let out = send(&agss_call(
        43,
        KADM_PROG,
        KADM_VERS,
        AUTH_GSSAPI_CONTINUE_INIT,
        &agss_cred(true, &handle),
        None,
        &init_arg(&token),
    ));
    let words = reply_words(&out);
    assert_eq!(
        &words[..9],
        [
            43,
            MSG_REPLY,
            MSG_ACCEPTED,
            FLAVOR_NONE,
            0,
            SUCCESS,
            4,
            4,
            words[8]
        ]
    );
    assert_eq!((words[9], words[10]), (0, 0), "established");
}

/// An established record's verifier must unseal to the next sequence number: one that does not
/// unseal is AUTH_BADVERF, one of a number already used AUTH_REJECTEDVERF, and neither moves the
/// record, so the next call under the next number is answered. An auth message to a kadm5
/// procedure is AUTH_FAILED after its verifier moved the record two, as MIT's kadmind answered
/// MIT's kadmin, whose next call then needed two refreshes, when settled live.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:516-556`): the verifier and the sequence.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:627-632`): another auth message is AUTH_FAILED.
#[test]
fn an_established_record_answers_a_verifier_that_does_not_check_out() {
    let mut c = Established::new(KADM_PROG, KADM_VERS);
    let s = c.seq;
    let rec = c.data(
        20,
        KADM_VERS,
        INIT,
        s.wrapping_add(1),
        &API_V2.to_be_bytes(),
    );
    let out = c.send(&rec).unwrap();
    let body = c.success(&out, 20, s.wrapping_add(2));
    assert_eq!(&c.unseal(&body)[..4], s.wrapping_add(2).to_be_bytes());
    let cred = c.cred(false);
    let mut bad = c.verf(s.wrapping_add(3));
    *bad.last_mut().unwrap() ^= 1;
    let out = c
        .send(&agss_call(
            21,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            &cred,
            Some(&bad),
            &[],
        ))
        .unwrap();
    assert_eq!(decode_denied(&out), (21, AUTH_BADVERF));
    let stale = c.verf(s.wrapping_add(1));
    let out = c
        .send(&agss_call(
            22,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            &cred,
            Some(&stale),
            &[],
        ))
        .unwrap();
    assert_eq!(decode_denied(&out), (22, AUTH_REJECTEDVERF));
    let rec = c.data(
        23,
        KADM_VERS,
        GET_PRIVS,
        s.wrapping_add(3),
        &API_V2.to_be_bytes(),
    );
    let out = c.send(&rec).unwrap();
    c.success(&out, 23, s.wrapping_add(4));
    let verf = c.verf(s.wrapping_add(5));
    let auth_msg = c.cred(true);
    let out = c
        .send(&agss_call(
            24,
            KADM_PROG,
            KADM_VERS,
            INIT,
            &auth_msg,
            Some(&verf),
            &[],
        ))
        .unwrap();
    assert_eq!(decode_denied(&out), (24, AUTH_FAILED));
    let verf = c.verf(s.wrapping_add(5));
    let out = c
        .send(&agss_call(
            25,
            KADM_PROG,
            KADM_VERS,
            GET_PRIVS,
            &cred,
            Some(&verf),
            &[],
        ))
        .unwrap();
    assert_eq!(
        decode_denied(&out),
        (25, AUTH_REJECTEDVERF),
        "the record moved"
    );
    let rec = c.data(
        26,
        KADM_VERS,
        GET_PRIVS,
        s.wrapping_add(7),
        &API_V2.to_be_bytes(),
    );
    let out = c.send(&rec).unwrap();
    c.success(&out, 26, s.wrapping_add(8));
}

/// GSSAPI_MSG to an established record: arguments that do not unseal are AUTH_BADCRED, and a
/// context token that does is AUTH_FAILED, as MIT's `gss_process_context_token` fails for an
/// RFC 4121 context.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:583-614`): GSSAPI_MSG's arguments and token.
#[test]
fn a_gssapi_msg_is_refused() {
    let mut c = Established::new(KADM_PROG, KADM_VERS);
    let s = c.seq;
    let cred = c.cred(true);
    let verf = c.verf(s.wrapping_add(1));
    let out = c
        .send(&agss_call(
            30,
            KADM_PROG,
            KADM_VERS,
            AUTH_GSSAPI_MSG,
            &cred,
            Some(&verf),
            &init_arg(b"tok"),
        ))
        .unwrap();
    assert_eq!(decode_denied(&out), (30, AUTH_BADCRED));
    let verf = c.verf(s.wrapping_add(3));
    let args = c.sealed(s.wrapping_add(3), &init_arg(b"tok"));
    let out = c
        .send(&agss_call(
            31,
            KADM_PROG,
            KADM_VERS,
            AUTH_GSSAPI_MSG,
            &cred,
            Some(&verf),
            &args,
        ))
        .unwrap();
    assert_eq!(decode_denied(&out), (31, AUTH_FAILED));
}

/// An authentic AUTH_GSSAPI call is answered under its reply verifier whatever the outcome
/// (`svcerr_progvers`, `svcerr_noproc`, `svcerr_decode` answer under the call's `xp_verf`):
/// another kadm5 version is PROG_MISMATCH; procedure 17 or one past CREATE_ALIAS is PROC_UNAVAIL
/// before its arguments are read; arguments that do not unseal, or unseal after another sequence
/// number, are GARBAGE_ARGS; NULLPROC is answered with the reply's sequence number sealed.
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:495-520`): the program and version, under the verifier.
/// MIT `kadm_1` (`kadm_rpc_svc.c:91-261`): NULLPROC, the procedures served, the arguments.
#[test]
fn an_authentic_call_is_answered_under_its_verifier() {
    let mut c = Established::new(KADM_PROG, KADM_VERS);
    let mut s = c.seq;
    let cred = c.cred(false);
    let mut next = |c: &mut Established, xid: u32, vers: u32, proc: u32, args: &[u8]| {
        let verf = c.verf(s.wrapping_add(1));
        let out = c
            .send(&agss_call(
                xid,
                KADM_PROG,
                vers,
                proc,
                &cred,
                Some(&verf),
                args,
            ))
            .unwrap();
        let got = c.accepted(&out, xid, s.wrapping_add(2));
        s = s.wrapping_add(2);
        got
    };
    let (stat, rest) = next(&mut c, 50, 3, INIT, &[]);
    assert_eq!(
        (stat, reply_words(&rest)),
        (PROG_MISMATCH, vec![KADM_VERS, KADM_VERS])
    );
    for proc in [SETV4KEY_PRINCIPAL, CREATE_ALIAS + 1] {
        let (stat, rest) = next(&mut c, 51, KADM_VERS, proc, b"not sealed");
        assert_eq!((stat, rest.len()), (PROC_UNAVAIL, 0), "procedure {proc}");
    }
    let (stat, _) = next(&mut c, 52, KADM_VERS, GET_PRIVS, &[0, 0, 0, 4, 1, 2, 3, 4]);
    assert_eq!(stat, GARBAGE_ARGS);
    let other = c.sealed(9, &API_V2.to_be_bytes());
    let (stat, _) = next(&mut c, 53, KADM_VERS, GET_PRIVS, &other);
    assert_eq!(stat, GARBAGE_ARGS, "sealed after another sequence number");
    let (stat, rest) = next(&mut c, 54, KADM_VERS, 0, &[]);
    assert_eq!(stat, SUCCESS);
    let sealed = XdrR::new(&rest).opaque().unwrap();
    assert_eq!(c.unseal(&sealed), s.to_be_bytes());
}

/// One AUTH_GSSAPI or RPCSEC_GSS call through `handle_rpc` for the ticket's service, from `peer`.
fn send_as(
    t: &AdminTicket,
    rc: &krb5_protocol::ReplayCache,
    agss: &mut Option<Agss>,
    gss: &mut Option<RpcsecGss>,
    rec: &[u8],
    peer: &RpcPeer,
) -> Vec<u8> {
    handle_rpc(
        RpcCtx {
            store: &t.store,
            acl: &t.acl,
            service_keys: std::slice::from_ref(&t.service_key),
            expected_realm: krb5_kdc::testrealm::TEST_REALM,
        },
        b"hdl",
        gss,
        agss,
        rc,
        rec,
        peer,
    )
    .unwrap()
}

/// A GSSAPI_INIT of `version` carrying `token`.
fn init_call(xid: u32, version: u32, token: &[u8]) -> Vec<u8> {
    let mut args = XdrW::default();
    args.u32(version);
    args.opaque(token);
    agss_call(
        xid,
        KADM_PROG,
        KADM_VERS,
        AUTH_GSSAPI_INIT,
        &agss_cred(true, &[]),
        None,
        &args.b,
    )
}

/// An init_res's GSS major status, after its version and handle.
fn init_res_major(out: &[u8]) -> u32 {
    let mut r = XdrR::new(out);
    let head: Vec<u32> = (0..4).map(|_| r.u32().unwrap()).collect();
    assert_eq!(&head[1..], [MSG_REPLY, MSG_ACCEPTED, FLAVOR_NONE]);
    r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
    r.u32().unwrap();
    r.opaque().unwrap();
    r.u32().unwrap()
}

/// A connection from `remote` to 127.0.0.1's kadmind port.
fn peer_from(remote: [u8; 4]) -> RpcPeer {
    let local = std::net::SocketAddr::from(([127, 0, 0, 1], 749));
    RpcPeer::new(
        Some(std::net::SocketAddr::from((remote, 50_000))),
        Some(local),
    )
}

/// An IPv4 channel binding from `initiator` to `acceptor`, as MIT's AUTH_GSSAPI client sends it.
fn inet_bindings(initiator: [u8; 4], acceptor: [u8; 4]) -> krb5_gss::ChannelBindings {
    krb5_gss::ChannelBindings {
        initiator_addrtype: krb5_gss::GSS_C_AF_INET,
        initiator_address: initiator.to_vec(),
        acceptor_addrtype: krb5_gss::GSS_C_AF_INET,
        acceptor_address: acceptor.to_vec(),
        application_data: Vec::new(),
    }
}

/// An established record lives until its ticket's end with the clock skew's grace; past that it
/// is dropped before the call is looked at, so its handle names no record (AUTH_BADCRED,
/// "invalid client handle received"), as MIT's kadmind answered a one-minute ticket's second call
/// at 400 s when settled live.
/// MIT `clean_client` (`svc_auth_gssapi.c:894-918`): expired records go first.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:474-478`): an established record's expiry.
#[test]
fn an_established_record_expires_at_its_tickets_end_with_the_skew() {
    let log = KlogFile::new("expiry");
    let mut c = Established::new(KADM_PROG, KADM_VERS);
    let st = c.agss.as_ref().unwrap();
    let end = st.ctx.as_ref().unwrap().endtime().unwrap();
    assert_eq!(st.expires, end + 300);
    let s = c.seq;
    let rec = c.data(
        60,
        KADM_VERS,
        GET_PRIVS,
        s.wrapping_add(1),
        &API_V2.to_be_bytes(),
    );
    let out = c.send(&rec).unwrap();
    c.success(&out, 60, s.wrapping_add(2));
    c.agss.as_mut().unwrap().expires = krb5_types::KerberosTime::now().unix_seconds() - 1;
    let rec = c.data(
        61,
        KADM_VERS,
        GET_PRIVS,
        s.wrapping_add(3),
        &API_V2.to_be_bytes(),
    );
    let out = c.send(&rec).unwrap();
    assert_eq!(decode_denied(&out), (61, AUTH_BADCRED));
    assert!(c.agss.is_none(), "the record is gone");
    assert!(
        log.text()
            .contains("Miscellaneous RPC error: 127.0.0.1, invalid client handle received"),
        "{}",
        log.text()
    );
}

/// A record whose GSSAPI_INIT did not complete lives 15 minutes; past that a CONTINUE_INIT under
/// its handle finds no record.
/// MIT `create_client` (`svc_auth_gssapi.c:710-712`): `INITIATION_TIMEOUT`.
#[test]
fn an_unfinished_record_expires_after_fifteen_minutes() {
    let t = admin_ticket(&krb5_kdc::principals::kadmin_admin(), None);
    let rc = krb5_protocol::ReplayCache::new();
    let (mut agss, mut gss) = (None, None);
    let before = krb5_types::KerberosTime::now().unix_seconds();
    let out = send_as(
        &t,
        &rc,
        &mut agss,
        &mut gss,
        &init_call(70, 4, &[0x60, 0]),
        &peer(),
    );
    assert_eq!(init_res_major(&out), GSS_S_DEFECTIVE_TOKEN);
    let expires = agss.as_ref().unwrap().expires;
    assert!(
        (before + 900..=before + 901).contains(&expires),
        "{expires} vs {before}"
    );
    agss.as_mut().unwrap().expires = before - 1;
    let (_ctx, token) = t.token(None);
    let mut args = XdrW::default();
    args.u32(4);
    args.opaque(&token);
    let rec = agss_call(
        71,
        KADM_PROG,
        KADM_VERS,
        AUTH_GSSAPI_CONTINUE_INIT,
        &agss_cred(true, &1u32.to_le_bytes()),
        None,
        &args.b,
    );
    let out = send_as(&t, &rc, &mut agss, &mut gss, &rec, &peer());
    assert_eq!(decode_denied(&out), (71, AUTH_BADCRED));
}

/// GSSAPI_INIT versions 3 and 4 bind the context to the caller's and the connection's IPv4
/// addresses: bindings that name another caller are GSS_S_BAD_BINDINGS (MIT's "Incorrect channel
/// bindings were supplied", minor 0), matching ones or none establish it, and versions 1 and 2
/// bind nothing; as MIT's kadmind refused MIT's kadmin through a relay when settled live.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:348-371`): the bindings for versions 3 and 4.
/// MIT `process_checksum` (`accept_sec_context.c:532-541`): a non-zero binding must match.
#[test]
fn version_3_and_4_inits_bind_the_connection_addresses() {
    let log = KlogFile::new("bindings");
    let t = admin_ticket(&krb5_kdc::principals::kadmin_admin(), None);
    let rc = krb5_protocol::ReplayCache::new();
    let (mut agss, mut gss) = (None, None);
    let other = inet_bindings([10, 0, 0, 1], [127, 0, 0, 1]);
    let same = inet_bindings([127, 0, 0, 1], [127, 0, 0, 1]);
    for (xid, version, cb, major) in [
        (80, 4, Some(&other), GSS_S_BAD_BINDINGS),
        (81, 3, Some(&other), GSS_S_BAD_BINDINGS),
        (82, 4, Some(&same), 0),
        (83, 4, None, 0),
        (84, 2, Some(&other), 0),
    ] {
        let (_ctx, token) = t.token(cb);
        let out = send_as(
            &t,
            &rc,
            &mut agss,
            &mut gss,
            &init_call(xid, version, &token),
            &peer(),
        );
        assert_eq!(init_res_major(&out), major, "call {xid}");
        let established = agss.as_ref().is_some_and(|st| st.ctx.is_some());
        assert_eq!(established, major == 0, "call {xid}");
    }
    let text = log.text();
    assert!(text.contains("Authentication attempt failed: 127.0.0.1, GSS-API error strings are:"));
    assert!(
        text.contains("    Incorrect channel bindings were supplied"),
        "{text}"
    );
    assert!(text.contains("    Unknown code 0"), "{text}");
}

/// Without the connection's own address a version 3 or 4 GSSAPI_INIT cannot be bound and is
/// AUTH_FAILED ("cannot get local address"); versions 1 and 2 need none.
/// MIT `gssrpc__svcauth_gssapi` (`svc_auth_gssapi.c:356-365`): `xp_laddrlen` is 0.
#[test]
fn an_init_without_the_local_address_is_auth_failed() {
    let log = KlogFile::new("nolocal");
    let t = admin_ticket(&krb5_kdc::principals::kadmin_admin(), None);
    let rc = krb5_protocol::ReplayCache::new();
    let (mut agss, mut gss) = (None, None);
    let nowhere = RpcPeer::new(
        Some(std::net::SocketAddr::from(([127, 0, 0, 1], 50_000))),
        None,
    );
    let (_ctx, token) = t.token(None);
    let out = send_as(
        &t,
        &rc,
        &mut agss,
        &mut gss,
        &init_call(90, 4, &token),
        &nowhere,
    );
    assert_eq!(decode_denied(&out), (90, AUTH_FAILED));
    assert!(
        log.text()
            .contains("Miscellaneous RPC error: 127.0.0.1, cannot get local address")
    );
    let out = send_as(
        &t,
        &rc,
        &mut agss,
        &mut gss,
        &init_call(91, 2, &token),
        &nowhere,
    );
    assert_eq!(init_res_major(&out), 0);
}

/// A version 3 or 4 GSSAPI_INIT's binding names the caller, and a ticket with addresses must
/// hold it: one from another address is GSS_S_FAILURE ("Incorrect net address"), one from the
/// ticket's address establishes; a version 2 init names no caller, so the ticket's addresses are
/// not looked at.
/// MIT `kg_accept_krb5` (`accept_sec_context.c:781-790`): the binding's initiator address.
/// MIT `rd_req_decoded_opt` (`rd_req_dec.c:536-540`): the ticket's addresses must hold it.
#[test]
fn an_addressful_ticket_must_name_the_caller() {
    let log = KlogFile::new("caddr");
    let ticket_addr = krb5_types::HostAddress {
        addr_type: krb5_types::HostAddress::ADDRTYPE_INET,
        address: vec![10, 0, 0, 9].into(),
    };
    let t = admin_ticket(
        &krb5_kdc::principals::kadmin_admin(),
        Some(vec![ticket_addr]),
    );
    let rc = krb5_protocol::ReplayCache::new();
    let (mut agss, mut gss) = (None, None);
    for (xid, version, remote, major) in [
        (100, 4, [127, 0, 0, 1], GSS_S_FAILURE),
        (101, 4, [10, 0, 0, 9], 0),
        (102, 2, [127, 0, 0, 1], 0),
    ] {
        let (_ctx, token) = t.token(None);
        let rec = init_call(xid, version, &token);
        let out = send_as(&t, &rc, &mut agss, &mut gss, &rec, &peer_from(remote));
        assert_eq!(init_res_major(&out), major, "call {xid}");
    }
    assert!(
        log.text().contains("Incorrect net address"),
        "{}",
        log.text()
    );
}

/// An RPCSEC_GSS context for a service kadm5 does not take is refused with MIT's lines: the
/// service principal, then the flavor; a procedure kadm5 does not serve is PROC_UNAVAIL with
/// MIT's line, under the call's verifier.
/// MIT `check_rpcsec_auth` (`kadm_rpc_svc.c:333-337`): `bad service principal`.
/// MIT `kadm_1` (`kadm_rpc_svc.c:80-88`): `Authentication attempt failed`, then AUTH_TOOWEAK.
/// MIT `kadm_1` (`kadm_rpc_svc.c:251-255`): `Invalid KADM5 procedure number`.
#[test]
fn a_refused_rpcsec_gss_call_writes_mits_lines() {
    use krb5_kdc::testrealm::{TEST_REALM, documented_kiprop};

    let log = KlogFile::new("rpcsec");
    let call = |t: &AdminTicket, procs: &[(u32, u32)]| -> Vec<Vec<u8>> {
        let rc = krb5_protocol::ReplayCache::new();
        let (mut agss, mut gss) = (None, None);
        let (mut ctx, token) = t.token(None);
        let mut arg = XdrW::default();
        arg.opaque(&token);
        let init = rpcsec_call(
            RpcCallId {
                xid: 1,
                prog: KADM_PROG,
                vers: KADM_VERS,
                proc: 0,
            },
            &rpcsec_cred(RPG_INIT, 0, GSS_NONE, &[]),
            FLAVOR_NONE,
            &[],
            &arg.b,
        );
        let out = send_as(t, &rc, &mut agss, &mut gss, &init, &peer());
        let mut r = XdrR::new(&out);
        let _ = (r.u32(), r.u32(), r.u32(), r.u32(), r.opaque(), r.u32());
        let handle = r.opaque().unwrap();
        let _ = (r.u32(), r.u32(), r.u32());
        let out_tok = r.opaque().unwrap();
        if !out_tok.is_empty() {
            ctx.process_ap_rep(&out_tok, &t.session).unwrap();
        }
        ctx.allow_rpcsec_init_window();
        procs
            .iter()
            .map(|&(xid, proc)| {
                let cred = rpcsec_cred(RPG_DATA, xid, GSS_NONE, &handle);
                let mut header = XdrW::default();
                for w in [
                    xid,
                    MSG_CALL,
                    RPC_VERSION,
                    KADM_PROG,
                    KADM_VERS,
                    proc,
                    FLAVOR_GSS,
                ] {
                    header.u32(w);
                }
                header.opaque(&cred);
                let mic = ctx.get_mic(&header.b).unwrap();
                let rec = rpcsec_call(
                    RpcCallId {
                        xid,
                        prog: KADM_PROG,
                        vers: KADM_VERS,
                        proc,
                    },
                    &cred,
                    FLAVOR_GSS,
                    &mic,
                    &API_V2.to_be_bytes(),
                );
                send_as(t, &rc, &mut agss, &mut gss, &rec, &peer())
            })
            .collect()
    };
    let kiprop = admin_ticket(&documented_kiprop(), None);
    let outs = call(&kiprop, &[(2, GET_PRIVS)]);
    assert_eq!(decode_denied(&outs[0]), (2, AUTH_TOOWEAK));
    let admin = admin_ticket(&krb5_kdc::principals::kadmin_admin(), None);
    let outs = call(&admin, &[(3, SETV4KEY_PRINCIPAL), (4, CREATE_ALIAS + 1)]);
    for (out, xid) in outs.iter().zip([3, 4]) {
        let w = reply_words(out);
        assert_eq!(&w[..4], [xid, MSG_REPLY, MSG_ACCEPTED, FLAVOR_GSS]);
        assert_eq!(*w.last().unwrap(), PROC_UNAVAIL, "call {xid}");
    }
    let text = log.text();
    for line in [
        format!(
            "bad service principal kiprop/{}@{TEST_REALM}",
            krb5_kdc::testrealm::TEST_HOST
        ),
        "Authentication attempt failed: 127.0.0.1, RPC authentication flavor 6".to_owned(),
        "Invalid KADM5 procedure number: 127.0.0.1, 17".to_owned(),
        "Invalid KADM5 procedure number: 127.0.0.1, 28".to_owned(),
    ] {
        assert!(text.contains(&line), "{line} not in {text}");
    }
}
