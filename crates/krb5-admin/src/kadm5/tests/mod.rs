//! In-src kadm5 tests, regrouped by family. Private-bound: they reach
//! the sibling modules' `pub(super)` items, nothing wider.

use krb5_crypto::ProtocolKey;
use krb5_gss::GssContext;
use krb5_kdc::{Acl, KDB_LOCKDOWN_KEYS, SharedDump as SharedStore, TL_LAST_PWD_CHANGE, TlData};
use krb5_types::PrincipalName;

use super::{
    auth::*, codes::*, dispatch::*, glob::*, iprop::*, log::*, policy::*, principal::*, rpc::*,
    xdr::*,
};
use crate::{AdminSession, Error};

fn rpc_call(xid: u32, prog: u32, vers: u32, proc: u32, flavor: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(prog);
    w.u32(vers);
    w.u32(proc);
    w.u32(flavor);
    w.opaque(&[]);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.b
}

fn rpcsec_cred(proc: u32, seq: u32, svc: u32, handle: &[u8]) -> Vec<u8> {
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(proc);
    cred.u32(seq);
    cred.u32(svc);
    cred.opaque(handle);
    cred.b
}

fn rpcsec_call(id: RpcCallId, cred: &[u8], verf_flavor: u32, verf: &[u8], args: &[u8]) -> Vec<u8> {
    let RpcCallId {
        xid,
        prog,
        vers,
        proc,
    } = id;
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(prog);
    w.u32(vers);
    w.u32(proc);
    w.u32(FLAVOR_GSS);
    w.opaque(cred);
    w.u32(verf_flavor);
    w.opaque(verf);
    w.b.extend_from_slice(args);
    w.b
}

fn decode_denied(out: &[u8]) -> (u32, u32) {
    let mut r = XdrR::new(out);
    let xid = r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    (xid, r.u32().unwrap())
}

#[allow(clippy::type_complexity)]
fn admin_gss_token() -> (
    krb5_kdc::SharedDump,
    Acl,
    GssContext,
    Vec<u8>,
    ProtocolKey,
    ProtocolKey,
) {
    use krb5_crypto::EncryptionType;
    use krb5_kdc::testrealm::TEST_REALM;

    use krb5_kdc::principals::kadmin_admin;

    use krb5_protocol::{as_req_sname, pa_enc_timestamp};
    use krb5_types::ascii;

    let (store, acl, _) = setup();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let kadm = kadmin_admin();
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
    let (ctx, token) = GssContext::init_sec_context(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &ascii(TEST_REALM),
        &admin,
        true,
        None,
        None,
    )
    .unwrap();
    (store, acl, ctx, token, kadm_key, as_out.session_key)
}

fn admin_rpcsec_init() -> (
    krb5_kdc::SharedDump,
    Acl,
    GssContext,
    Vec<u8>,
    Option<RpcsecGss>,
) {
    admin_rpcsec_init_svc(GSS_PRIVACY)
}

fn admin_rpcsec_init_svc(
    svc: u32,
) -> (
    krb5_kdc::SharedDump,
    Acl,
    GssContext,
    Vec<u8>,
    Option<RpcsecGss>,
) {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, token, kadm_key, session) = admin_gss_token();
    let cred = rpcsec_cred(RPG_INIT, 0, svc, &[]);
    let mut arg = XdrW::default();
    arg.opaque(&token);
    let rec = rpcsec_call(
        RpcCallId {
            xid: 1,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc: 0,
        },
        &cred,
        FLAVOR_NONE,
        &[],
        &arg.b,
    );
    let mut gss = None;
    let mut agss = None;
    let keys = [kadm_key];
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &keys,
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 1);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_GSS);
    let verf = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
    let handle = r.opaque().unwrap();
    let _major = r.u32().unwrap();
    let _minor = r.u32().unwrap();
    let window = r.u32().unwrap();
    let out_tok = r.opaque().unwrap();
    if !out_tok.is_empty() {
        ctx.process_ap_rep(&out_tok, &session).unwrap();
    }
    ctx.allow_rpcsec_init_window();
    ctx.verify_mic(&window.to_be_bytes(), &verf).unwrap();
    assert!(gss.is_some());
    (store, acl, ctx, handle, gss)
}

fn rpcsec_data_rec(
    ctx: &mut GssContext,
    id: RpcCallId,
    seq: u32,
    handle: &[u8],
    args: &[u8],
    wrap: bool,
) -> Vec<u8> {
    let RpcCallId {
        xid,
        prog,
        vers,
        proc,
    } = id;
    let cred = rpcsec_cred(RPG_DATA, seq, GSS_PRIVACY, handle);
    let mut header = XdrW::default();
    header.u32(xid);
    header.u32(MSG_CALL);
    header.u32(RPC_VERSION);
    header.u32(prog);
    header.u32(vers);
    header.u32(proc);
    header.u32(FLAVOR_GSS);
    header.opaque(&cred);
    let mic = ctx.get_mic(&header.b).unwrap();
    let mut arg = XdrW::default();
    if wrap {
        let mut inner = Vec::with_capacity(4 + args.len());
        inner.extend_from_slice(&seq.to_be_bytes());
        inner.extend_from_slice(args);
        let w = ctx.wrap_with_rrc(&inner, 0).unwrap();
        arg.opaque(&w);
    } else {
        arg.b.extend_from_slice(args);
    }
    rpcsec_call(
        RpcCallId {
            xid,
            prog,
            vers,
            proc,
        },
        &cred,
        FLAVOR_GSS,
        &mic,
        &arg.b,
    )
}

fn rpcsec_integ_rec(
    ctx: &mut GssContext,
    xid: u32,
    proc: u32,
    seq: u32,
    handle: &[u8],
    args: &[u8],
    tamper: bool,
) -> Vec<u8> {
    let cred = rpcsec_cred(RPG_DATA, seq, GSS_INTEGRITY, handle);
    let mut header = XdrW::default();
    header.u32(xid);
    header.u32(MSG_CALL);
    header.u32(RPC_VERSION);
    header.u32(KADM_PROG);
    header.u32(KADM_VERS);
    header.u32(proc);
    header.u32(FLAVOR_GSS);
    header.opaque(&cred);
    let mic = ctx.get_mic(&header.b).unwrap();
    let mut databody = Vec::with_capacity(4 + args.len());
    databody.extend_from_slice(&seq.to_be_bytes());
    databody.extend_from_slice(args);
    let mut checksum = ctx.get_mic(&databody).unwrap();
    if tamper {
        *checksum.last_mut().unwrap() ^= 0xFF;
    }
    let mut arg = XdrW::default();
    arg.opaque(&databody);
    arg.opaque(&checksum);
    rpcsec_call(
        RpcCallId {
            xid,
            prog: KADM_PROG,
            vers: KADM_VERS,
            proc,
        },
        &cred,
        FLAVOR_GSS,
        &mic,
        &arg.b,
    )
}

fn list_args() -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("*"));
    w.b
}

fn getprinc_args(name: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(u32::MAX);
    w.b
}

fn modify_args(name: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(3600);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.u32(KADM5_ATTRIBUTES);
    w.b
}

fn setstr_args(name: &str, key: &str, value: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.nullstring(Some(key));
    w.nullstring(Some(value));
    w.b
}

fn cpw_dispatch(
    store: &krb5_kdc::SharedDump,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
) -> Vec<u8> {
    dispatch_kadm5_ticket(store, acl, actor, proc, args, true, true).unwrap()
}

fn setup() -> (krb5_kdc::SharedDump, Acl, String) {
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    (krb5_kdc::shared_dump(store), acl, actor)
}

fn encode_named(name: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.b
}

fn ret_code(b: &[u8]) -> u32 {
    let mut r = XdrR::new(b);
    let _ = r.u32().unwrap();
    r.u32().unwrap()
}

fn gprinc_key_kvnos(out: &[u8]) -> (u32, Vec<u32>) {
    let mut r = XdrR::new(out);
    r.u32().unwrap();
    r.u32().unwrap();
    let _ = r.nullstring().unwrap();
    for _ in 0..4 {
        r.u32().unwrap();
    }
    assert_eq!(r.u32().unwrap(), 0);
    let _ = r.nullstring().unwrap();
    for _ in 0..4 {
        r.u32().unwrap();
    }
    let _ = r.nullstring().unwrap();
    for _ in 0..5 {
        r.u32().unwrap();
    }
    let n_key = r.u32().unwrap();
    let n_tl = r.u32().unwrap();
    let tl_null = r.u32().unwrap();
    if tl_null == 0 {
        loop {
            let more = r.u32().unwrap();
            if more == 0 {
                break;
            }
            r.u32().unwrap();
            let _ = r.opaque().unwrap();
        }
    } else {
        assert_eq!(n_tl, 0);
    }
    let n = r.u32().unwrap();
    assert_eq!(n, n_key);
    let mut kvnos = Vec::new();
    for _ in 0..n {
        let ver = r.u32().unwrap();
        kvnos.push(r.u32().unwrap());
        r.u32().unwrap();
        if ver > 1 {
            r.u32().unwrap();
        }
    }
    (n_key, kvnos)
}

fn gprinc_pwd_and_mod(out: &[u8]) -> (u32, u32) {
    let mut r = XdrR::new(out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    let _ = r.nullstring().unwrap();
    let _ = r.u32().unwrap();
    let last_pwd = r.u32().unwrap();
    let _ = r.u32().unwrap();
    let _ = r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), 0);
    let _ = r.nullstring().unwrap();
    let mod_date = r.u32().unwrap();
    (last_pwd, mod_date)
}

fn create_rec(name: &str, pass: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(3600);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.u32(KADM5_PRINCIPAL);
    w.nullstring(Some(pass));
    w.b
}

/// `create_rec` with `KADM5_POLICY` set and the policy string filled.
fn create_rec_policy(name: &str, pass: &str, policy: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    for v in [0, 0, 0, 3600, 1, 0, 0, 1, 1] {
        w.u32(v);
    }
    w.nullstring(Some(policy));
    // aux, max_rlife, last_success, last_failed, fail_auth_count, n_key,
    // n_tl, tl_data NULL, empty key_data array.
    for v in [0, 0, 0, 0, 0, 0, 0, 1, 0] {
        w.u32(v);
    }
    w.u32(KADM5_PRINCIPAL | KADM5_POLICY);
    w.nullstring(Some(pass));
    w.b
}

fn stub_unk_before_acl(proc: u32, args: &[u8], not_auth: u32) {
    let (store, _acl, _actor) = setup();
    let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
    let out = dispatch_kadm5(&store, &none, "user@KERBER.TEST", proc, args)
        .unwrap_or_else(|e| panic!("proc {proc} dispatch {e:?}"));
    assert_eq!(ret_code(&out), KADM5_UNK_PRINC, "proc {proc}");
    assert_ne!(
        ret_code(&out),
        not_auth,
        "proc {proc} must not be ACL-first"
    );
}

fn modify_rec(name: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(3600);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.u32(KADM5_ATTRIBUTES);
    w.b
}

fn extract_args(name: &str, kvno: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(kvno);
    w.b
}

fn purgekeys_args(name: &str, keepkvno: i32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(u32::from_be_bytes(keepkvno.to_be_bytes()));
    w.b
}

fn setkey16_args(name: &str, etype: i32, key: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(1);
    w.u32(u32::try_from(etype).unwrap());
    w.opaque(key);
    w.b
}

fn setkey4_args(
    name: &str,
    keepold: bool,
    kvno: u32,
    etype: i32,
    key: &[u8],
    salt_type: i32,
    salt: &[u8],
) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.u32(u32::from(keepold));
    w.u32(1);
    w.u32(kvno);
    w.u32(u32::try_from(etype).unwrap());
    w.opaque(key);
    w.u32(u32::try_from(salt_type).unwrap());
    w.opaque(salt);
    w.b
}

fn chpass_args(name: &str, pass: &str) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(name));
    w.nullstring(Some(pass));
    w.b
}

fn lockdown_user(store: &SharedStore) {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let mut g = store.write().unwrap();
    g.apply_admin_fields(
        &user,
        krb5_kdc::AdminFields {
            attributes: Some(KDB_LOCKDOWN_KEYS),
            max_life: None,
            expiration: None,
            pw_expire: None,
            policy: None,
            clear_policy: false,
            max_renewable_life: None,
        },
    )
    .unwrap();
}

fn encode_cpol(api: u32, p: &krb5_kdc::NamedPolicy, mask: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    encode_policy_rec(&mut w, api, p);
    w.u32(mask);
    w.b
}

fn modify_policy_floor_code(mask: u32, set: impl Fn(&mut krb5_kdc::NamedPolicy)) -> u32 {
    let (store, acl, actor) = setup();
    let pol = krb5_kdc::NamedPolicy::new("fl");
    let created = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_POLICY,
        &encode_cpol(API_V2, &pol, KADM5_POLICY),
    )
    .unwrap();
    assert_eq!(ret_code(&created), 0);
    let mut rec = pol;
    set(&mut rec);
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        MODIFY_POLICY,
        &encode_cpol(API_V2, &rec, mask),
    )
    .unwrap();
    ret_code(&out)
}

// Give a shared store a real master key the iprop encoder can wrap keys
// with: `save_store` writes a keytab stash for the fresh bootstrap, then
// `persist_paths` points `iprop_master_key` at it. Without this a store has
// no master key and the encoder refuses to ship keys (see the negative test).
fn seed_master_key(store: &krb5_kdc::SharedDump) {
    let dir = std::env::temp_dir().join(format!(
        "krb5-iprop-mk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    {
        let g = store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        krb5_kdc::save_store(&g, &db, &stash).expect("write master stash");
    }
    let mut g = store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.persist_paths = Some((db, stash));
}

mod auth_gssapi;
mod changepw;
mod framing;
mod getprinc;
mod glob;
mod iprop;
mod keysalt;
mod lockdown;
mod policy;
mod principal;
mod privilege;
mod reload;
mod rpcsec;
mod setstr;
