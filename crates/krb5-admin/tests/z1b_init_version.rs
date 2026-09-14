//! W1-Z Z1b.1: the AUTH_GSSAPI `GSSAPI_INIT` arg-version switch
//! (`lib/rpc/svc_auth_gssapi.c:326-341`): versions 1 and 2 are answered with
//! `call_res.version` 1 (the OpenVision compat downgrade), 3 and 4 are
//! echoed, anything else is `AUTH_BADCRED` before the token is looked at.
//! Compiles at `59c363b` (parent-red): the parent echoed every version and
//! answered version 5 with an accepted `init_res`.

mod common;

use common::{FLAVOR_NONE, MSG_ACCEPTED, MSG_REPLY, RPC_VERSION, SUCCESS, push_opaque, push_u32};
use krb5_admin::{Kadm5RpcSession, kadm5_handle_rpc};
use krb5_kdc::{Acl, TEST_REALM, bootstrap_documented, shared_dump};
use krb5_protocol::ReplayCache;

const MSG_CALL: u32 = 0;
const KADM_PROG: u32 = 2112;
const KADM_VERS: u32 = 2;
const AUTH_GSSAPI_INIT: u32 = 1;
const FLAVOR_AUTH_GSSAPI: u32 = 300_001;
const AUTH_GSSAPI_CREDS_VERS: u32 = 2;
const MSG_DENIED: u32 = 1;
const REJECT_AUTH_ERROR: u32 = 1;
const AUTH_BADCRED: u32 = 1;

/// One `AUTH_GSSAPI_INIT` call on `KADM_PROG` whose `authgssapi_init_arg`
/// carries `version` and an empty token (the token never verifies, which
/// MIT still answers with an `init_res` — `svc_auth_gssapi.c:452-463`).
fn init_call(xid: u32, version: u32) -> Vec<u8> {
    let mut cred = Vec::new();
    push_u32(&mut cred, AUTH_GSSAPI_CREDS_VERS);
    push_u32(&mut cred, 1); // auth_msg TRUE
    push_opaque(&mut cred, &[]); // client_handle
    let mut w = Vec::new();
    push_u32(&mut w, xid);
    push_u32(&mut w, MSG_CALL);
    push_u32(&mut w, RPC_VERSION);
    push_u32(&mut w, KADM_PROG);
    push_u32(&mut w, KADM_VERS);
    push_u32(&mut w, AUTH_GSSAPI_INIT);
    push_u32(&mut w, FLAVOR_AUTH_GSSAPI);
    push_opaque(&mut w, &cred);
    push_u32(&mut w, FLAVOR_NONE);
    push_opaque(&mut w, &[]);
    push_u32(&mut w, version);
    push_opaque(&mut w, &[]);
    w
}

fn reply_words(version: u32) -> Vec<u32> {
    let (store, _) = bootstrap_documented().unwrap();
    let store = shared_dump(store);
    let acl = Acl::parse("*/admin@KERBER.TEST *\n").unwrap();
    let mut sess = Kadm5RpcSession::default();
    let out = kadm5_handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &init_call(77, version),
        "127.0.0.1",
    )
    .unwrap();
    out.as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect()
}

/// `init_res.version` of an accepted reply: words are xid, REPLY, ACCEPTED,
/// verf flavor, verf len 0, SUCCESS, then the `authgssapi_init_res`.
fn accepted_res_version(w: &[u32]) -> u32 {
    assert_eq!(
        &w[..6],
        &[77, MSG_REPLY, MSG_ACCEPTED, FLAVOR_NONE, 0, SUCCESS]
    );
    w[6]
}

#[test]
fn z1b_init_arg_version_2_is_answered_with_version_1() {
    // 3 and 4 are echoed (`:333-336`) …
    assert_eq!(accepted_res_version(&reply_words(4)), 4);
    assert_eq!(accepted_res_version(&reply_words(3)), 3);
    // … 1 and 2 are the OpenVision protocol and get `call_res.version = 1`
    // (`:328-331`); the parent echoed 2.
    assert_eq!(accepted_res_version(&reply_words(2)), 1);
    assert_eq!(accepted_res_version(&reply_words(1)), 1);
}

#[test]
fn z1b_init_arg_version_5_is_auth_badcred() {
    // `:337-341` default: "unsupported GSSAPI_INIT version" → AUTH_BADCRED,
    // an RPC MSG_DENIED / AUTH_ERROR; the parent accepted it and echoed 5.
    let w = reply_words(5);
    assert_eq!(
        &w[..5],
        &[77, MSG_REPLY, MSG_DENIED, REJECT_AUTH_ERROR, AUTH_BADCRED],
        "reply words {w:?}"
    );
    let w = reply_words(0);
    assert_eq!(
        &w[..5],
        &[77, MSG_REPLY, MSG_DENIED, REJECT_AUTH_ERROR, AUTH_BADCRED]
    );
}
