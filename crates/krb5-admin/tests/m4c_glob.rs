//! GET_PRINCS glob filtering like MIT `svr_iters.c glob_to_regexp` + `regexec`:
//! `*1` matches a1/a11/xa1 but not a10 (settled live in
//! `working/logs/audit-polish-0902/w1k/m3a-settle-mit-alias.log` §E).

mod common;

use common::{
    API_V2, GET_PRINCS, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_u32,
    take_opaque, take_u32,
};
use krb5_kdc::{Acl, TEST_REALM, bootstrap_documented, documented_kadmin, shared_dump};
use krb5_types::PrincipalName;

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn gprincs_args(glob: &str) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, glob);
    w
}

/// Names from a `gprincs_ret` databody (api, code, n, n, [nullstring…]).
fn names(body: &[u8]) -> Vec<String> {
    let mut i = 8; // api + code
    let n = take_u32(body, &mut i);
    let _n2 = take_u32(body, &mut i);
    (0..n)
        .map(|_| {
            let b = take_opaque(body, &mut i);
            String::from_utf8_lossy(b.strip_suffix(&[0]).unwrap_or(b)).into_owned()
        })
        .collect()
}

#[test]
fn get_princs_glob_matches_svr_iters() {
    let (mut store, _) = bootstrap_documented().unwrap();
    for p in ["a1", "a10", "a11", "xa1", "b2"] {
        store
            .insert_new_password(&name(p), TEST_REALM, b"pw", &[])
            .unwrap();
    }
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &name("admin"),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );

    let (stat, body) = data_call(&mut c, &store, &acl, GET_PRINCS, &gprincs_args("*1"));
    assert_eq!(stat, SUCCESS);
    let got = names(&body);
    assert!(got.contains(&format!("a1@{TEST_REALM}")), "{got:?}");
    assert!(got.contains(&format!("a11@{TEST_REALM}")), "{got:?}");
    assert!(got.contains(&format!("xa1@{TEST_REALM}")), "{got:?}");
    assert!(
        !got.contains(&format!("a10@{TEST_REALM}")),
        "a10 must not match *1: {got:?}"
    );

    let (_, body) = data_call(&mut c, &store, &acl, GET_PRINCS, &gprincs_args("a?"));
    let got = names(&body);
    assert!(got.contains(&format!("a1@{TEST_REALM}")), "{got:?}");
    assert!(
        !got.contains(&format!("a10@{TEST_REALM}")),
        "a10 is two chars: {got:?}"
    );
    assert!(!got.contains(&format!("b2@{TEST_REALM}")), "{got:?}");

    let (_, body) = data_call(&mut c, &store, &acl, GET_PRINCS, &gprincs_args("[ab]1*"));
    let got = names(&body);
    assert!(got.contains(&format!("a10@{TEST_REALM}")), "{got:?}");
    assert!(got.contains(&format!("a11@{TEST_REALM}")), "{got:?}");
    assert!(!got.contains(&format!("xa1@{TEST_REALM}")), "{got:?}");
}
