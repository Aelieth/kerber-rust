//! kadm5 setstr tests (private-bound; regrouped in place).

use super::*;

#[test]
fn setstr_getstrs_round_trip() {
    let (store, acl, actor) = setup();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.nullstring(Some("note"));
    w.nullstring(Some("hello-g3d"));
    let out = dispatch_kadm5(&store, &acl, &actor, SET_STRING, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let mut g = XdrW::default();
    g.u32(API_V2);
    g.nullstring(Some("user@KERBER.TEST"));
    let got = dispatch_kadm5(&store, &acl, &actor, GET_STRINGS, &g.b).unwrap();
    assert_eq!(ret_code(&got), 0);
    let mut r = XdrR::new(&got);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    let n = r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), n);
    assert_eq!(n, 1);
    assert_eq!(r.nullstring().unwrap().as_deref(), Some("note"));
    assert_eq!(r.nullstring().unwrap().as_deref(), Some("hello-g3d"));
}
