//! kadm5 glob tests (private-bound; regrouped in place).

#[test]
fn glob_matches_like_svr_iters() {
    use super::{glob_expand, glob_is_match};
    let m = |g: &str, realm: bool, t: &str| {
        glob_is_match(glob_expand(g, realm).as_bytes(), t.as_bytes())
    };
    assert!(m("a*", true, "a1@KERBER.TEST"));
    assert!(m("a?", true, "a1@KERBER.TEST"));
    assert!(!m("a?", true, "a10@KERBER.TEST"));
    assert!(m("*1", true, "a1@KERBER.TEST"));
    assert!(m("*1", true, "a11@KERBER.TEST"));
    assert!(m("*1", true, "xa1@KERBER.TEST"));
    assert!(!m("*1", true, "a10@KERBER.TEST"));
    assert!(m("[ab]1*", true, "a10@KERBER.TEST"));
    assert!(!m("[ab]1*", true, "c10@KERBER.TEST"));
    assert!(m("*@KERBER.TEST", true, "a1@KERBER.TEST"));
    assert!(!m("a.1", true, "a11@KERBER.TEST"));
    assert!(m("*x", false, "p1x"));
    assert!(m("*x", false, "px"));
    assert!(!m("*x", false, "p2"));
    assert!(m("p?", false, "px"));
    assert!(!m("p?", false, "p1x"));
    assert!(!m("*@*", false, "p1x"));
}
