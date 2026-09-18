//! kadm5 glob tests (private-bound; regrouped in place).

#[test]
fn glob_rejects_malformed_and_matches_posix_classes() {
    use super::{glob_is_match, glob_pattern_ok};
    // MIT regcomp fails these (EINVAL from kadm5_get_either).
    assert!(!glob_pattern_ok("[abc"), "unterminated bracket");
    assert!(!glob_pattern_ok("ga\\"), "trailing backslash");
    assert!(
        !glob_pattern_ok("ga\\\\"),
        "trailing escaped backslash (Rust does not unescape)"
    );
    assert!(
        !glob_pattern_ok("a[[:digit:]"),
        "unterminated class bracket"
    );
    // Valid patterns compile.
    assert!(glob_pattern_ok("ga*"));
    assert!(glob_pattern_ok("[abc]"));
    assert!(glob_pattern_ok("[[:digit:]]a*"));
    assert!(glob_pattern_ok("[]abc]"));
    // POSIX classes match like MIT's BRE.
    assert!(glob_is_match(b"[[:digit:]]", b"5"));
    assert!(!glob_is_match(b"[[:digit:]]", b"a"));
    assert!(glob_is_match(b"[[:alpha:]]x", b"gx"));
    assert!(!glob_is_match(b"[[:digit:]]a*", b"ga1"));
}

#[test]
fn glob_matches_like_svr_iters() {
    use super::{glob_expand, glob_is_match};
    let m = |g: &str, realm: bool, t: &str| {
        glob_is_match(glob_expand(g, realm).as_bytes(), t.as_bytes())
    };
    // Principals: implicit @* so "a*" matches a1@REALM.
    assert!(m("a*", true, "a1@KERBER.TEST"));
    assert!(m("a?", true, "a1@KERBER.TEST"));
    assert!(!m("a?", true, "a10@KERBER.TEST"));
    // "*1" matches a1/a11/xa1, not a10 (ends in 0 before @).
    assert!(m("*1", true, "a1@KERBER.TEST"));
    assert!(m("*1", true, "a11@KERBER.TEST"));
    assert!(m("*1", true, "xa1@KERBER.TEST"));
    assert!(!m("*1", true, "a10@KERBER.TEST"));
    assert!(m("[ab]1*", true, "a10@KERBER.TEST"));
    assert!(!m("[ab]1*", true, "c10@KERBER.TEST"));
    assert!(m("*@KERBER.TEST", true, "a1@KERBER.TEST"));
    assert!(!m("a.1", true, "a11@KERBER.TEST"));
    // Policies: no realm append.
    assert!(m("*x", false, "p1x"));
    assert!(m("*x", false, "px"));
    assert!(!m("*x", false, "p2"));
    assert!(m("p?", false, "px"));
    assert!(!m("p?", false, "p1x"));
    assert!(!m("*@*", false, "p1x"));
}
