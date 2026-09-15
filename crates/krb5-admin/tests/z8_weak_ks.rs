//! Z8.5: v3 `ks_tuple` uses MIT `ETYPE_WEAK` (`is_mit_weak`), not the
//! house `is_weak` set. Source pin so the inject compiles at the parent
//! (`key_salt_tuples` already exists) and still fails.

#[test]
fn z8_ks_tuple_filters_mit_weak_only() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/kadm5.rs"));
    assert!(
        src.contains("is_mit_weak()"),
        "allow_weak_crypto × ks_tuple: etypes.c ETYPE_WEAK only"
    );
}
