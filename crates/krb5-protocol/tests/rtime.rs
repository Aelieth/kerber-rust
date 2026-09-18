//! Z8.2: `set_request_times` clamps `rtime` to `till`
//! (`get_in_tkt.c:718-722`). Source pin so the inject compiles at the
//! parent (no public rtime getter there) and still fails.

#[test]
fn z8_rtime_is_clamped_up_to_till() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/as_ex.rs"));
    assert!(
        src.contains("till.unix_seconds() > rt.unix_seconds()") || src.contains("if till > rtime"),
        "get_in_tkt.c:718-722 rtime = max(from+renew_life, till)"
    );
}
