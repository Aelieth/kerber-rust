//! W1-B B1: `kdc_timesync` in `verify_as_reply`.
//! MIT `get_in_tkt.c:260-270`. The live oracle is
//! `scripts/client-differential-gate.sh` (+3d `LD_PRELOAD`).
//! Unit-only here: at `432e4b9` `check_as_rep_times` is `pub(crate)`
//! so a `pub use` inject does not compile (vacuous red).

use krb5_config::set_test_krb5_paths;
use krb5_protocol::check_as_rep_times;
use krb5_types::{
    EncKdcRepPart, EncryptionKey, KerberosTime, OctetString, PrincipalName, TicketFlags, ascii,
    kerberos_time_from_utc_z,
};

fn sample_part() -> EncKdcRepPart {
    let t = kerberos_time_from_utc_z("20260819120000Z").expect("sample time");
    EncKdcRepPart {
        key: EncryptionKey {
            keytype: 18,
            keyvalue: OctetString::from(vec![1u8; 32]),
        },
        last_req: vec![],
        nonce: 7,
        key_expiration: None,
        flags: TicketFlags::none(),
        authtime: t.clone(),
        starttime: None,
        endtime: t,
        renew_till: None,
        srealm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        caddr: None,
        encrypted_pa_data: None,
    }
}

fn pin_timesync(on: bool) {
    let dir = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|p| std::path::PathBuf::from(p).join("test-krb5"))
        })
        .unwrap_or_else(|| {
            std::path::PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../target/test-krb5"
            ))
        });
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!(
        "b1-timesync-{}-{}.conf",
        std::process::id(),
        if on { "on" } else { "off" }
    ));
    let flag = if on { "yes" } else { "no" };
    std::fs::write(&path, format!("[libdefaults]\n    kdc_timesync = {flag}\n"))
        .expect("write timesync conf");
    set_test_krb5_paths(Some(vec![path]));
}

#[test]
fn b1_kdc_timesync_accepts_authtime_outside_skew() {
    pin_timesync(true);
    let mut part = sample_part();
    let now_t = KerberosTime::now();
    let now = i64::from(now_t.unix_seconds());
    part.authtime = kerberos_time_from_utc_z("20000101000000Z").expect("old");
    part.starttime = Some(part.authtime.clone());
    part.endtime = now_t.add_hours(10).unwrap_or(now_t);
    check_as_rep_times(&part, now, 300).expect("MIT default kdc_timesync skips starttime");
}

#[test]
fn b1_kdc_timesync_off_is_kdcrep_skew() {
    pin_timesync(false);
    let mut part = sample_part();
    let now_t = KerberosTime::now();
    let now = i64::from(now_t.unix_seconds());
    part.authtime = kerberos_time_from_utc_z("20000101000000Z").expect("old");
    part.starttime = Some(part.authtime.clone());
    part.endtime = now_t.add_hours(10).unwrap_or(now_t);
    let err = check_as_rep_times(&part, now, 300).expect_err("timesync=0");
    assert!(
        err.to_string()
            .contains("Clock skew too great in KDC reply"),
        "MIT get_in_tkt.c:266-269, got {err}"
    );
}
