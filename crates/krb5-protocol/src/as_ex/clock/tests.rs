//! The AS clock as MIT's `k5_init_creds_current_time`, `note_req_timestamp` and
//! `k5_time_with_offset`.

use super::{Clock, with_offset};
use crate::auth_con::us_timeofday;
use krb5_types::{KerberosTime, KrbError, Microseconds, PrincipalName, ascii, err};

fn preauth_required_at(stime: u32, susec: u32) -> KrbError {
    KrbError {
        pvno: KrbError::PVNO,
        msg_type: KrbError::MSG_TYPE,
        ctime: None,
        cusec: None,
        stime: KerberosTime::from_unix_seconds(stime),
        susec: Microseconds::new(susec).unwrap(),
        error_code: err::PREAUTH_REQUIRED,
        crealm: None,
        cname: None,
        realm: ascii("KERBER.TEST"),
        sname: PrincipalName::krbtgt("KERBER.TEST"),
        e_text: None,
        e_data: None,
    }
}

fn secs(t: &KerberosTime) -> i64 {
    i64::from(t.unix_seconds())
}

#[test]
fn the_offset_carries_microseconds_into_seconds_as_mit() {
    let at = |sec, usec, off_sec, off_usec| {
        let (t, u) = with_offset(sec, usec, off_sec, off_usec);
        (secs(&t), u.get())
    };
    assert_eq!(at(1000, 400_000, 3600, 300_000), (4600, 700_000));
    assert_eq!(at(1000, 900_000, 3600, 300_000), (4601, 200_000));
    assert_eq!(at(10_000, 100_000, -3600, -300_000), (6399, 800_000));
    // MIT leaves exactly 1000000 microseconds (`usec > 1000000`); here it carries.
    assert_eq!(at(1000, 999_999, 0, 1), (1001, 0));
}

#[test]
fn a_kdc_time_is_used_after_a_preauth_error_as_mit() {
    let (now, _) = us_timeofday();
    let kdc = now.unix_seconds() - 3600;
    let clock = Clock::with_sync(true);
    assert!(
        (secs(&clock.now(true).0) - secs(&now)).abs() <= 2,
        "no offset: the local time"
    );
    clock.note(&preauth_required_at(kdc, 0), false);
    let unauth = secs(&clock.now(true).0);
    assert!(
        (unauth - i64::from(kdc)).abs() <= 2,
        "the KDC's time: {unauth} vs {kdc}"
    );
    // An unarmored error's offset is not used where only an authenticated one may be.
    assert!((secs(&clock.now(false).0) - secs(&now)).abs() <= 2);
    clock.note(&preauth_required_at(kdc, 0), true);
    assert!((secs(&clock.now(false).0) - i64::from(kdc)).abs() <= 2);
}

#[test]
fn kdc_timesync_off_keeps_the_local_time() {
    let (now, _) = us_timeofday();
    let clock = Clock::with_sync(false);
    clock.note(&preauth_required_at(now.unix_seconds() + 7200, 0), true);
    assert!((secs(&clock.now(true).0) - secs(&now)).abs() <= 2);
    assert!((secs(&clock.now(false).0) - secs(&now)).abs() <= 2);
}
