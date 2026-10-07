//! The AS exchange's clock: the local time, or the KDC's as a preauth error gave it.
//!
//! A PREAUTH_REQUIRED or PREAUTH_FAILED error that is retried carries the KDC's time; its offset
//! from the local clock is kept for the rest of the exchange, marked authenticated when the error
//! came through FAST armor. With `[libdefaults] kdc_timesync` on (the default) every later
//! request's times, the encrypted timestamp and the PKINIT authenticator use the KDC's time, and
//! the encrypted challenge uses it when it is authenticated.

use std::cell::Cell;

use krb5_types::{KerberosTime, KrbError, Microseconds};

use crate::auth_con::us_timeofday;

/// MIT `pa_offset`, `pa_offset_usec` and `pa_offset_state` (`init_creds_ctx.h`): the KDC's time
/// less the local time, and whether it came through FAST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Offset {
    sec: i64,
    usec: i64,
    authenticated: bool,
}

/// One AS exchange's clock.
#[derive(Debug)]
pub(super) struct Clock {
    offset: Cell<Option<Offset>>,
    /// MIT `KRB5_LIBOPT_SYNC_KDCTIME`: `[libdefaults] kdc_timesync`, on by default.
    sync: bool,
}

impl Clock {
    /// A clock with no KDC time yet, syncing as `kdc_timesync` says.
    /// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:268-270`): `kdc_timesync` is on unless set to 0.
    pub(super) fn new() -> Self {
        Self::with_sync(krb5_config::load_krb5_conf().is_none_or(|c| c.kdc_timesync))
    }

    /// A clock with no KDC time yet; `sync` is `kdc_timesync`.
    pub(super) fn with_sync(sync: bool) -> Self {
        Self {
            offset: Cell::new(None),
            sync,
        }
    }

    /// Note the KDC's time from `err`, a retried PREAUTH_REQUIRED or PREAUTH_FAILED; `armored`
    /// when it came through FAST.
    /// MIT `note_req_timestamp` (`lib/krb5/krb/get_in_tkt.c:1433-1438`): the offset is the error's time less the local time, authenticated when there is an armor key.
    /// MIT `init_creds_step_reply` (`lib/krb5/krb/get_in_tkt.c:1727-1733`): a PREAUTH_REQUIRED or PREAUTH_FAILED error that is retried notes it.
    pub(super) fn note(&self, err: &KrbError, armored: bool) {
        let (now, usec) = us_timeofday();
        self.offset.set(Some(Offset {
            sec: i64::from(err.stime.unix_seconds()) - i64::from(now.unix_seconds()),
            usec: i64::from(err.susec.get()) - i64::from(usec.get()),
            authenticated: armored,
        }));
    }

    /// The time now: the KDC's when an offset is noted, `kdc_timesync` is on, and the caller takes
    /// an unauthenticated offset (`allow_unauth`) or the offset is authenticated; else the local
    /// time.
    /// MIT `k5_init_creds_current_time` (`lib/krb5/krb/get_in_tkt.c:683-697`): the offset from a preauth-required error, else the local time.
    pub(super) fn now(&self, allow_unauth: bool) -> (KerberosTime, Microseconds) {
        match self.offset.get() {
            Some(o) if self.sync && (allow_unauth || o.authenticated) => {
                let (now, usec) = us_timeofday();
                with_offset(
                    i64::from(now.unix_seconds()),
                    i64::from(usec.get()),
                    o.sec,
                    o.usec,
                )
            }
            _ => us_timeofday(),
        }
    }
}

/// The time `sec`.`usec` moved by `off_sec`.`off_usec`.
/// MIT `k5_time_with_offset` (`lib/krb5/os/ustime.c:47-59`): the microseconds are added first and carried into the seconds, then the seconds.
/// MIT carries only past 1000000 and so can leave exactly 1000000 microseconds, which is no valid
/// value; here that carries too.
fn with_offset(sec: i64, usec: i64, off_sec: i64, off_usec: i64) -> (KerberosTime, Microseconds) {
    let mut sec = sec;
    let mut usec = usec + off_usec;
    if usec >= 1_000_000 {
        usec -= 1_000_000;
        sec += 1;
    }
    if usec < 0 {
        usec += 1_000_000;
        sec -= 1;
    }
    sec += off_sec;
    let sec = u32::try_from(sec.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX);
    let usec = u32::try_from(usec).unwrap_or_default();
    (
        KerberosTime::from_unix_seconds(sec),
        Microseconds::from_subsec_micros(usec),
    )
}

#[cfg(test)]
mod tests;
