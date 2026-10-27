//! The AS exchange's clock: the local time, or the KDC's as a preauth error gave it.

use std::cell::{Cell, RefCell};

use krb5_types::{KerberosTime, KrbError, Microseconds};

use super::AsRestart;
use crate::auth_con::us_timeofday;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Offset {
    sec: i64,
    usec: i64,
    authenticated: bool,
}

#[derive(Debug)]
pub(super) struct Clock {
    offset: Cell<Option<Offset>>,
    sync: bool,
    request: RefCell<AsRestart>,
}

impl Clock {
    // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:268-270)
    /// On unless set to 0.
    pub(super) fn new(profile: &krb5_config::Krb5Conf, start: AsRestart) -> Self {
        Self {
            offset: Cell::new(None),
            sync: profile.kdc_timesync,
            request: RefCell::new(start),
        }
    }

    // MIT: `init_creds_step_request` (lib/krb5/krb/get_in_tkt.c:1273-1281)
    /// A restart takes the request as the last step left it.
    pub(super) fn note_request(&self, step: AsRestart) {
        self.request.replace(step);
    }

    pub(super) fn restart(&self) -> AsRestart {
        self.request.borrow().clone()
    }

    // MIT: `note_req_timestamp` (lib/krb5/krb/get_in_tkt.c:1433-1438)
    /// The offset is the error's time less the local time.
    /// An armor key makes the offset authenticated.
    // MIT: `init_creds_step_reply` (lib/krb5/krb/get_in_tkt.c:1727-1733)
    pub(super) fn note(&self, err: &KrbError, armored: bool) {
        let (now, usec) = us_timeofday();
        self.offset.set(Some(Offset {
            sec: i64::from(err.stime.unix_seconds()) - i64::from(now.unix_seconds()),
            usec: i64::from(err.susec.get()) - i64::from(usec.get()),
            authenticated: armored,
        }));
    }

    /// Sync is on and an offset is noted.
    pub(super) fn follows_kdc(&self) -> bool {
        self.sync && self.offset.get().is_some()
    }

    // MIT: `k5_init_creds_current_time` (lib/krb5/krb/get_in_tkt.c:683-697)
    /// An unauthenticated offset is used only when the caller allows it.
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

// MIT: `k5_time_with_offset` (lib/krb5/os/ustime.c:47-59)
/// Microseconds are added first and carried, then the seconds.
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
