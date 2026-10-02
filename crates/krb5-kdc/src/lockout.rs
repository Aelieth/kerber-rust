//! The KDC's account lockout as MIT's db2 module runs it: the policy check before
//! preauthentication, and the audit of every AS outcome that counts, which records a client's
//! last successful and last failed authentication and its failed-attempt count.
//!
//! The audit decides from the client entry as the request looked it up; the store applies the
//! decision to the attributes as they are when it writes ([`PrincipalRead::update_lockout`]), so
//! two outcomes recorded at once both count. The audit never changes the entry's attributes: a
//! locked-out client is refused by the check, not disabled.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use krb5_types::err;

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::kdb_dump::TL_LAST_ADMIN_UNLOCK;
use crate::status;
use crate::store::{KDB_REQUIRES_PRE_AUTH, Principal};

/// A principal's three lockout attributes, which MIT does not replicate: the last successful
/// and the last failed authentication, and the failed attempts since the count was reset.
/// MIT `klmdb_encode_princ_lockout` (`plugins/kdb/lmdb/marshal.c:91-98`): a lockout record holds these three fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lockout {
    /// `last_success`, Unix seconds (0 = never).
    pub last_success: u32,
    /// `last_failed`, Unix seconds (0 = never).
    pub last_failed: u32,
    /// `fail_auth_count`.
    pub fail_auth_count: u32,
}

impl Lockout {
    /// The attributes `p` carries.
    #[must_use]
    pub fn of(p: &Principal) -> Self {
        Self {
            last_success: p.last_success,
            last_failed: p.last_failed,
            fail_auth_count: p.fail_auth_count,
        }
    }

    /// Give `p` these attributes.
    pub fn set_on(self, p: &mut Principal) {
        p.last_success = self.last_success;
        p.last_failed = self.last_failed;
        p.fail_auth_count = self.fail_auth_count;
    }
}

/// What one counted AS outcome changes in a principal's [`Lockout`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LockoutUpdate {
    /// The failed-attempt count goes back to 0 first.
    pub zero_fail_count: bool,
    /// `last_success` becomes the request's time.
    pub set_last_success: bool,
    /// `last_failed` becomes the request's time and the count goes up by one.
    pub set_last_failure: bool,
}

impl LockoutUpdate {
    /// Whether the update changes nothing, so nothing is written.
    #[must_use]
    pub fn is_empty(self) -> bool {
        !(self.zero_fail_count || self.set_last_success || self.set_last_failure)
    }

    /// `base` with the update applied at `stamp`.
    /// MIT `klmdb_update_lockout` (`plugins/kdb/lmdb/kdb_lmdb.c:1054-1121`): the update starts from the attributes stored when it writes, then zeroes, stamps and counts.
    #[must_use]
    pub fn apply(self, base: Lockout, stamp: u32) -> Lockout {
        let mut out = base;
        if self.zero_fail_count {
            out.fail_auth_count = 0;
        }
        if self.set_last_success {
            out.last_success = stamp;
        }
        if self.set_last_failure {
            out.last_failed = stamp;
            out.fail_auth_count = out.fail_auth_count.wrapping_add(1);
        }
        out
    }
}

/// The lockout attributes a process keeps in memory for the principals whose AS outcomes it
/// recorded, shared by every copy of its store and kept across its reads of the database.
#[derive(Debug, Default)]
pub(crate) struct LockoutState {
    overlay: Mutex<HashMap<String, Lockout>>,
}

impl LockoutState {
    fn overlay(&self) -> MutexGuard<'_, HashMap<String, Lockout>> {
        self.overlay.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The attributes kept for `id`, if any.
    pub(crate) fn overlay_get(&self, id: &str) -> Option<Lockout> {
        self.overlay().get(id).copied()
    }

    /// Keep `lockout` for `id`.
    pub(crate) fn overlay_put(&self, id: String, lockout: Lockout) {
        self.overlay().insert(id, lockout);
    }

    /// Zero the failed authentication count kept for `id`, when one is kept.
    pub(crate) fn overlay_zero(&self, id: &str) {
        if let Some(l) = self.overlay().get_mut(id) {
            l.fail_auth_count = 0;
        }
    }
}

/// MIT `ts_after` (`include/k5-int.h:2350-2354`): times compare as unsigned 32-bit values.
fn ts_after(a: u32, b: u32) -> bool {
    a > b
}

/// MIT `ts_incr` (`include/k5-int.h:2343-2347`): a time plus a duration wraps as an unsigned 32-bit value.
fn ts_incr(ts: u32, delta: u32) -> u32 {
    ts.wrapping_add(delta)
}

/// The time of the principal's last administrative unlock, 0 when it has none.
/// MIT `krb5_dbe_lookup_last_admin_unlock` (`lib/kdb/kdb5.c:1530-1552`): a `KRB5_TL_LAST_ADMIN_UNLOCK` that is not four bytes, or none, is time 0.
pub(crate) fn last_admin_unlock(p: &Principal) -> u32 {
    // KRB5_TL_LAST_ADMIN_UNLOCK (0x0700) holds the time as four little-endian bytes.
    p.tl_data
        .iter()
        .find(|t| t.ty == TL_LAST_ADMIN_UNLOCK)
        .and_then(|t| <[u8; 4]>::try_from(t.contents.as_slice()).ok())
        .map_or(0, u32::from_le_bytes)
}

/// The principal's lockout policy: its maximum failures, failure count interval and lockout
/// duration, all 0 when it has no policy or its policy does not exist.
/// MIT `lookup_lockout_policy` (`plugins/kdb/db2/lockout.c:40-89`): the policy named in the entry's kadm5 data, zeros without one.
fn lookup_lockout_policy<S: PrincipalRead + ?Sized>(store: &S, p: &Principal) -> (u32, u32, u32) {
    store.named_policy_for(p).map_or((0, 0, 0), |pol| {
        (
            pol.max_fail,
            pol.pw_failcnt_interval,
            pol.pw_lockout_duration,
        )
    })
}

/// Whether `p` is locked out at `stamp`.
/// MIT `locked_check_p` (`plugins/kdb/db2/lockout.c:92-113`): an unlock since the last failure unlocks; else locked at max_fail failures, for good or until the duration passes.
fn locked_check_p(stamp: u32, max_fail: u32, lockout_duration: u32, p: &Principal) -> bool {
    if !ts_after(p.last_failed, last_admin_unlock(p)) {
        return false;
    }
    if max_fail == 0 || p.fail_auth_count < max_fail {
        return false;
    }
    if lockout_duration == 0 {
        return true;
    }
    ts_after(ts_incr(p.last_failed, lockout_duration), stamp)
}

/// The KDB module's AS policy check: `CLIENT_REVOKED` with MIT's `LOCKED_OUT` status for a
/// client locked out at `stamp`, the request's time.
/// MIT `krb5_db2_lockout_check_policy` (`plugins/kdb/db2/lockout.c:115-139`): nothing with `disable_lockout`, else `CLIENT_REVOKED` when `locked_check_p` holds.
/// MIT `krb5_db2_check_policy_as` (`plugins/kdb/db2/kdb_db2.c:1539-1550`): that refusal's status is `LOCKED_OUT`.
///
/// # Errors
///
/// [`Error::Protocol`] `CLIENT_REVOKED` / `LOCKED_OUT` when the client is locked out.
pub(crate) fn lockout_check_policy<S: PrincipalRead + ?Sized>(
    store: &S,
    p: &Principal,
    stamp: u32,
) -> Result<(), Error> {
    if store.policy().disable_lockout {
        return Ok(());
    }
    let (max_fail, _, lockout_duration) = lookup_lockout_policy(store, p);
    if locked_check_p(stamp, max_fail, lockout_duration, p) {
        return Err(crate::preauth::proto(
            err::CLIENT_REVOKED,
            status::LOCKED_OUT,
        ));
    }
    Ok(())
}

/// The code an AS exchange ended with, as the audit sees it: 0 for a reply, else the KRB-ERROR
/// code; a failure that is no KRB-ERROR is `KRB_ERR_GENERIC`, which never counts.
pub(crate) fn as_outcome<T>(out: &Result<T, Error>) -> i32 {
    match out {
        Ok(_) => 0,
        Err(Error::Protocol { code, .. }) => *code,
        Err(Error::PreauthRequired { .. }) => err::PREAUTH_REQUIRED,
        Err(_) => err::GENERIC,
    }
}

/// Record one AS outcome of `p`, the client entry as the request looked it up, ended with
/// `status` at `stamp`, the request's time: a reply to a client that requires preauthentication
/// stamps its last success and zeroes its count; a failed preauthentication or integrity check
/// stamps its last failure and counts it, the count first zeroed after an administrative unlock
/// since the last failure or once the policy's failure count interval has passed; any other
/// outcome, and any outcome for a client already locked out, changes nothing. The KDB's
/// `disable_last_success` and `disable_lockout` suppress the writes they name.
/// MIT `log_as_req` (`kdc/kdc_log.c:57-97`): every logged AS outcome goes to the KDB's audit with the request's time and error code.
/// MIT `krb5_db2_audit_as_req` (`plugins/kdb/db2/kdb_db2.c:1553-1560`): the audit is `krb5_db2_lockout_audit`.
/// MIT `krb5_db2_lockout_audit` (`plugins/kdb/db2/lockout.c:141-222`): only 0, `PREAUTH_FAILED` and `BAD_INTEGRITY` count, a locked entry is not written, and one put records what changed.
pub fn lockout_audit<S: PrincipalRead + ?Sized>(store: &S, p: &Principal, stamp: u32, status: i32) {
    if !matches!(status, 0 | err::PREAUTH_FAILED | err::BAD_INTEGRITY) {
        return;
    }
    let policy = store.policy();
    let (max_fail, failcnt_interval, lockout_duration) = if policy.disable_lockout {
        (0, 0, 0)
    } else {
        lookup_lockout_policy(store, p)
    };
    if locked_check_p(stamp, max_fail, lockout_duration, p) {
        return;
    }
    let mut update = LockoutUpdate::default();
    if status == 0 && p.attributes & KDB_REQUIRES_PRE_AUTH != 0 {
        update.zero_fail_count = !policy.disable_lockout && p.fail_auth_count != 0;
        update.set_last_success = !policy.disable_last_success;
    } else if status != 0 && !policy.disable_lockout {
        if !ts_after(p.last_failed, last_admin_unlock(p)) {
            update.zero_fail_count = true;
        }
        if failcnt_interval != 0 && ts_after(stamp, ts_incr(p.last_failed, failcnt_interval)) {
            update.zero_fail_count = true;
        }
        update.set_last_failure = true;
    }
    if !update.is_empty() {
        store.update_lockout(p, stamp, update);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{NamedPolicy, TlData};
    use crate::testrealm::{TEST_USER, bootstrap_documented};
    use krb5_types::PrincipalName;

    fn policy(max_fail: u32, interval: u32, duration: u32) -> NamedPolicy {
        NamedPolicy {
            name: "lock".into(),
            min_length: 1,
            min_classes: 1,
            history: 0,
            max_fail,
            pw_failcnt_interval: interval,
            pw_lockout_duration: duration,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        }
    }

    /// The documented realm with `user@` under `pol`, its attributes and lockout state set.
    fn realm(pol: NamedPolicy, attrs: u32, state: Lockout) -> (crate::PrincipalStore, Principal) {
        let (mut store, _) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        store.put_policy(pol);
        store
            .set_principal_policy(&user, Some("lock".into()))
            .unwrap();
        let mut p = store.get_name(&user).unwrap().clone();
        p.attributes = attrs;
        p.requires_preauth = attrs & KDB_REQUIRES_PRE_AUTH != 0;
        state.set_on(&mut p);
        store.debug_insert(p.clone());
        (store, p)
    }

    fn now(store: &crate::PrincipalStore, p: &Principal) -> Lockout {
        let mut q = p.clone();
        store.merge_lockout(&mut q);
        Lockout::of(&q)
    }

    /// One request: the entry looked up now, then its outcome audited.
    fn audit(store: &crate::PrincipalStore, p: &Principal, stamp: u32, status: i32) {
        let mut q = p.clone();
        store.merge_lockout(&mut q);
        lockout_audit(store, &q, stamp, status);
    }

    fn with_unlock(p: &mut Principal, at: u32) {
        p.tl_data.retain(|t| t.ty != TL_LAST_ADMIN_UNLOCK);
        p.tl_data.push(TlData {
            ty: TL_LAST_ADMIN_UNLOCK,
            contents: at.to_le_bytes().to_vec(),
        });
    }

    #[test]
    fn only_a_reply_a_failed_preauth_and_a_bad_integrity_count() {
        let (store, p) = realm(policy(3, 0, 0), KDB_REQUIRES_PRE_AUTH, Lockout::default());
        for status in [
            err::PREAUTH_REQUIRED,
            err::CLIENT_REVOKED,
            err::MORE_PREAUTH_DATA_REQUIRED,
            err::SKEW,
            err::GENERIC,
        ] {
            audit(&store, &p, 1000, status);
            assert_eq!(now(&store, &p), Lockout::default(), "status {status}");
        }
        audit(&store, &p, 1000, err::BAD_INTEGRITY);
        assert_eq!(now(&store, &p).fail_auth_count, 1);
        audit(&store, &p, 1001, err::PREAUTH_FAILED);
        let after = now(&store, &p);
        assert_eq!((after.fail_auth_count, after.last_failed), (2, 1001));
    }

    #[test]
    fn a_reply_counts_only_for_a_client_that_requires_preauth() {
        let state = Lockout {
            last_success: 0,
            last_failed: 900,
            fail_auth_count: 2,
        };
        let (store, p) = realm(policy(3, 0, 0), 0, state);
        audit(&store, &p, 1000, 0);
        assert_eq!(now(&store, &p), state);
        let (store, p) = realm(policy(3, 0, 0), KDB_REQUIRES_PRE_AUTH, state);
        audit(&store, &p, 1000, 0);
        assert_eq!(
            now(&store, &p),
            Lockout {
                last_success: 1000,
                last_failed: 900,
                fail_auth_count: 0,
            }
        );
    }

    #[test]
    fn a_locked_client_is_neither_counted_nor_stamped() {
        let state = Lockout {
            last_success: 10,
            last_failed: 900,
            fail_auth_count: 3,
        };
        let (store, p) = realm(policy(3, 0, 0), KDB_REQUIRES_PRE_AUTH, state);
        audit(&store, &p, 1000, err::PREAUTH_FAILED);
        audit(&store, &p, 1001, 0);
        assert_eq!(now(&store, &p), state);
        assert!(lockout_check_policy(&store, &p, 1002).is_err());
    }

    #[test]
    fn an_unlock_since_the_last_failure_unlocks_and_restarts_the_count() {
        let state = Lockout {
            last_success: 0,
            last_failed: 900,
            fail_auth_count: 3,
        };
        let (mut store, mut p) = realm(policy(3, 0, 0), KDB_REQUIRES_PRE_AUTH, state);
        with_unlock(&mut p, 950);
        store.debug_insert(p.clone());
        assert!(lockout_check_policy(&store, &p, 1000).is_ok());
        audit(&store, &p, 1000, err::PREAUTH_FAILED);
        let after = now(&store, &p);
        assert_eq!((after.fail_auth_count, after.last_failed), (1, 1000));
    }

    #[test]
    fn the_failure_count_interval_resets_the_count_but_never_a_lock() {
        let state = Lockout {
            last_success: 0,
            last_failed: 900,
            fail_auth_count: 1,
        };
        let (store, p) = realm(policy(2, 60, 0), KDB_REQUIRES_PRE_AUTH, state);
        audit(&store, &p, 961, err::PREAUTH_FAILED);
        assert_eq!(now(&store, &p).fail_auth_count, 1, "past the interval");
        let (store, p) = realm(policy(2, 60, 0), KDB_REQUIRES_PRE_AUTH, state);
        audit(&store, &p, 960, err::PREAUTH_FAILED);
        assert_eq!(now(&store, &p).fail_auth_count, 2, "at the interval's end");
        let locked = Lockout {
            fail_auth_count: 2,
            ..state
        };
        let (store, p) = realm(policy(2, 60, 0), KDB_REQUIRES_PRE_AUTH, locked);
        assert!(
            lockout_check_policy(&store, &p, 2000).is_err(),
            "a permanent lock outlives the interval"
        );
    }

    #[test]
    fn a_lock_with_a_duration_ends_when_the_duration_has_passed() {
        let state = Lockout {
            last_success: 0,
            last_failed: 900,
            fail_auth_count: 1,
        };
        let (store, p) = realm(policy(1, 0, 30), KDB_REQUIRES_PRE_AUTH, state);
        assert!(lockout_check_policy(&store, &p, 929).is_err());
        assert!(lockout_check_policy(&store, &p, 930).is_ok());
    }

    #[test]
    fn disable_lockout_and_disable_last_success_suppress_their_writes() {
        let state = Lockout {
            last_success: 0,
            last_failed: 900,
            fail_auth_count: 3,
        };
        let (mut store, p) = realm(policy(3, 0, 0), KDB_REQUIRES_PRE_AUTH, state);
        store.policy.disable_lockout = true;
        assert!(lockout_check_policy(&store, &p, 1000).is_ok());
        audit(&store, &p, 1000, err::PREAUTH_FAILED);
        assert_eq!(now(&store, &p), state);
        audit(&store, &p, 1001, 0);
        assert_eq!(
            now(&store, &p),
            Lockout {
                last_success: 1001,
                ..state
            },
            "the count stays with disable_lockout"
        );
        let (mut store, p) = realm(
            policy(3, 0, 0),
            KDB_REQUIRES_PRE_AUTH,
            Lockout {
                fail_auth_count: 1,
                ..state
            },
        );
        store.policy.disable_last_success = true;
        audit(&store, &p, 1000, 0);
        assert_eq!(
            now(&store, &p),
            Lockout {
                last_success: 0,
                last_failed: 900,
                fail_auth_count: 0,
            }
        );
    }

    #[test]
    fn an_admin_unlock_stamp_must_be_four_bytes() {
        let (_, mut p) = realm(policy(1, 0, 0), 0, Lockout::default());
        p.tl_data.push(TlData {
            ty: TL_LAST_ADMIN_UNLOCK,
            contents: vec![1, 0, 0, 0, 0],
        });
        assert_eq!(last_admin_unlock(&p), 0);
        with_unlock(&mut p, 77);
        assert_eq!(last_admin_unlock(&p), 77);
    }
}
