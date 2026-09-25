//! Policy argument and reply codecs (`kadm_rpc_xdr.c` `xdr_cpol_arg`,
//! `xdr_gpol_ret`) and the `svr_policy.c` validation: mask bits, the
//! password-quality floors and `allowed_keysalts`.

use super::codes::{
    ALL_POLICY_MASK, API_V2, API_V3, API_V4, KADM5_BAD_CLASS, KADM5_BAD_HISTORY,
    KADM5_BAD_KEYSALTS, KADM5_BAD_LENGTH, KADM5_BAD_MASK, KADM5_BAD_MIN_PASS_LIFE,
    KADM5_BAD_POLICY, KADM5_DUP, KADM5_POLICY, KADM5_POLICY_ALLOWED_KEYSALTS,
    KADM5_PW_FAILURE_COUNT_INTERVAL, KADM5_PW_HISTORY_NUM, KADM5_PW_LOCKOUT_DURATION,
    KADM5_PW_MAX_FAILURE, KADM5_PW_MAX_LIFE, KADM5_PW_MIN_CLASSES, KADM5_PW_MIN_LENGTH,
    KADM5_PW_MIN_LIFE, KADM5_UNK_POLICY,
};
use super::xdr::{XdrR, XdrW};
use crate::Error;

pub(super) fn parse_policy_name(args: &[u8]) -> Result<(u32, String), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    Ok((api, r.nullstring()?.unwrap_or_default()))
}

pub(super) fn parse_gpols(args: &[u8]) -> (u32, Option<String>) {
    let mut r = XdrR::new(args);
    let api = r.u32().unwrap_or(API_V2);
    (api, r.nullstring().ok().flatten())
}

/// MIT `_xdr_kadm5_policy_ent_rec` (`kadm_rpc_xdr.c:507-514`): lockout fields are present only at API version 3 or later.
/// Allowed keysalts are read only at version 4 or later, so an older argument's mask is not consumed as a lockout field.
pub(super) fn parse_policy_arg(args: &[u8]) -> Result<(u32, krb5_kdc::NamedPolicy, u32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let name = r.nullstring()?.unwrap_or_default();
    let min_life = r.u32().unwrap_or(0);
    let max_life = r.u32().unwrap_or(0);
    let min_length = r.u32().unwrap_or(0);
    let min_classes = r.u32().unwrap_or(0);
    let history = r.u32().unwrap_or(0);
    let _refcnt = r.u32().unwrap_or(0);
    let mut max_fail = 0;
    let mut pw_failcnt_interval = 0;
    let mut pw_lockout_duration = 0;
    let mut allowed_keysalts = None;
    if api >= API_V3 {
        max_fail = r.u32().unwrap_or(0);
        pw_failcnt_interval = r.u32().unwrap_or(0);
        pw_lockout_duration = r.u32().unwrap_or(0);
    }
    if api >= API_V4 {
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        allowed_keysalts = r.nullstring().ok().flatten().filter(|s| !s.is_empty());
        let _n_tl = r.u32().unwrap_or(0);
        let tl_null = r.u32().unwrap_or(1);
        if tl_null == 0 {
            loop {
                let more = r.u32().unwrap_or(0);
                if more == 0 {
                    break;
                }
                let _ = r.u32();
                let _ = r.opaque();
            }
        }
    }
    let mask = r.u32().unwrap_or(0);
    Ok((
        api,
        krb5_kdc::NamedPolicy {
            name,
            min_length,
            min_classes,
            history,
            max_fail,
            pw_failcnt_interval,
            pw_lockout_duration,
            pw_min_life: min_life,
            pw_max_life: max_life,
            allowed_keysalts,
        },
        mask,
    ))
}

pub(super) fn merge_policy(
    mut existing: krb5_kdc::NamedPolicy,
    rec: &krb5_kdc::NamedPolicy,
    mask: u32,
) -> krb5_kdc::NamedPolicy {
    if mask & KADM5_PW_MIN_LIFE != 0 {
        existing.pw_min_life = rec.pw_min_life;
    }
    if mask & KADM5_PW_MAX_LIFE != 0 {
        existing.pw_max_life = rec.pw_max_life;
    }
    if mask & KADM5_PW_MIN_LENGTH != 0 {
        existing.min_length = rec.min_length;
    }
    if mask & KADM5_PW_MIN_CLASSES != 0 {
        existing.min_classes = rec.min_classes;
    }
    if mask & KADM5_PW_HISTORY_NUM != 0 {
        existing.history = rec.history;
    }
    if mask & KADM5_PW_MAX_FAILURE != 0 {
        existing.max_fail = rec.max_fail;
    }
    if mask & KADM5_PW_FAILURE_COUNT_INTERVAL != 0 {
        existing.pw_failcnt_interval = rec.pw_failcnt_interval;
    }
    if mask & KADM5_PW_LOCKOUT_DURATION != 0 {
        existing.pw_lockout_duration = rec.pw_lockout_duration;
    }
    if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0 {
        existing.allowed_keysalts.clone_from(&rec.allowed_keysalts);
    }
    existing
}

const MIN_PW_LENGTH: u32 = 1;
const MIN_PW_CLASSES: u32 = 1;
const MAX_PW_CLASSES: u32 = 5;
const MIN_PW_HISTORY: u32 = 1;

/// MIT `kadm_err.et` text for a policy validation code (kadmin.local `com_err`).
pub(crate) fn policy_text(code: u32) -> &'static str {
    match code {
        KADM5_DUP => "Principal or policy already exists",
        KADM5_UNK_POLICY => "Policy does not exist",
        KADM5_BAD_POLICY => "Illegal policy name",
        KADM5_BAD_MIN_PASS_LIFE => "Password minimum life is greater than password maximum life",
        KADM5_BAD_LENGTH => "Invalid password length",
        KADM5_BAD_CLASS => "Invalid number of character classes",
        KADM5_BAD_HISTORY => "Invalid password history count",
        KADM5_BAD_KEYSALTS => "Invalid key/salt tuples",
        _ => "Operation failed",
    }
}

/// MIT `validate_allowed_keysalts` (`svr_policy.c:22-36`): a tab is
/// `KADM5_BAD_KEYSALTS`. `krb5_string_to_keysalts` skips unknown tokens
/// and only fails ENOMEM, so `addpol -allowedkeysalts bogus:normal`
/// succeeds on MIT 1.22.2 (live settle).
pub(super) fn validate_allowed_keysalts(allowed: Option<&str>) -> Option<u32> {
    let s = allowed.filter(|s| !s.is_empty())?;
    if s.contains('\t') {
        return Some(KADM5_BAD_KEYSALTS);
    }
    None
}

/// Build an `osa_policy_ent` and its mask from CLI `PolicyArgs`.
pub(crate) fn build_policy(a: &crate::PolicyArgs) -> (krb5_kdc::NamedPolicy, u32) {
    let mut p = krb5_kdc::NamedPolicy::new(&a.name);
    let mut mask = 0u32;
    if let Some(v) = a.pw_max_life {
        p.pw_max_life = v;
        mask |= KADM5_PW_MAX_LIFE;
    }
    if let Some(v) = a.pw_min_life {
        p.pw_min_life = v;
        mask |= KADM5_PW_MIN_LIFE;
    }
    if let Some(v) = a.min_length {
        p.min_length = v;
        mask |= KADM5_PW_MIN_LENGTH;
    }
    if let Some(v) = a.min_classes {
        p.min_classes = v;
        mask |= KADM5_PW_MIN_CLASSES;
    }
    if let Some(v) = a.history {
        p.history = v;
        mask |= KADM5_PW_HISTORY_NUM;
    }
    if let Some(v) = a.max_fail {
        p.max_fail = v;
        mask |= KADM5_PW_MAX_FAILURE;
    }
    if let Some(v) = a.pw_failcnt_interval {
        p.pw_failcnt_interval = v;
        mask |= KADM5_PW_FAILURE_COUNT_INTERVAL;
    }
    if let Some(v) = a.pw_lockout_duration {
        p.pw_lockout_duration = v;
        mask |= KADM5_PW_LOCKOUT_DURATION;
    }
    if a.allowed_keysalts.is_some() {
        p.allowed_keysalts.clone_from(&a.allowed_keysalts);
        mask |= KADM5_POLICY_ALLOWED_KEYSALTS;
    }
    (p, mask)
}

/// `kadm5_create_policy` for kadmin.local: DUP -> name -> min>max -> length ->
/// MIT `com_err` (`com_err.c:131-140`): classes -> history (`svr_policy.c`). Returns the text on failure.
pub(crate) fn create_policy_local(
    exists: bool,
    a: &crate::PolicyArgs,
) -> Result<krb5_kdc::NamedPolicy, &'static str> {
    let (mut pol, mask) = build_policy(a);
    if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
        && let Some(code) = validate_allowed_keysalts(pol.allowed_keysalts.as_deref())
    {
        return Err(policy_text(code));
    }
    if exists {
        return Err(policy_text(KADM5_DUP));
    }
    if let Some(code) = policy_name_err(&a.name) {
        return Err(policy_text(code));
    }
    if let Some(code) = policy_floor_err(&pol, mask) {
        return Err(policy_text(code));
    }
    apply_policy_floors(&mut pol, mask);
    Ok(pol)
}

/// `kadm5_modify_policy` for kadmin.local: merge the masked fields onto the
/// existing policy, then the same floor checks (no name check).
pub(crate) fn modify_policy_local(
    existing: &krb5_kdc::NamedPolicy,
    a: &crate::PolicyArgs,
) -> Result<krb5_kdc::NamedPolicy, &'static str> {
    let (rec, mask) = build_policy(a);
    if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
        && let Some(code) = validate_allowed_keysalts(rec.allowed_keysalts.as_deref())
    {
        return Err(policy_text(code));
    }
    let merged = merge_policy(existing.clone(), &rec, mask);
    if let Some(code) = policy_floor_err(&merged, mask) {
        return Err(policy_text(code));
    }
    Ok(merged)
}

pub(crate) fn policy_name_err(name: &str) -> Option<u32> {
    if name.is_empty() || name.bytes().any(|b| !(b' '..=b'~').contains(&b)) {
        return Some(KADM5_BAD_POLICY);
    }
    None
}

pub(super) fn policy_mask_err(mask: u32, create: bool) -> Option<u32> {
    if mask & !ALL_POLICY_MASK != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if create {
        if mask & KADM5_POLICY == 0 {
            return Some(KADM5_BAD_MASK);
        }
    } else if mask & KADM5_POLICY != 0 {
        return Some(KADM5_BAD_MASK);
    }
    None
}

pub(crate) fn policy_floor_err(pol: &krb5_kdc::NamedPolicy, mask: u32) -> Option<u32> {
    if mask & KADM5_PW_MIN_LIFE != 0 && pol.pw_min_life > pol.pw_max_life && pol.pw_max_life != 0 {
        return Some(KADM5_BAD_MIN_PASS_LIFE);
    }
    if mask & KADM5_PW_MIN_LENGTH != 0 && pol.min_length < MIN_PW_LENGTH {
        return Some(KADM5_BAD_LENGTH);
    }
    if mask & KADM5_PW_MIN_CLASSES != 0
        && (pol.min_classes < MIN_PW_CLASSES || pol.min_classes > MAX_PW_CLASSES)
    {
        return Some(KADM5_BAD_CLASS);
    }
    if mask & KADM5_PW_HISTORY_NUM != 0 && pol.history < MIN_PW_HISTORY {
        return Some(KADM5_BAD_HISTORY);
    }
    None
}

pub(crate) fn apply_policy_floors(pol: &mut krb5_kdc::NamedPolicy, mask: u32) {
    if mask & KADM5_PW_MIN_LENGTH == 0 {
        pol.min_length = MIN_PW_LENGTH;
    }
    if mask & KADM5_PW_MIN_CLASSES == 0 {
        pol.min_classes = MIN_PW_CLASSES;
    }
    if mask & KADM5_PW_HISTORY_NUM == 0 {
        pol.history = MIN_PW_HISTORY;
    }
}

pub(super) fn encode_policy_rec(w: &mut XdrW, api: u32, p: &krb5_kdc::NamedPolicy) {
    w.nullstring(Some(&p.name));
    w.u32(p.pw_min_life);
    w.u32(p.pw_max_life);
    w.u32(p.min_length);
    w.u32(p.min_classes);
    w.u32(p.history);
    w.u32(0);
    if api >= API_V3 {
        w.u32(p.max_fail);
        w.u32(p.pw_failcnt_interval);
        w.u32(p.pw_lockout_duration);
    }
    if api >= API_V4 {
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.nullstring(p.allowed_keysalts.as_deref());
        w.u32(0);
        w.u32(1);
    }
}

pub(super) fn encode_policy(api: u32, p: &krb5_kdc::NamedPolicy) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    encode_policy_rec(&mut w, api, p);
    w.b
}

pub(super) fn encode_pols(api: u32, names: &[String]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    let n = u32::try_from(names.len()).unwrap_or(0);
    w.u32(n);
    w.u32(n);
    for name in names {
        w.nullstring(Some(name));
    }
    w.b
}
