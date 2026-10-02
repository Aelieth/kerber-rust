//! The policy requests of MIT `kadmin.c`: add, modify, delete, get and list.

use std::fmt::Write as _;

use krb5_kdc::Error;

use super::{Session, atoi, texts};
use crate::{PolicyArgs, getdate};

/// The record `kadmin_parse_policy_args` fills; `clear_keysalts` for `-allowedkeysalts -`.
struct PolArgs {
    args: PolicyArgs,
    clear_keysalts: bool,
}

/// A count option's value: C `atoi`, a negative one held as 0 (both fail the same floors).
fn count(v: &str) -> u32 {
    u32::try_from(atoi(v).max(0)).unwrap_or(u32::MAX)
}

/// MIT `kadmin_parse_policy_args` (`kadmin.c:1596-1696`): option and value pairs, then the
/// policy name; `None` after printing what MIT prints there.
fn parse_policy_args(s: &mut Session<'_>, argv: &[String], caller: &str) -> Option<PolArgs> {
    let argc = argv.len();
    let now = getdate::now();
    let mut a = PolicyArgs::default();
    let mut clear_keysalts = false;
    let mut i = 1;
    while i + 1 < argc {
        let opt = argv[i].as_str();
        i += 1;
        if i + 2 > argc {
            return None;
        }
        let v = argv[i].as_str();
        let interval = |s: &mut Session<'_>| match getdate::parse_interval(v, now) {
            Ok(d) => Some(getdate::low32(d)),
            Err(e) => {
                s.io.error(&format!("{e}\n"));
                None
            }
        };
        match opt {
            "-maxlife" => a.pw_max_life = Some(interval(s)?),
            "-minlife" => a.pw_min_life = Some(interval(s)?),
            "-minlength" => a.min_length = Some(count(v)),
            "-minclasses" => a.min_classes = Some(count(v)),
            "-history" => a.history = Some(count(v)),
            "-maxfailure" => a.max_fail = Some(getdate::low32(atoi(v))),
            "-failurecountinterval" => a.pw_failcnt_interval = Some(interval(s)?),
            "-lockoutduration" => a.pw_lockout_duration = Some(interval(s)?),
            "-allowedkeysalts" => {
                if v == "-" {
                    clear_keysalts = true;
                    a.allowed_keysalts = None;
                } else {
                    a.allowed_keysalts = Some(v.to_owned());
                }
            }
            _ => return None,
        }
        i += 1;
    }
    if i + 1 != argc {
        s.io.error(&format!("{caller}: parser lost count!\n"));
        return None;
    }
    argv[i].clone_into(&mut a.name);
    Some(PolArgs {
        args: a,
        clear_keysalts,
    })
}

fn usage(s: &mut Session<'_>, func: &str) {
    for line in texts::addmodpol_usage(func) {
        s.io.error(&line);
    }
}

/// MIT `kadmin_addpol` (`kadmin.c:1711-1729`): the options parsed, then `kadm5_create_policy`.
pub(crate) fn addpol(s: &mut Session<'_>, argv: &[String]) {
    let Some(a) = parse_policy_args(s, argv, "add_policy") else {
        usage(s, "add_policy");
        return;
    };
    let name = a.args.name.clone();
    let done = s.h.mutate(|st, _| {
        let exists = st.policies().contains_key(&a.args.name);
        let pol = crate::kadm5::create_policy_local(exists, &a.args)
            .map_err(|t| Error::InvalidArgument(t.to_owned()))?;
        st.put_policy_and_save(pol)
    });
    if let Err(e) = done {
        s.io.com_err(
            "add_policy",
            Some(&texts::policy_text(&e)),
            &format!("while creating policy \"{name}\"."),
        );
    }
}

/// MIT `kadmin_modpol` (`kadmin.c:1732-1750`): the options parsed, then `kadm5_modify_policy`.
pub(crate) fn modpol(s: &mut Session<'_>, argv: &[String]) {
    let Some(a) = parse_policy_args(s, argv, "modify_policy") else {
        usage(s, "modify_policy");
        return;
    };
    let name = a.args.name.clone();
    let done = s.h.mutate(|st, _| {
        let existing = st
            .policies()
            .get(&a.args.name)
            .cloned()
            .ok_or(Error::NotFound)?;
        let mut pol = crate::kadm5::modify_policy_local(&existing, &a.args)
            .map_err(|t| Error::InvalidArgument(t.to_owned()))?;
        if a.clear_keysalts {
            pol.allowed_keysalts = None;
        }
        st.put_policy_and_save(pol)
    });
    if let Err(e) = done {
        s.io.com_err(
            "modify_policy",
            Some(&texts::policy_text(&e)),
            &format!("while modifying policy \"{name}\"."),
        );
    }
}

/// MIT `kadmin_delpol` (`kadmin.c:1753-1776`): `-force`, else the `yes` question; the error is
/// prefixed `delete_policy:` with its colon, as MIT's `com_err` call spells it.
pub(crate) fn delpol(s: &mut Session<'_>, argv: &[String]) {
    let argc = argv.len();
    if !(argc == 2 || (argc == 3 && argv[1] == "-force")) {
        s.io.error("usage: delete_policy [-force] policy\n");
        return;
    }
    if argc == 2 && !s.io.script_mode {
        s.io.print(&format!(
            "Are you sure you want to delete the policy \"{}\"? (yes/no): ",
            argv[1]
        ));
        let reply = s.io.fgets(5);
        if s.io.interrupted {
            return;
        }
        if reply.as_deref() != Some(b"yes\n".as_slice()) {
            s.io.eprint(&format!("Policy \"{}\" not deleted.\n", argv[1]));
            return;
        }
    }
    let name = argv[argc - 1].clone();
    let done = if name.is_empty() {
        Err("Illegal policy name".to_owned())
    } else {
        s.h.mutate(|st, _| st.delete_policy(&name))
            .map_err(|e| texts::policy_text(&e))
    };
    if let Err(msg) = done {
        s.io.com_err(
            "delete_policy:",
            Some(&msg),
            &format!("while deleting policy \"{name}\""),
        );
    }
}

/// MIT `kadmin_getpol` (`kadmin.c:1779-1822`): the policy, or with `-terse` its fields
/// tab-separated.
pub(crate) fn getpol(s: &mut Session<'_>, argv: &[String]) {
    let argc = argv.len();
    if !(argc == 2 || (argc == 3 && argv[1] == "-terse")) {
        s.io.error("usage: get_policy [-terse] policy\n");
        return;
    }
    let name = &argv[argc - 1];
    let found =
        s.h.refresh()
            .map_err(|e| texts::policy_text(&e))
            .and_then(|()| {
                s.h.store
                    .policies()
                    .get(name)
                    .cloned()
                    .ok_or_else(|| texts::UNK_POLICY.to_owned())
            });
    let p = match found {
        Ok(p) => p,
        Err(msg) => {
            s.io.com_err(
                "get_policy",
                Some(&msg),
                &format!("while retrieving policy \"{name}\"."),
            );
            return;
        }
    };
    let dur = |v: u32| crate::strdur(i64::from(v.cast_signed()));
    let mut o = String::new();
    if argc == 2 {
        let _ = writeln!(o, "Policy: {}", p.name);
        let _ = writeln!(o, "Maximum password life: {}", dur(p.pw_max_life));
        let _ = writeln!(o, "Minimum password life: {}", dur(p.pw_min_life));
        let _ = writeln!(o, "Minimum password length: {}", p.min_length);
        let _ = writeln!(
            o,
            "Minimum number of password character classes: {}",
            p.min_classes
        );
        let _ = writeln!(o, "Number of old keys kept: {}", p.history);
        let _ = writeln!(
            o,
            "Maximum password failures before lockout: {}",
            p.max_fail
        );
        let _ = writeln!(
            o,
            "Password failure count reset interval: {}",
            dur(p.pw_failcnt_interval)
        );
        let _ = writeln!(
            o,
            "Password lockout duration: {}",
            dur(p.pw_lockout_duration)
        );
        if let Some(ks) = &p.allowed_keysalts {
            let _ = writeln!(o, "Allowed key/salt types: {ks}");
        }
    } else {
        let _ = writeln!(
            o,
            "\"{}\"\t{}\t{}\t{}\t{}\t{}\t0\t{}\t{}\t{}\t{}",
            p.name,
            p.pw_max_life.cast_signed(),
            p.pw_min_life.cast_signed(),
            p.min_length,
            p.min_classes,
            p.history,
            p.max_fail,
            p.pw_failcnt_interval.cast_signed(),
            p.pw_lockout_duration.cast_signed(),
            p.allowed_keysalts.as_deref().unwrap_or("-")
        );
    }
    s.io.print(&o);
}

/// MIT `kadmin_getpols` (`kadmin.c:1825-1844`): the policy names, sorted, matching the glob.
/// MIT `glob_to_regexp` (`svr_iters.c:55-109`): an empty glob is `^$`, which no name matches.
pub(crate) fn getpols(s: &mut Session<'_>, argv: &[String]) {
    let expr = match argv {
        [_] => None,
        [_, e] => Some(e.as_str()),
        _ => {
            s.io.error("usage: get_policies [expression]\n");
            return;
        }
    };
    if expr.is_some_and(|g| !crate::glob_pattern_ok(g)) {
        s.io.com_err(
            "get_policies",
            Some("Invalid argument"),
            "while retrieving list.",
        );
        return;
    }
    if let Err(e) = s.h.refresh() {
        s.io.com_err(
            "get_policies",
            Some(&texts::policy_text(&e)),
            "while retrieving list.",
        );
        return;
    }
    let mut out = String::new();
    for n in crate::kadm5::policies_matching(&s.h.store, expr) {
        out.push_str(&n);
        out.push('\n');
    }
    s.io.print(&out);
}
