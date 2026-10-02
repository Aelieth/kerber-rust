//! The principal requests of MIT `kadmin.c`: add, delete, modify, rename, alias, change the
//! password, get, list, purge keys, string attributes, privileges and the database lock.

use std::fmt::Write as _;

use krb5_crypto::EncryptionType;
use krb5_kdc::{AdminEnt, AdminFields, Error, PrincipalStore, PrincipalWrite as _};
use krb5_types::PrincipalName;
use zeroize::Zeroizing;

use super::{Session, string_to_keysalts, texts};
use crate::getdate;

/// The kadm5 mask bits (`admin.h`) the principal requests set.
mod mask {
    pub(super) const PRINCIPAL: u32 = 0x0000_0001;
    pub(super) const PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
    pub(super) const PW_EXPIRATION: u32 = 0x0000_0004;
    pub(super) const ATTRIBUTES: u32 = 0x0000_0010;
    pub(super) const MAX_LIFE: u32 = 0x0000_0020;
    pub(super) const KVNO: u32 = 0x0000_0100;
    pub(super) const POLICY: u32 = 0x0000_0800;
    pub(super) const POLICY_CLR: u32 = 0x0000_1000;
    pub(super) const MAX_RLIFE: u32 = 0x0000_2000;
    pub(super) const FAIL_AUTH_COUNT: u32 = 0x0001_0000;
    pub(super) const KEY_DATA: u32 = 0x0002_0000;
    pub(super) const TL_DATA: u32 = 0x0004_0000;
}

/// The record `kadmin_parse_princ_args` fills.
#[derive(Default)]
struct PrincArgs {
    mask: u32,
    attributes: u32,
    max_life: u32,
    max_rlife: u32,
    princ_expire_time: u32,
    pw_expiration: u32,
    kvno: u32,
    policy: Option<String>,
    pass: Option<String>,
    randkey: bool,
    nokey: bool,
    unlock: bool,
    keysalts: Vec<EncryptionType>,
    db_args: Vec<String>,
    name: Option<(PrincipalName, String)>,
}

/// MIT `krb5_flagspec_to_mask` (`kadm5/str_conv.c:171-197`): a `+`, `-` or unsigned attribute
/// name, or a `0x` number, set or cleared on `attributes`; `None` for any other word.
fn flagspec(spec: &str, attributes: u32) -> Option<u32> {
    let signed = if spec.starts_with(['+', '-']) {
        spec.to_owned()
    } else {
        format!("+{spec}")
    };
    let (set, clear) = krb5_kdc::kadmin_flagspec(&signed)?;
    Some((attributes | set) & !clear)
}

/// MIT `kadmin_parse_princ_args` (`kadmin.c:1048-1179`): the options before the last word,
/// which is the principal. `None` after printing what MIT prints there; the caller then prints
/// its usage.
fn parse_princ_args(
    s: &mut Session<'_>,
    argv: &[String],
    attributes: u32,
    caller: &str,
) -> Option<PrincArgs> {
    let argc = argv.len();
    let now = getdate::now();
    let mut a = PrincArgs {
        attributes,
        ..PrincArgs::default()
    };
    let mut i = 1;
    while i + 1 < argc {
        let value = |i: &mut usize| -> Option<String> {
            *i += 1;
            (*i + 2 <= argc).then(|| argv[*i].clone())
        };
        match argv[i].as_str() {
            "-x" => {
                a.db_args.push(value(&mut i)?);
                a.mask |= mask::TL_DATA;
            }
            "-expire" => {
                a.princ_expire_time = date(s, &value(&mut i)?, now)?;
                a.mask |= mask::PRINC_EXPIRE_TIME;
            }
            "-pwexpire" => {
                a.pw_expiration = date(s, &value(&mut i)?, now)?;
                a.mask |= mask::PW_EXPIRATION;
            }
            "-maxlife" => {
                a.max_life = interval(s, &value(&mut i)?, now)?;
                a.mask |= mask::MAX_LIFE;
            }
            "-maxrenewlife" => {
                a.max_rlife = interval(s, &value(&mut i)?, now)?;
                a.mask |= mask::MAX_RLIFE;
            }
            "-kvno" => {
                a.kvno = getdate::low32(super::atoi(&value(&mut i)?));
                a.mask |= mask::KVNO;
            }
            "-policy" => {
                a.policy = Some(value(&mut i)?);
                a.mask |= mask::POLICY;
            }
            "-clearpolicy" => {
                a.policy = None;
                a.mask |= mask::POLICY_CLR;
            }
            "-pw" => a.pass = Some(value(&mut i)?),
            "-randkey" => a.randkey = true,
            "-nokey" => a.nokey = true,
            "-unlock" => {
                a.unlock = true;
                a.mask |= mask::FAIL_AUTH_COUNT | mask::TL_DATA;
            }
            "-e" => a.keysalts = string_to_keysalts(&value(&mut i)?, &[',', ' ', '\t']),
            other => {
                a.attributes = flagspec(other, a.attributes)?;
                a.mask |= mask::ATTRIBUTES;
            }
        }
        i += 1;
    }
    if i + 1 != argc {
        return None;
    }
    match s.h.parse_name(&argv[i]) {
        Ok(n) => a.name = Some(n),
        Err(msg) => {
            s.io.com_err(caller, Some(msg), "while parsing principal");
            return None;
        }
    }
    Some(a)
}

/// MIT `parse_date` (`kadmin.c:158-166`): the date as a 32-bit `krb5_timestamp`.
fn date(s: &mut Session<'_>, spec: &str, now: i64) -> Option<u32> {
    match getdate::parse_date(spec, now) {
        Ok(d) => Some(getdate::low32(d)),
        Err(e) => {
            s.io.error(&format!("{e}\n"));
            None
        }
    }
}

/// MIT `parse_interval` (`kadmin.c:174-197`): the interval as a 32-bit `krb5_deltat`.
fn interval(s: &mut Session<'_>, spec: &str, now: i64) -> Option<u32> {
    match getdate::parse_interval(spec, now) {
        Ok(d) => Some(getdate::low32(d)),
        Err(e) => {
            s.io.error(&format!("{e}\n"));
            None
        }
    }
}

fn usage(s: &mut Session<'_>, lines: &[&str]) {
    for line in lines {
        s.io.error(line);
    }
}

/// MIT `policy_exists` (`kadmin.c:277-285`): whether `kadm5_get_policy` finds the name.
fn policy_exists(s: &mut Session<'_>, name: &str) -> bool {
    let _ = s.h.refresh();
    s.h.store.policies().contains_key(name)
}

/// MIT `kadmin_addprinc` (`kadmin.c:1242-1362`): the policy notice, the password (asked twice
/// when none is given), the create, `Principal "…" created.`.
pub(crate) fn addprinc(s: &mut Session<'_>, argv: &[String]) {
    let Some(mut a) = parse_princ_args(s, argv, 0, "add_principal") else {
        usage(s, &texts::ADDPRINC_USAGE);
        return;
    };
    let Some((name, realm)) = a.name.clone() else {
        return;
    };
    let canon = name.unparse_with_realm(&realm);
    if a.mask & mask::POLICY != 0 {
        let policy = a.policy.clone().unwrap_or_default();
        if !s.io.script_mode && !policy_exists(s, &policy) {
            s.io.eprint(&format!("WARNING: policy \"{policy}\" does not exist\n"));
        }
    } else if a.mask & mask::POLICY_CLR == 0 {
        if policy_exists(s, "default") {
            if !s.io.script_mode {
                s.io.eprint(&format!(
                    "No policy specified for {canon}; assigning \"default\"\n"
                ));
            }
            a.policy = Some("default".to_owned());
            a.mask |= mask::POLICY;
        } else if !s.io.script_mode {
            s.io.eprint(&format!(
                "No policy specified for {canon}; defaulting to no policy\n"
            ));
        }
    }
    a.mask &= !mask::POLICY_CLR;
    let pass: Option<Zeroizing<Vec<u8>>> = if a.nokey {
        a.mask |= mask::KEY_DATA;
        None
    } else if a.randkey {
        None
    } else if let Some(p) = a.pass.take() {
        Some(Zeroizing::new(p.into_bytes()))
    } else {
        match s.io.read_password(
            &format!("Enter password for principal \"{canon}\""),
            Some(&format!("Re-enter password for principal \"{canon}\"")),
        ) {
            Ok(pw) => Some(pw),
            Err(e) => {
                s.io.com_err(
                    "add_principal",
                    Some(&e.to_string()),
                    &format!("while reading password for \"{canon}\"."),
                );
                return;
            }
        }
    };
    a.mask |= mask::PRINCIPAL;
    let done = s.h.mutate(|st, caller| {
        create(
            st,
            caller,
            &a,
            &name,
            &realm,
            pass.as_ref().map(|p| p.as_slice()),
        )
    });
    if let Err(e) = done {
        s.io.com_err(
            "add_principal",
            Some(&texts::princ_text(&e)),
            &format!("while creating \"{canon}\"."),
        );
        return;
    }
    s.io.info(&format!("Principal \"{canon}\" created.\n"));
}

/// MIT `kadm5_create_principal_3` (`svr_principal.c:300-505`): the parsed record created; `-nokey`
/// leaves the entry keyless, and a db2 argument is refused where the entry would be stored.
fn create(
    st: &mut PrincipalStore,
    caller: &str,
    a: &PrincArgs,
    name: &PrincipalName,
    realm: &str,
    pass: Option<&[u8]>,
) -> Result<(), Error> {
    if let Some(arg) = a.db_args.first() {
        if st.get_in_realm(name, realm).is_some() {
            return Err(Error::AlreadyExists);
        }
        if let Some(pw) = pass {
            st.check_new_password(name, a.policy.as_deref(), pw)?;
        }
        return Err(db2_put_refused(arg));
    }
    let ent = AdminEnt {
        mask: a.mask,
        attributes: a.attributes,
        max_life: a.max_life,
        max_renewable_life: a.max_rlife,
        princ_expire_time: a.princ_expire_time,
        pw_expiration: a.pw_expiration,
        kvno: a.kvno,
        policy: a.policy.clone(),
    };
    st.create_principal_3_in(name, realm, pass, &a.keysalts, &ent, caller)?;
    if a.nokey {
        st.purgekeys_in(name, realm, i32::MAX, caller)?;
    }
    Ok(())
}

/// MIT `krb5_db2_put_principal` (`kdb_db2.c:812-822`): the db2 module takes no per-principal
/// argument.
fn db2_put_refused(arg: &str) -> Error {
    Error::InvalidArgument(format!("Unsupported argument \"{arg}\" for db2"))
}

/// MIT `kadmin_modprinc` (`kadmin.c:1365-1435`): the entry is read first, the options apply to
/// its attributes, `Principal "…" modified.`.
pub(crate) fn modprinc(s: &mut Session<'_>, argv: &[String]) {
    let argc = argv.len();
    if argc < 2 {
        usage(s, &texts::MODPRINC_USAGE);
        return;
    }
    let (name, realm) = match s.h.parse_name(&argv[argc - 1]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err("modify_principal", Some(msg), "while parsing principal");
            return;
        }
    };
    let canon = name.unparse_with_realm(&realm);
    let old =
        s.h.refresh()
            .map_err(|e| texts::princ_text(&e))
            .and_then(|()| {
                s.h.store
                    .get_in_realm(&name, &realm)
                    .map(|p| (p.attributes, p.pw_policy.is_some()))
                    .ok_or_else(|| texts::UNK_PRINC.to_owned())
            });
    let (attributes, had_policy) = match old {
        Ok(v) => v,
        Err(msg) => {
            s.io.com_err(
                "modify_principal",
                Some(&msg),
                &format!("while getting \"{canon}\"."),
            );
            return;
        }
    };
    let a = parse_princ_args(s, argv, attributes, "modify_principal");
    let Some(a) = a.filter(|a| a.keysalts.is_empty() && !a.randkey && !a.nokey && a.pass.is_none())
    else {
        usage(s, &texts::MODPRINC_USAGE);
        return;
    };
    if a.mask & mask::POLICY != 0 {
        let policy = a.policy.clone().unwrap_or_default();
        if !s.io.script_mode && !policy_exists(s, &policy) {
            s.io.eprint(&format!("WARNING: policy \"{policy}\" does not exist\n"));
        }
    }
    if a.mask != 0 {
        let done =
            s.h.mutate(|st, caller| modify(st, caller, &a, &name, &realm, had_policy));
        if let Err(e) = done {
            s.io.com_err(
                "modify_principal",
                Some(&texts::princ_text(&e)),
                &format!("while modifying \"{canon}\"."),
            );
            return;
        }
    }
    s.io.info(&format!("Principal \"{canon}\" modified.\n"));
}

/// MIT `kadm5_modify_principal` (`svr_principal.c:556-690`): the parsed record applied, one store
/// write for every field.
fn modify(
    st: &mut PrincipalStore,
    caller: &str,
    a: &PrincArgs,
    name: &PrincipalName,
    realm: &str,
    had_policy: bool,
) -> Result<(), Error> {
    let mut entry = st
        .get_in_realm(name, realm)
        .cloned()
        .ok_or(Error::NotFound)?;
    if let Some(arg) = a.db_args.first() {
        return Err(db2_put_refused(arg));
    }
    if a.mask & mask::KVNO != 0 {
        for k in &mut entry.keys {
            k.kvno = a.kvno & 0xffff;
        }
        st.put_principal(entry)?;
    }
    if a.unlock {
        st.admin_unlock_in(name, realm, caller)?;
    }
    let set = |bit: u32| a.mask & bit != 0;
    st.apply_admin_fields_in(
        name,
        realm,
        AdminFields {
            attributes: set(mask::ATTRIBUTES).then_some(a.attributes),
            max_life: set(mask::MAX_LIFE).then_some(u64::from(a.max_life)),
            expiration: set(mask::PRINC_EXPIRE_TIME).then_some(a.princ_expire_time),
            pw_expire: set(mask::PW_EXPIRATION).then_some(a.pw_expiration),
            policy: if set(mask::POLICY) {
                a.policy.clone()
            } else {
                None
            },
            clear_policy: set(mask::POLICY_CLR) && had_policy,
            max_renewable_life: set(mask::MAX_RLIFE).then_some(u64::from(a.max_rlife)),
        },
        caller,
    )
}

/// MIT `kadmin_delprinc` (`kadmin.c:666-711`): `-force`, else the `yes` question.
pub(crate) fn delprinc(s: &mut Session<'_>, argv: &[String]) {
    let argc = argv.len();
    if !(argc == 2 || (argc == 3 && argv[1] == "-force")) {
        s.io.error("usage: delete_principal [-force] principal\n");
        return;
    }
    let (name, realm) = match s.h.parse_name(&argv[argc - 1]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err(
                "delete_principal",
                Some(msg),
                "while parsing principal name",
            );
            return;
        }
    };
    let canon = name.unparse_with_realm(&realm);
    if argc == 2 && !s.io.script_mode {
        s.io.print(&format!(
            "Are you sure you want to delete the principal \"{canon}\"? (yes/no): "
        ));
        if s.io.fgets(5).as_deref() != Some(b"yes\n".as_slice()) {
            s.io.eprint(&format!("Principal \"{canon}\" not deleted\n"));
            return;
        }
    }
    let done = if s.h.is_master(&name, &realm) {
        Err(texts::PROTECT_PRINCIPAL.to_owned())
    } else {
        s.h.mutate(|st, _| st.remove_in(&name, &realm))
            .map_err(|e| texts::princ_text(&e))
    };
    if let Err(msg) = done {
        s.io.com_err(
            "delete_principal",
            Some(&msg),
            &format!("while deleting principal \"{canon}\""),
        );
        return;
    }
    s.io.info(&format!("Principal \"{canon}\" deleted.\n"));
    s.io.info("Make sure that you have removed this principal from all ACLs before reusing.\n");
}

/// MIT `kadmin_renameprinc` (`kadmin.c:714-775`): `-force`, else the `yes` question.
pub(crate) fn renprinc(s: &mut Session<'_>, argv: &[String]) {
    let argc = argv.len();
    if !(argc == 3 || (argc == 4 && argv[1] == "-force")) {
        s.io.error("usage: rename_principal [-force] old_principal new_principal\n");
        return;
    }
    let (old, old_realm) = match s.h.parse_name(&argv[argc - 2]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err(
                "rename_principal",
                Some(msg),
                "while parsing old principal name",
            );
            return;
        }
    };
    let (new, new_realm) = match s.h.parse_name(&argv[argc - 1]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err(
                "rename_principal",
                Some(msg),
                "while parsing new principal name",
            );
            return;
        }
    };
    let ocanon = old.unparse_with_realm(&old_realm);
    let ncanon = new.unparse_with_realm(&new_realm);
    if argc == 3 && !s.io.script_mode {
        s.io.print(&format!(
            "Are you sure you want to rename the principal \"{ocanon}\" to \"{ncanon}\"? \
             (yes/no): "
        ));
        if s.io.fgets(5).as_deref() != Some(b"yes\n".as_slice()) {
            s.io.eprint(&format!("Principal \"{ocanon}\" not renamed\n"));
            return;
        }
    }
    let done =
        s.h.mutate(|st, caller| st.rename_unchecked(&old, &old_realm, &new, &new_realm, caller));
    if let Err(e) = done {
        let msg = match e {
            Error::NotFound => texts::NOENTRY.to_owned(),
            other => texts::princ_text(&other),
        };
        s.io.com_err(
            "rename_principal",
            Some(&msg),
            &format!("while renaming principal \"{ocanon}\" to \"{ncanon}\""),
        );
        return;
    }
    s.io.info(&format!(
        "Principal \"{ocanon}\" renamed to \"{ncanon}\".\n"
    ));
    s.io.info("Make sure that you have removed the old principal from all ACLs before reusing.\n");
}

/// MIT `kadmin_addalias` (`kadmin.c:778-824`): `Principal "…" aliased to "…".`
pub(crate) fn addalias(s: &mut Session<'_>, argv: &[String]) {
    if argv.len() != 3 {
        s.io.error("usage: add_alias alias_principal target_principal\n");
        return;
    }
    let (alias, arealm) = match s.h.parse_name(&argv[1]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err("add_alias", Some(msg), "while parsing alias principal name");
            return;
        }
    };
    let (target, trealm) = match s.h.parse_name(&argv[2]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err(
                "add_alias",
                Some(msg),
                "while parsing target principal name",
            );
            return;
        }
    };
    let acanon = alias.unparse_with_realm(&arealm);
    let tcanon = target.unparse_with_realm(&trealm);
    let done =
        s.h.mutate(|st, caller| st.create_alias_in(&alias, &arealm, &target, &trealm, caller));
    if let Err(e) = done {
        s.io.com_err(
            "add_alias",
            Some(&texts::princ_text(&e)),
            &format!("while aliasing principal \"{acanon}\" to \"{tcanon}\""),
        );
        return;
    }
    s.io.info(&format!(
        "Principal \"{acanon}\" aliased to \"{tcanon}\".\n"
    ));
}

/// MIT `cpw_usage` (`kadmin.c:827-833`): the message when given, then the usage line.
fn cpw_usage(s: &mut Session<'_>, msg: Option<&str>) {
    if let Some(m) = msg {
        s.io.error(&format!("{m}\n"));
    }
    s.io.error(texts::CPW_USAGE);
}

/// MIT `kadmin_cpw` (`kadmin.c:836-973`): `-pw`, `-randkey`, or the password asked twice;
/// `-keepold` and `-e` as given.
pub(crate) fn cpw(s: &mut Session<'_>, argv: &[String]) {
    let mut rest = argv.get(1..).unwrap_or_default();
    let mut pwarg: Option<String> = None;
    let mut randkey = false;
    let mut keepold = false;
    let mut keysalts = Vec::new();
    while let Some(opt) = rest.first().filter(|a| a.starts_with('-')) {
        match opt.as_str() {
            "-x" | "-pw" | "-e" => {
                let Some(v) = rest.get(1) else {
                    let what = match opt.as_str() {
                        "-x" => "missing db argument",
                        "-pw" => "missing password arg",
                        _ => "missing keysaltlist arg",
                    };
                    cpw_usage(s, Some(&format!("change_password: {what}")));
                    return;
                };
                if opt == "-pw" {
                    pwarg = Some(v.clone());
                } else if opt == "-e" {
                    keysalts = string_to_keysalts(v, &[',', ' ', '\t']);
                }
                rest = &rest[1..];
            }
            "-randkey" => randkey = true,
            "-keepold" => keepold = true,
            _ => {
                s.io.com_err(
                    "change_password",
                    None,
                    &format!("unrecognized option {opt}"),
                );
                cpw_usage(s, None);
                return;
            }
        }
        rest = &rest[1..];
    }
    if rest.len() != 1 {
        let what = if rest.is_empty() {
            "missing principal name"
        } else {
            "too many arguments"
        };
        s.io.com_err("change_password", None, what);
        cpw_usage(s, None);
        return;
    }
    let (name, realm) = match s.h.parse_name(&rest[0]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err("change_password", Some(msg), "while parsing principal name");
            return;
        }
    };
    let canon = name.unparse_with_realm(&realm);
    let keep = u32::from(keepold);
    if pwarg.is_none() && randkey {
        let done = s.h.mutate(|st, caller| {
            st.chrand_etypes_keepold_in(&name, &realm, &keysalts, keep, caller)
                .map(|_| ())
        });
        if let Err(e) = done {
            s.io.com_err(
                "change_password",
                Some(&texts::princ_text(&e)),
                &format!("while randomizing key for \"{canon}\"."),
            );
            return;
        }
        s.io.info(&format!("Key for \"{canon}\" randomized.\n"));
        return;
    }
    let pw = match pwarg {
        Some(p) => Zeroizing::new(p.into_bytes()),
        None => match s.io.read_password(
            &format!("Enter password for principal \"{canon}\""),
            Some(&format!("Re-enter password for principal \"{canon}\"")),
        ) {
            Ok(pw) => pw,
            Err(e) => {
                s.io.com_err(
                    "change_password",
                    Some(&e.to_string()),
                    &format!("while reading password for \"{canon}\"."),
                );
                return;
            }
        },
    };
    let done = s.h.mutate(|st, caller| {
        st.set_password_etypes_keepold_n_in(&name, &realm, &pw, keep, caller, &keysalts)
    });
    if let Err(e) = done {
        s.io.com_err(
            "change_password",
            Some(&texts::princ_text(&e)),
            &format!("while changing password for \"{canon}\"."),
        );
        return;
    }
    s.io.info(&format!("Password for \"{canon}\" changed.\n"));
}

/// MIT `kadmin_getprinc` (`kadmin.c:1438-1571`): the record, or with `-terse` its fields
/// tab-separated.
pub(crate) fn getprinc(s: &mut Session<'_>, argv: &[String]) {
    let argc = argv.len();
    if !(argc == 2 || (argc == 3 && argv[1] == "-terse")) {
        s.io.error("usage: get_principal [-terse] principal\n");
        return;
    }
    let (name, realm) = match s.h.parse_name(&argv[argc - 1]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err("get_principal", Some(msg), "while parsing principal");
            return;
        }
    };
    let canon = name.unparse_with_realm(&realm);
    let found =
        s.h.refresh()
            .map_err(|e| texts::princ_text(&e))
            .and_then(|()| {
                s.h.store
                    .get_in_realm(&name, &realm)
                    .cloned()
                    .ok_or_else(|| texts::UNK_PRINC.to_owned())
            });
    let p = match found {
        Ok(p) => p,
        Err(msg) => {
            s.io.com_err(
                "get_principal",
                Some(&msg),
                &format!("while retrieving \"{canon}\"."),
            );
            return;
        }
    };
    let policy_missing = p
        .pw_policy
        .as_deref()
        .is_some_and(|pol| !s.h.store.policies().contains_key(pol));
    let text = if argc == 2 {
        super::show::principal(&p, policy_missing)
    } else {
        super::show::principal_terse(&p)
    };
    s.io.print(&text);
}

/// MIT `kadmin_getprincs` (`kadmin.c:1574-1593`): the names, sorted, that match the glob (the
/// realm free when the glob names none).
pub(crate) fn getprincs(s: &mut Session<'_>, argv: &[String]) {
    let expr = match argv {
        [_] => None,
        [_, e] => Some(e.as_str()),
        _ => {
            s.io.error("usage: get_principals [expression]\n");
            return;
        }
    };
    if expr.is_some_and(|g| !crate::glob_pattern_ok(g)) {
        s.io.com_err(
            "get_principals",
            Some("Invalid argument"),
            "while retrieving list.",
        );
        return;
    }
    if let Err(e) = s.h.refresh() {
        s.io.com_err(
            "get_principals",
            Some(&texts::princ_text(&e)),
            "while retrieving list.",
        );
        return;
    }
    let pattern = expr
        .filter(|g| *g != "*" && !g.is_empty())
        .map(|g| crate::kadm5::glob_expand(g, true));
    let mut out = String::new();
    for id in s.h.store.ids() {
        if pattern
            .as_deref()
            .is_none_or(|pat| crate::kadm5::glob_is_match(pat.as_bytes(), id.as_bytes()))
        {
            out.push_str(&id);
            out.push('\n');
        }
    }
    s.io.print(&out);
}

/// MIT `kadmin_getprivs` (`kadmin.c:1847-1869`): `kadmin.local` holds every privilege.
pub(crate) fn getprivs(s: &mut Session<'_>, argv: &[String]) {
    if argv.len() != 1 {
        s.io.error("usage: get_privs\n");
        return;
    }
    s.io.print("current privileges: INQUIRE ADD MODIFY DELETE\n");
}

/// MIT `kadmin_purgekeys` (`kadmin.c:1872-1921`): keep the newest keys, `-keepkvno N` and
/// newer, or (`-all`) none.
pub(crate) fn purgekeys(s: &mut Session<'_>, argv: &[String]) {
    let (keepkvno, pname) = match argv {
        [_, opt, kvno, p] if opt == "-keepkvno" => {
            (i32::try_from(super::atoi(kvno)).unwrap_or(-1), p)
        }
        [_, opt, p] if opt == "-all" => (i32::MAX, p),
        [_, p] => (-1, p),
        _ => {
            s.io.error("usage: purgekeys [-all|-keepkvno oldest_kvno_to_keep] principal\n");
            return;
        }
    };
    let (name, realm) = match s.h.parse_name(pname) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err("purgekeys", Some(msg), "while parsing principal");
            return;
        }
    };
    let canon = name.unparse_with_realm(&realm);
    let done =
        s.h.mutate(|st, caller| st.purgekeys_in(&name, &realm, keepkvno, caller));
    if let Err(e) = done {
        s.io.com_err(
            "purgekeys",
            Some(&texts::princ_text(&e)),
            &format!("while purging keys for principal \"{canon}\""),
        );
        return;
    }
    if keepkvno == i32::MAX {
        s.io.info(&format!("All keys for principal \"{canon}\" removed.\n"));
    } else {
        s.io.info(&format!("Old keys for principal \"{canon}\" purged.\n"));
    }
}

/// MIT `kadmin_getstrings` (`kadmin.c:1924-1967`): `key: value` lines, or `(No string attributes.)`.
pub(crate) fn getstrings(s: &mut Session<'_>, argv: &[String]) {
    if argv.len() != 2 {
        s.io.error("usage: get_strings principal\n");
        return;
    }
    let (name, realm) = match s.h.parse_name(&argv[1]) {
        Ok(n) => n,
        Err(msg) => {
            s.io.com_err("get_strings", Some(msg), "while parsing principal");
            return;
        }
    };
    let canon = name.unparse_with_realm(&realm);
    let got =
        s.h.refresh()
            .and_then(|()| s.h.store.get_strings_in(&name, &realm));
    match got {
        Ok(strings) if strings.is_empty() => s.io.print("(No string attributes.)\n"),
        Ok(strings) => {
            let mut out = String::new();
            for (k, v) in strings {
                let _ = writeln!(out, "{k}: {v}");
            }
            s.io.print(&out);
        }
        Err(e) => s.io.com_err(
            "get_strings",
            Some(&texts::princ_text(&e)),
            &format!("while getting attributes for principal \"{canon}\""),
        ),
    }
}

/// MIT `kadmin_setstring` (`kadmin.c:1970-2008`): `Attribute set for principal "…".`
pub(crate) fn setstring(s: &mut Session<'_>, argv: &[String]) {
    let [_, pname, key, value] = argv else {
        s.io.error("usage: set_string principal key value\n");
        return;
    };
    set_or_del(s, pname, key, Some(value), "set_string");
}

/// MIT `kadmin_delstring` (`kadmin.c:2011-2048`): `Attribute removed from principal "…".`
pub(crate) fn delstring(s: &mut Session<'_>, argv: &[String]) {
    let [_, pname, key] = argv else {
        s.io.error("usage: del_string principal key\n");
        return;
    };
    set_or_del(s, pname, key, None, "del_string");
}

fn set_or_del(s: &mut Session<'_>, pname: &str, key: &str, value: Option<&str>, prog: &str) {
    let (name, realm) = match s.h.parse_name(pname) {
        Ok(n) => n,
        Err(msg) => {
            // MIT `kadmin_delstring` (`kadmin.c:2011-2048`): this one message is `delstring`.
            let p = if value.is_some() { prog } else { "delstring" };
            s.io.com_err(p, Some(msg), "while parsing principal");
            return;
        }
    };
    let canon = name.unparse_with_realm(&realm);
    let done =
        s.h.mutate(|st, caller| st.set_string_in(&name, &realm, key, value, caller));
    match (done, value) {
        (Err(e), Some(_)) => s.io.com_err(
            prog,
            Some(&texts::princ_text(&e)),
            &format!("while setting attribute on principal \"{canon}\""),
        ),
        (Err(e), None) => s.io.com_err(
            prog,
            Some(&texts::princ_text(&e)),
            &format!("while deleting attribute from principal \"{canon}\""),
        ),
        (Ok(()), Some(_)) => {
            s.io.info(&format!("Attribute set for principal \"{canon}\".\n"));
        }
        (Ok(()), None) => {
            s.io.info(&format!("Attribute removed from principal \"{canon}\".\n"));
        }
    }
}

/// MIT `kadmin_lock` (`kadmin.c:636-648`): the store has no database lock to hold, but a writer
/// that could not take one is refused as MIT's `krb5_db_lock` refuses it.
pub(crate) fn lock(s: &mut Session<'_>, _argv: &[String]) {
    if s.locked {
        return;
    }
    if krb5_protocol::check_secret_file_writable(s.h.db_path()).is_err() {
        s.io.com_err("lock", Some(texts::CANTLOCK), "");
        return;
    }
    s.locked = true;
}

/// MIT `kadmin_unlock` (`kadmin.c:651-663`): the lock `lock` noted is let go.
pub(crate) fn unlock(s: &mut Session<'_>, _argv: &[String]) {
    s.locked = false;
}
