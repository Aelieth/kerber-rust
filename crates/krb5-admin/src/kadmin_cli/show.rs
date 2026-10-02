//! How `getprinc` shows a principal record: MIT `kadmin_getprinc` and the `strdate`, `strdur`,
//! flag and salt-type names it prints with.

use std::fmt::Write as _;

use krb5_kdc::Principal;

/// The 4-byte little-endian value of the first `ty` tl-data entry, 0 when there is none.
fn tl_u32(p: &Principal, ty: i32) -> u32 {
    p.tl_data
        .iter()
        .find(|t| t.ty == ty)
        .and_then(|t| t.contents.get(..4))
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

const TL_LAST_PWD_CHANGE: i32 = 1;
const TL_MOD_PRINC: i32 = 2;

fn mod_name(p: &Principal) -> String {
    krb5_kdc::tl_mod_princ_name(&p.tl_data).unwrap_or_else(|| format!("kadmin/admin@{}", p.realm))
}

/// The record's kvno: its highest key's (`kadm5_get_principal`).
fn kvno(p: &Principal) -> u32 {
    p.keys.iter().map(|k| k.kvno).max().unwrap_or(0)
}

/// `key_data_ver`: 2 when the key carries its salt, else 1.
fn key_ver(k: &krb5_kdc::KeyEntry) -> u32 {
    if k.salt_type.is_some() && k.kdb_salt.is_some() {
        2
    } else {
        1
    }
}

/// MIT `kadmin_getprinc` (`kadmin.c:1438-1571`): the full record.
pub(crate) fn principal(p: &Principal, policy_missing: bool) -> String {
    let never = |t: u32| {
        if t == 0 {
            "[never]".to_owned()
        } else {
            strdate(t)
        }
    };
    let mut o = String::new();
    let _ = writeln!(o, "Principal: {}", p.id());
    let _ = writeln!(o, "Expiration date: {}", never(p.expiration));
    let _ = writeln!(
        o,
        "Last password change: {}",
        never(tl_u32(p, TL_LAST_PWD_CHANGE))
    );
    let _ = writeln!(o, "Password expiration date: {}", never(p.pw_expire));
    let _ = writeln!(o, "Maximum ticket life: {}", strdur(p.max_life));
    let _ = writeln!(
        o,
        "Maximum renewable life: {}",
        strdur(p.max_renewable_life)
    );
    let _ = writeln!(
        o,
        "Last modified: {} ({})",
        strdate(tl_u32(p, TL_MOD_PRINC)),
        mod_name(p)
    );
    let _ = writeln!(
        o,
        "Last successful authentication: {}",
        never(p.last_success)
    );
    let _ = writeln!(o, "Last failed authentication: {}", never(p.last_failed));
    let _ = writeln!(o, "Failed password attempts: {}", p.fail_auth_count);
    let _ = writeln!(o, "Number of keys: {}", p.keys.len());
    for k in &p.keys {
        let deprecated = if k.etype.is_deprecated() {
            "DEPRECATED:"
        } else {
            ""
        };
        let salt = match k.salt_type {
            Some(t) if key_ver(k) > 1 && t != 0 => format!(":{}", salttype_name(t)),
            _ => String::new(),
        };
        let _ = writeln!(
            o,
            "Key: vno {}, {deprecated}{}{salt}",
            k.kvno,
            k.etype.to_mit_name()
        );
    }
    let _ = writeln!(o, "MKey: vno {}", p.mkvno);
    let _ = writeln!(o, "Attributes:{}", flags_to_string(p.attributes));
    match p.pw_policy.as_deref() {
        Some(pol) if policy_missing => {
            let _ = writeln!(o, "Policy: {pol} [does not exist]");
        }
        Some(pol) => {
            let _ = writeln!(o, "Policy: {pol}");
        }
        None => o.push_str("Policy: [none]\n"),
    }
    o
}

/// MIT `kadmin_getprinc` (`kadmin.c:1438-1571`): `-terse`, the fields tab-separated, then
/// version, kvno, enctype and salt type of each key.
pub(crate) fn principal_terse(p: &Principal) -> String {
    let mut o = format!(
        "\"{}\"\t{}\t{}\t{}\t{}\t\"{}\"\t{}\t{}\t{}\t{}\t\"{}\"\t{}\t{}\t{}\t{}\t{}",
        p.id(),
        p.expiration.cast_signed(),
        tl_u32(p, TL_LAST_PWD_CHANGE).cast_signed(),
        p.pw_expire.cast_signed(),
        p.max_life,
        mod_name(p),
        tl_u32(p, TL_MOD_PRINC).cast_signed(),
        p.attributes.cast_signed(),
        kvno(p),
        p.mkvno,
        p.pw_policy.as_deref().unwrap_or("[none]"),
        p.max_renewable_life,
        p.last_success.cast_signed(),
        p.last_failed.cast_signed(),
        p.fail_auth_count,
        p.keys.len()
    );
    for k in &p.keys {
        let _ = write!(
            o,
            "\t{}\t{}\t{}\t{}",
            key_ver(k),
            k.kvno,
            k.etype.to_iana(),
            if key_ver(k) > 1 {
                k.salt_type.unwrap_or(0)
            } else {
                0
            }
        );
    }
    o.push('\n');
    o
}

/// MIT `strdate` (`kadmin.c:142-153`): `%a %b %d %H:%M:%S %Z %Y` in local time; the zone is
/// `UTC` at offset zero and the numeric offset elsewhere (no zone abbreviations).
pub(crate) fn strdate(when: u32) -> String {
    let Some(t) = chrono::DateTime::from_timestamp(i64::from(when), 0) else {
        return "(error)".to_owned();
    };
    let local = t.with_timezone(&chrono::Local);
    let zone = if local.offset().local_minus_utc() == 0 {
        "UTC".to_owned()
    } else {
        local.format("%Z").to_string()
    };
    format!(
        "{} {zone} {}",
        local.format("%a %b %d %H:%M:%S"),
        local.format("%Y")
    )
}

/// MIT `strdur` (`kadmin.c:118-139`): `D days HH:MM:SS`, `day` when D is one.
pub(crate) fn strdur(duration: u64) -> String {
    crate::strdur(i64::try_from(duration).unwrap_or(i64::MAX))
}

/// MIT `krb5_flags_to_strings` (`kadm5/str_conv.c:229-261`): one name per set bit, in bit
/// order, each after a space; a bit with no name is `0x%08lx`.
pub(crate) fn flags_to_string(attributes: u32) -> String {
    const NAMES: [Option<&str>; 24] = [
        Some("DISALLOW_POSTDATED"),
        Some("DISALLOW_FORWARDABLE"),
        Some("DISALLOW_TGT_BASED"),
        Some("DISALLOW_RENEWABLE"),
        Some("DISALLOW_PROXIABLE"),
        Some("DISALLOW_DUP_SKEY"),
        Some("DISALLOW_ALL_TIX"),
        Some("REQUIRES_PRE_AUTH"),
        Some("REQUIRES_HW_AUTH"),
        Some("REQUIRES_PWCHANGE"),
        None,
        None,
        Some("DISALLOW_SVR"),
        Some("PWCHANGE_SERVICE"),
        Some("SUPPORT_DESMD5"),
        Some("NEW_PRINC"),
        None,
        None,
        None,
        None,
        Some("OK_AS_DELEGATE"),
        Some("OK_TO_AUTH_AS_DELEGATE"),
        Some("NO_AUTH_DATA_REQUIRED"),
        Some("LOCKDOWN_KEYS"),
    ];
    let mut out = String::new();
    for bit in 0..32u32 {
        if attributes & (1u32 << bit) == 0 {
            continue;
        }
        out.push(' ');
        match NAMES.get(bit as usize).copied().flatten() {
            Some(n) => out.push_str(n),
            None => {
                let _ = write!(out, "0x{:08x}", 1u32 << bit);
            }
        }
    }
    out
}

/// MIT `krb5_salttype_to_string` (`krb/str_conv.c:95-114`): normal, norealm, onlyrealm and
/// special; any other is `<Salt type 0x..>`.
pub(crate) fn salttype_name(t: i32) -> String {
    match t {
        0 => "normal".into(),
        2 => "norealm".into(),
        3 => "onlyrealm".into(),
        4 => "special".into(),
        other => format!("<Salt type 0x{other:x}>"),
    }
}
