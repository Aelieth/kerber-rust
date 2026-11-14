//! MIT `kadmin_getprinc` and the date, duration, flag and salt names it prints.

use std::fmt::Write as _;

use krb5_kdc::Principal;

use super::backend::PrincRec;

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

fn kvno(p: &Principal) -> u32 {
    let opaque = p.opaque_keys.iter().map(|o| o.kvno);
    p.keys
        .iter()
        .map(|k| k.kvno)
        .chain(opaque)
        .max()
        .unwrap_or(0)
}

// MIT: `krb5_enctype_to_name` (lib/crypto/krb/enctype_util.c:137-143)
// MIT: `krb5int_enctypes_list` (lib/crypto/krb/etypes.c:37-75)
fn legacy_enctype_name(etype: i32) -> Option<(&'static str, &'static str)> {
    match etype {
        1 => Some(("UNSUPPORTED:", "des-cbc-crc")),
        2 => Some(("UNSUPPORTED:", "des-cbc-md4")),
        3 => Some(("UNSUPPORTED:", "des-cbc-md5")),
        4 => Some(("UNSUPPORTED:", "des-cbc-raw")),
        8 => Some(("UNSUPPORTED:", "des-hmac-sha1")),
        6 => Some(("DEPRECATED:", "des3-cbc-raw")),
        24 => Some(("DEPRECATED:", "arcfour-hmac-exp")),
        _ => None,
    }
}

// MIT: `kadmin_getprinc` (kadmin/cli/kadmin.c:1505-1525)
fn slot_fields(slot: krb5_kdc::KeySlot<'_>) -> Option<(u32, u32, i32, i32, String)> {
    match slot {
        krb5_kdc::KeySlot::Usable(k) => {
            let deprecated = if k.etype.is_deprecated() {
                "DEPRECATED:"
            } else {
                ""
            };
            let name = format!("{deprecated}{}", k.etype.to_mit_name());
            let salt = k.salt_type.unwrap_or(0);
            Some((key_ver(k), k.kvno, k.etype.to_iana(), salt, name))
        }
        krb5_kdc::KeySlot::Opaque(o) => {
            let et = o.slots.first().map_or(0, |s| s.0);
            let name = legacy_enctype_name(et).map_or_else(
                || format!("UNSUPPORTED:<Encryption type 0x{et:x}>"),
                |(prefix, n)| format!("{prefix}{n}"),
            );
            let salt = o.slots.get(1).map_or(0, |s| s.0);
            Some((u32::try_from(o.ver).unwrap_or(1), o.kvno, et, salt, name))
        }
        _ => None,
    }
}

fn key_ver(k: &krb5_kdc::KeyEntry) -> u32 {
    if k.salt_type.is_some() && k.kdb_salt.is_some() {
        2
    } else {
        1
    }
}

struct KeyLine {
    ver: u32,
    kvno: u32,
    etype: i32,
    salt: i32,
    name: String,
}

struct View {
    id: String,
    expiration: u32,
    last_pwd_change: u32,
    pw_expire: u32,
    max_life: u64,
    max_renewable_life: u64,
    mod_date: u32,
    mod_name: String,
    last_success: u32,
    last_failed: u32,
    fail_auth_count: u32,
    nkeys: usize,
    nkeys_terse: usize,
    keys: Vec<KeyLine>,
    mkvno: u32,
    attributes: u32,
    kvno: u32,
    policy: Option<String>,
}

fn wire_key_name(et: i32) -> String {
    if let Ok(e) = krb5_crypto::EncryptionType::from_iana(et) {
        let deprecated = if e.is_deprecated() { "DEPRECATED:" } else { "" };
        return format!("{deprecated}{}", e.to_mit_name());
    }
    legacy_enctype_name(et).map_or_else(
        || format!("UNSUPPORTED:<Encryption type 0x{et:x}>"),
        |(prefix, n)| format!("{prefix}{n}"),
    )
}

fn view(rec: &PrincRec) -> View {
    match rec {
        PrincRec::Local(p) => {
            let slots = p.key_slots();
            let nkeys = slots.len();
            let keys = slots
                .into_iter()
                .filter_map(slot_fields)
                .map(|(ver, kvno, etype, salt, name)| KeyLine {
                    ver,
                    kvno,
                    etype,
                    salt,
                    name,
                })
                .collect();
            View {
                id: p.id(),
                expiration: p.expiration,
                last_pwd_change: tl_u32(p, TL_LAST_PWD_CHANGE),
                pw_expire: p.pw_expire,
                max_life: p.max_life,
                max_renewable_life: p.max_renewable_life,
                mod_date: tl_u32(p, TL_MOD_PRINC),
                mod_name: mod_name(p),
                last_success: p.last_success,
                last_failed: p.last_failed,
                fail_auth_count: p.fail_auth_count,
                nkeys,
                nkeys_terse: p.keys.len() + p.opaque_keys.len(),
                keys,
                mkvno: u32::from(p.mkvno),
                attributes: p.attributes,
                kvno: kvno(p),
                policy: p.pw_policy.clone(),
            }
        }
        PrincRec::Wire(w) => View {
            id: w.principal.clone(),
            expiration: w.princ_expire_time,
            last_pwd_change: w.last_pwd_change,
            pw_expire: w.pw_expiration,
            max_life: u64::from(w.max_life),
            max_renewable_life: u64::from(w.max_renewable_life),
            mod_date: w.mod_date,
            mod_name: w.mod_name.clone().unwrap_or_else(|| "(null)".to_owned()),
            last_success: w.last_success,
            last_failed: w.last_failed,
            fail_auth_count: w.fail_auth_count,
            nkeys: w.key_data.len(),
            nkeys_terse: w.key_data.len(),
            keys: w
                .key_data
                .iter()
                .map(|k| KeyLine {
                    ver: u32::try_from(k.ver).unwrap_or(0),
                    kvno: k.kvno,
                    etype: k.enctype,
                    salt: k.salttype,
                    name: wire_key_name(k.enctype),
                })
                .collect(),
            mkvno: w.mkvno,
            attributes: w.attributes,
            kvno: w.kvno,
            policy: w.policy.clone(),
        },
    }
}

pub(crate) fn principal(rec: &PrincRec, policy_missing: bool) -> String {
    let p = view(rec);
    let never = |t: u32| {
        if t == 0 {
            "[never]".to_owned()
        } else {
            strdate(t)
        }
    };
    let mut o = String::new();
    let _ = writeln!(o, "Principal: {}", p.id);
    let _ = writeln!(o, "Expiration date: {}", never(p.expiration));
    let _ = writeln!(o, "Last password change: {}", never(p.last_pwd_change));
    let _ = writeln!(o, "Password expiration date: {}", never(p.pw_expire));
    let _ = writeln!(o, "Maximum ticket life: {}", strdur(p.max_life));
    let _ = writeln!(
        o,
        "Maximum renewable life: {}",
        strdur(p.max_renewable_life)
    );
    let _ = writeln!(o, "Last modified: {} ({})", strdate(p.mod_date), p.mod_name);
    let _ = writeln!(
        o,
        "Last successful authentication: {}",
        never(p.last_success)
    );
    let _ = writeln!(o, "Last failed authentication: {}", never(p.last_failed));
    let _ = writeln!(o, "Failed password attempts: {}", p.fail_auth_count);
    let _ = writeln!(o, "Number of keys: {}", p.nkeys);
    for k in &p.keys {
        let salt = if k.ver > 1 && k.salt != 0 {
            format!(":{}", salttype_name(k.salt))
        } else {
            String::new()
        };
        let _ = writeln!(o, "Key: vno {}, {}{salt}", k.kvno, k.name);
    }
    let _ = writeln!(o, "MKey: vno {}", p.mkvno);
    let _ = writeln!(o, "Attributes:{}", flags_to_string(p.attributes));
    match p.policy.as_deref() {
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

pub(crate) fn principal_terse(rec: &PrincRec) -> String {
    let p = view(rec);
    let mut o = format!(
        "\"{}\"\t{}\t{}\t{}\t{}\t\"{}\"\t{}\t{}\t{}\t{}\t\"{}\"\t{}\t{}\t{}\t{}\t{}",
        p.id,
        p.expiration.cast_signed(),
        p.last_pwd_change.cast_signed(),
        p.pw_expire.cast_signed(),
        p.max_life,
        p.mod_name,
        p.mod_date.cast_signed(),
        p.attributes.cast_signed(),
        p.kvno,
        p.mkvno,
        p.policy.as_deref().unwrap_or("[none]"),
        p.max_renewable_life,
        p.last_success.cast_signed(),
        p.last_failed.cast_signed(),
        p.fail_auth_count,
        p.nkeys_terse
    );
    for k in &p.keys {
        let st = if k.ver > 1 { k.salt } else { 0 };
        let _ = write!(o, "\t{}\t{}\t{}\t{st}", k.ver, k.kvno, k.etype);
    }
    o.push('\n');
    o
}

// MIT: `strdate` (kadmin.c:142-153)
/// The zone is `UTC` at offset zero and a numeric offset elsewhere: no abbreviations.
pub(crate) fn strdate(when: u32) -> String {
    krb5_types::timestamp::strftime("%a %b %d %H:%M:%S %Z %Y", when, 40)
        .unwrap_or_else(|| "(error)".to_owned())
}

pub(crate) fn strdur(duration: u64) -> String {
    crate::strdur(i64::try_from(duration).unwrap_or(i64::MAX))
}

// MIT: `krb5_flags_to_strings` (kadm5/str_conv.c:229-261)
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

// MIT: `krb5_salttype_to_string` (krb/str_conv.c:95-114)
pub(crate) fn salttype_name(t: i32) -> String {
    match t {
        0 => "normal".into(),
        2 => "norealm".into(),
        3 => "onlyrealm".into(),
        4 => "special".into(),
        other => format!("<Salt type 0x{other:x}>"),
    }
}
