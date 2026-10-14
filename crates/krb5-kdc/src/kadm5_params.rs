//! The realm values MIT's `kadm5_init` requires of `kadm5_get_config_params`: a value written in
//! the KDC profile that does not convert leaves its parameter unset, and the admin interface
//! (`kadmin.local`, `kadmind`, `kdb5_util create`) refuses to start with
//! `KADM5_MISSING_CONF_PARAMS`, [`krb5_config::MISSING_CONF_PARAMS`].

use krb5_config::{KdcConf, KdcPaths};
use krb5_crypto::EncryptionType;

/// Whether `kadm5_init` refuses the realm's parameters in `conf`: a `default_principal_expiration`
/// that is no timestamp, a `default_principal_flags` word that is no flag, a `master_key_type`
/// that is no enctype (when `with_master_key_type`; `kdb5_util create` meets that one first, at
/// the master key), or `supported_enctypes` with no key/salt tuple in it.
/// MIT `kadm5_init` (`lib/kadm5/srv/server_init.c:207-218`): every required parameter must be
/// set, else `KADM5_MISSING_CONF_PARAMS`.
/// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:580-594`): a
/// `default_principal_expiration` that `krb5_string_to_timestamp` refuses leaves it unset.
/// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:541-555`): so does a `master_key_type`
/// that `krb5_string_to_enctype` refuses.
/// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:649-671`): and `supported_enctypes` that
/// give no key/salt tuple.
#[must_use]
pub fn kadm5_params_missing(conf: &KdcConf, with_master_key_type: bool) -> bool {
    let expiration = conf
        .default_principal_expiration
        .as_deref()
        .is_some_and(|s| krb5_types::timestamp::string_to_timestamp(s).is_none());
    let flags = conf
        .default_principal_flags
        .as_deref()
        .is_some_and(|s| !crate::acl::principal_flags_spec(s).1);
    let master = with_master_key_type
        && conf
            .master_key_type
            .as_deref()
            .is_some_and(|s| crate::mkey::string_to_enctype(s).is_err());
    let enctypes = !conf.supported_enctypes.is_empty()
        && !keysalts_present(&conf.supported_enctypes.join(" "));
    expiration || flags || master || enctypes
}

/// [`kadm5_params_missing`] for `realm`'s own stanza of the KDC profile `paths` read; a profile
/// that is not there, or does not load, leaves every parameter its default.
#[must_use]
pub fn realm_kadm5_params_missing(
    paths: &KdcPaths,
    realm: &str,
    with_master_key_type: bool,
) -> bool {
    if paths.conf.is_none() {
        return false;
    }
    let Ok(bytes) = std::fs::read(&paths.profile) else {
        return false;
    };
    crate::create::kdc_conf_for_realm(&String::from_utf8_lossy(&bytes), realm)
        .is_ok_and(|conf| kadm5_params_missing(&conf, with_master_key_type))
}

/// Whether `s` holds a key/salt tuple: tuples split on `,`, space or tab; each an enctype name,
/// then a salt type after `:` or `.` when there is one; a tuple that does not convert is skipped.
/// MIT `krb5_string_to_keysalts` (`lib/kadm5/str_conv.c:337-358`): unrecognized tuples are
/// discarded, so a list of them gives none.
/// MIT `krb5_string_to_salttype` (`lib/krb5/krb/str_conv.c:72-86`): a salt name in any case.
fn keysalts_present(s: &str) -> bool {
    const SALTS: [&str; 4] = ["normal", "norealm", "onlyrealm", "special"];
    s.split([',', ' ', '\t'])
        .filter(|t| !t.is_empty())
        .any(|tuple| {
            let (etype, salt) = match tuple.find([':', '.']) {
                Some(i) => (&tuple[..i], Some(&tuple[i + 1..])),
                None => (tuple, None),
            };
            EncryptionType::from_mit_name(etype).is_ok()
                && salt.is_none_or(|s| SALTS.iter().any(|n| n.eq_ignore_ascii_case(s)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(line: &str) -> KdcConf {
        KdcConf::parse(&format!("[realms]\n    R = {{\n        {line}\n    }}\n")).unwrap()
    }

    /// Live MIT 1.22.2: each of these stops kadmin.local, kadmind and kdb5_util create.
    #[test]
    fn a_realm_value_that_does_not_convert_is_a_missing_parameter() {
        for line in [
            "default_principal_expiration = garbage",
            "default_principal_expiration = 19000102030405",
            "default_principal_flags = +preauth,+bogus",
            "master_key_type = bogus-enctype",
            "supported_enctypes = bogus:normal",
            "supported_enctypes = aes256-cts:bogussalt",
        ] {
            assert!(kadm5_params_missing(&conf(line), true), "{line}");
        }
        assert!(!kadm5_params_missing(
            &conf("master_key_type = bogus-enctype"),
            false
        ));
        for line in [
            "max_life = 10h",
            "default_principal_expiration = 20991231235959",
            "default_principal_flags = +preauth, -allow-tix",
            "master_key_type = aes256-cts",
            "supported_enctypes = aes256-cts:normal aes128-cts.special",
        ] {
            assert!(!kadm5_params_missing(&conf(line), true), "{line}");
        }
    }

    /// The realm's own stanza, written `R =` with its `{` on the next line, is read as the
    /// profile parser reads it.
    #[test]
    fn a_two_line_realm_stanza_is_the_realm_s() {
        let text =
            "[realms]\n    R =\n    {\n        default_principal_expiration = garbage\n    }\n";
        let conf = crate::create::kdc_conf_for_realm(text, "R").unwrap();
        assert!(kadm5_params_missing(&conf, true));
    }

    /// MIT's word loop: the first comma anywhere ends the first word, so `+a +b,+c` is one word
    /// with a space in it, which is no flag.
    #[test]
    fn the_flags_loop_cuts_at_the_first_comma_first() {
        assert!(!crate::acl::principal_flags_spec("+preauth +needchange,+allow-tix").1);
        let (flags, ok) = crate::acl::principal_flags_spec("+preauth, -allow-tix");
        assert!(ok);
        assert_ne!(flags & crate::store::KDB_REQUIRES_PRE_AUTH, 0);
    }
}
