//! In-crate config tests (private-bound; moved out of `lib.rs`).

use super::ccname::{unix_euid, unix_uid};
use super::profile::parse_duration_secs;
use super::testenv::TEST_KRB5_PATHS;

use super::*;

#[test]
fn isolate_test_krb5_stays_off_host_tmp() {
    isolate_test_krb5();
    let paths = TEST_KRB5_PATHS
        .with(|c| c.borrow().clone())
        .expect("isolated");
    let path = paths.first().expect("path");
    assert!(!path.starts_with("/tmp/kerber-test-krb5"));
    assert!(path.exists());
}

#[test]
fn parse_krb5_conf_realms_and_libdefaults() {
    let text = r"
[libdefaults]
    default_realm = KERBER.TEST
    allow_weak_crypto = false
    clockskew = 300
    dns_lookup_kdc = no

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:88
        admin_server = 127.0.0.1:749
    }

[domain_realm]
    .kerber.test = KERBER.TEST
";
    let c = Krb5Conf::parse(text).unwrap();
    assert_eq!(c.default_realm.as_deref(), Some("KERBER.TEST"));
    assert!(!c.dns_lookup_kdc);
    assert!(c.kdc_timeout.is_none());
    assert!(c.max_retries.is_none());
    assert!(!c.allow_weak_crypto);
    assert!(c.allow_rc4.is_none());
    assert!(c.allow_des3.is_none());
    assert_eq!(c.clockskew, 300);
    assert_eq!(c.kdcs["KERBER.TEST"][0].host, "127.0.0.1");
    assert_eq!(c.kdcs["KERBER.TEST"][0].port, 88);
    assert!(c.pkinit_identities.is_empty());
    assert!(c.pkinit_anchors.is_empty());
    let discovered = c.kdcs_for("KERBER.TEST").unwrap();
    assert_eq!(discovered[0].host, "127.0.0.1");
    assert_eq!(discovered[0].port, 88);
    assert_eq!(c.domain_realm[".kerber.test"], "KERBER.TEST");
    assert_eq!(c.realm_for_host("app.kerber.test"), Some("KERBER.TEST"));
    assert_eq!(c.realm_for_host("kerber.test"), None);
    let mapped = Krb5Conf::parse(
        r"
[domain_realm]
    testhost.kerber.test = EXACT.TEST
    .kerber.test = DOT.TEST
    kerber.test = BARE.TEST
    .test = SHORT.TEST
",
    )
    .unwrap();
    assert_eq!(
        mapped.realm_for_host("testhost.kerber.test"),
        Some("EXACT.TEST")
    );
    assert_eq!(mapped.realm_for_host("app.kerber.test"), Some("DOT.TEST"));
    assert_eq!(mapped.realm_for_host("kerber.test"), Some("BARE.TEST"));
    assert_eq!(mapped.realm_for_host("other.test"), Some("SHORT.TEST"));
    assert!(is_numeric_address("1.2.3.4"));
    assert!(is_numeric_address("2001:db8::1"));
    assert!(!is_numeric_address("1.2.3"));
    assert!(!is_numeric_address("host.1.2.3.4"));
    let numeric = Krb5Conf::parse(
        r"
[domain_realm]
    1.2.3.4 = OTHER.TEST
    .kerber.test = KERBER.TEST
",
    )
    .unwrap();
    assert_eq!(numeric.realm_for_host("1.2.3.4"), None);
    assert_eq!(
        numeric.realm_for_host("app.kerber.test"),
        Some("KERBER.TEST")
    );
}

#[test]
fn parse_fleet_knobs_and_ignore_heimdal_spellings() {
    let c = Krb5Conf::parse(
        r"
[libdefaults]
    udp_preference_limit = 0
    rdns = false
    kdc_timesync = no
    forwardable = true
    ticket_lifetime = 10h
    renew_lifetime = 7d
    dns_lookup_realm = no
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes128-cts-hmac-sha1-96
    kdc_timeout = 1
    max_retries = 1
",
    )
    .unwrap();
    assert_eq!(c.udp_preference_limit, Some(0));
    assert!(!c.rdns);
    assert!(!c.kdc_timesync);
    assert!(!c.verify_ap_req_nofail);
    let nf = Krb5Conf::parse("[libdefaults]\n    verify_ap_req_nofail = true\n").unwrap();
    assert!(nf.verify_ap_req_nofail);
    assert!(c.forwardable);
    assert!(!c.proxiable);
    let px = Krb5Conf::parse("[libdefaults]\n    proxiable = true\n").unwrap();
    assert!(px.proxiable);
    assert!(!c.canonicalize);
    let cn = Krb5Conf::parse("[libdefaults]\n    canonicalize = true\n").unwrap();
    assert!(cn.canonicalize);
    assert_eq!(c.ticket_lifetime, Some(10 * 3600));
    assert_eq!(c.renew_lifetime, Some(7 * 86400));
    assert_eq!(c.permitted_enctypes.len(), 2);
    assert_eq!(c.default_tkt_enctypes, ["aes256-cts-hmac-sha1-96"]);
    assert_eq!(c.kdc_timeout.as_deref(), Some("1"));
    assert_eq!(c.max_retries.as_deref(), Some("1"));
    assert!(c.kcm_socket.is_none());
    assert!(c.default_ccache_name.is_none());
    let groups =
        Krb5Conf::parse("[libdefaults]\n    spake_preauth_groups = edwards25519 P-256\n").unwrap();
    assert_eq!(
        groups.spake_preauth_groups.as_deref(),
        Some(["edwards25519".to_string(), "P-256".to_string()].as_slice())
    );
    let pref =
        Krb5Conf::parse("[libdefaults]\n    preferred_preauth_types = 17, 16, 151\n").unwrap();
    assert_eq!(pref.preferred_preauth_types, [17, 16, 151]);
    let sock = Krb5Conf::parse("[libdefaults]\n    kcm_socket = /tmp/kcm.sock\n").unwrap();
    assert_eq!(sock.kcm_socket.as_deref(), Some("/tmp/kcm.sock"));
    let cc = Krb5Conf::parse("[libdefaults]\n    default_ccache_name = FILE:/tmp/krb5cc_%{uid}\n")
        .unwrap();
    assert_eq!(
        cc.default_ccache_name.as_deref(),
        Some("FILE:/tmp/krb5cc_%{uid}")
    );
}

#[test]
fn default_ccache_name_uses_process_uid() {
    let uid = nix::unistd::Uid::current().as_raw();
    assert_eq!(
        default_ccache_name(),
        PathBuf::from(format!("/tmp/krb5cc_{uid}"))
    );
    if uid != 0 {
        assert_ne!(default_ccache_name(), PathBuf::from("/tmp/krb5cc_0"));
    }
}

#[test]
fn expand_ccache_params_uid_tokens() {
    let uid = unix_uid();
    let euid = unix_euid();
    assert_eq!(
        expand_ccache_params("FILE:/tmp/x_%{uid}_%{USERID}_%{euid}").unwrap(),
        format!("FILE:/tmp/x_{uid}_{uid}_{euid}")
    );
    assert_eq!(
        expand_ccache_params("FILE:/tmp/n_%{null}x").unwrap(),
        "FILE:/tmp/n_x"
    );
    assert!(
        expand_ccache_params("FILE:/tmp/%{nope}")
            .unwrap_err()
            .to_string()
            .contains("nope")
    );
    assert!(
        expand_ccache_params("FILE:/tmp/x_%{uid")
            .unwrap_err()
            .to_string()
            .contains("unterminated")
    );
    let expanded = expand_ccache_params("FILE:/tmp/krb5cc_%{uid}").unwrap();
    assert_eq!(
        parse_ccspec(&expanded).unwrap(),
        CcSpec::File(default_ccache_name())
    );
}

#[test]
fn parse_ccname_file_and_rejects_other_types() {
    assert_eq!(
        parse_ccname("FILE:/tmp/krb5cc_1").unwrap(),
        PathBuf::from("/tmp/krb5cc_1")
    );
    assert_eq!(
        parse_ccname("KEYRING:user:foo").unwrap_err().to_string(),
        KRB5_CC_UNKNOWN_TYPE
    );
    assert_eq!(
        parse_ccname("/tmp/krb5cc_9").unwrap(),
        PathBuf::from("/tmp/krb5cc_9")
    );
}

#[test]
fn parse_ccspec_file_memory_dir_and_unknown() {
    assert_eq!(
        parse_ccspec("FILE:/tmp/a").unwrap(),
        CcSpec::File(PathBuf::from("/tmp/a"))
    );
    assert_eq!(
        parse_ccspec("/tmp/a").unwrap(),
        CcSpec::File(PathBuf::from("/tmp/a"))
    );
    assert_eq!(
        parse_ccspec("MEMORY:foo").unwrap(),
        CcSpec::Memory("foo".into())
    );
    assert_eq!(
        parse_ccspec("DIR:/tmp/cc").unwrap(),
        CcSpec::Dir("/tmp/cc".into())
    );
    assert_eq!(
        parse_ccspec("DIR::/tmp/cc/tkt").unwrap(),
        CcSpec::Dir(":/tmp/cc/tkt".into())
    );
    assert_eq!(
        parse_ccspec("KEYRING:persistent:1")
            .unwrap_err()
            .to_string(),
        KRB5_CC_UNKNOWN_TYPE
    );
    assert_eq!(parse_ccspec("KCM:").unwrap(), CcSpec::Kcm(String::new()));
    assert_eq!(parse_ccspec("KCM:0").unwrap(), CcSpec::Kcm("0".into()));
    assert_eq!(
        parse_ccspec("JUNK:x").unwrap_err().to_string(),
        KRB5_CC_UNKNOWN_TYPE
    );
    assert!(
        !parse_ccspec("KEYRING:x")
            .unwrap_err()
            .to_string()
            .contains("G8")
    );
}

#[test]
fn expand_ccache_params_unterminated_display_is_exact() {
    assert_eq!(
        expand_ccache_params("FILE:/tmp/x_%{uid")
            .unwrap_err()
            .to_string(),
        "unterminated %{token}"
    );
}

#[test]
fn expand_ccache_params_unknown_token_display_is_exact() {
    assert_eq!(
        expand_ccache_params("FILE:/tmp/%{nope}")
            .unwrap_err()
            .to_string(),
        "unknown ccache parameter %{nope}"
    );
}

#[test]
fn parse_ccspec_unknown_type_display_is_exact() {
    assert_eq!(
        parse_ccspec("KEYRING:x").unwrap_err().to_string(),
        "Unknown credential cache type",
    );
}

#[test]
fn parse_kdc_conf_policy() {
    let text = r"
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    KERBER.TEST = {
        max_life = 10h
        max_renewable_life = 7d
        requires_preauth = yes
        database_name = /var/lib/krb5kdc/principal
        master_key_type = aes256-cts-hmac-sha384-192
        db_library = db2
        domain_sid = S-1-5-21-891046300-1937985867-1481223175
    }
";
    let c = KdcConf::parse(text).unwrap();
    assert_eq!(c.realm, "KERBER.TEST");
    assert_eq!(c.max_life, 36000);
    assert_eq!(c.max_renewable_life, 7 * 86400);
    assert_eq!(c.realm_max_renewable_life, 7 * 86400);
    assert!(c.requires_preauth);
    assert_eq!(
        c.master_key_type.as_deref(),
        Some("aes256-cts-hmac-sha384-192")
    );
    assert_eq!(c.db_library.as_deref(), Some("db2"));
    assert_eq!(
        c.domain_sid.as_deref(),
        Some("S-1-5-21-891046300-1937985867-1481223175")
    );
    assert_eq!(c.kdc_listen, "88");
    assert_eq!(c.kdc_tcp_listen.as_deref(), Some("88"));
    assert!(c.reject_bad_transit);
    let rc4 = KdcConf::parse(
        r"
[libdefaults]
    allow_rc4 = true
    allow_des3 = yes
    permitted_enctypes = aes256-cts arcfour-hmac

[kdcdefaults]
    allow_weak_crypto = true

[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts:normal rc4-hmac:normal
    }
",
    )
    .unwrap();
    assert_eq!(rc4.allow_rc4, Some(true));
    assert_eq!(rc4.allow_des3, Some(true));
    assert_eq!(
        rc4.allow_weak_crypto, None,
        "[kdcdefaults] allow_weak_crypto is ignored like MIT's get_boolean(LIBDEFAULTS)"
    );
    assert_eq!(rc4.permitted_enctypes, vec!["aes256-cts", "arcfour-hmac"]);
    let elsewhere = KdcConf::parse(
        r"
[kdcdefaults]
    allow_rc4 = true
    allow_des3 = true
    permitted_enctypes = arcfour-hmac

[realms]
    KERBER.TEST = {
        allow_rc4 = true
        allow_weak_crypto = true
        permitted_enctypes = arcfour-hmac
    }
",
    )
    .unwrap();
    assert_eq!(elsewhere.allow_rc4, None);
    assert_eq!(elsewhere.allow_des3, None);
    assert_eq!(elsewhere.allow_weak_crypto, None);
    assert_eq!(elsewhere.permitted_enctypes, [] as [String; 0]);
    assert_eq!(
        rc4.supported_enctypes,
        vec!["aes256-cts:normal", "rc4-hmac:normal"]
    );
    let mit = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        database_name = /var/lib/krb5kdc/principal
        key_stash_file = /var/lib/krb5kdc/.k5.KERBER.TEST
    }
",
    )
    .unwrap();
    assert!(mit.reject_bad_transit);
    let lax = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        reject_bad_transit = false
    }
",
    )
    .unwrap();
    assert!(!lax.reject_bad_transit);
    assert_eq!(lax.max_renewable_life, 0);
    assert_eq!(lax.realm_max_renewable_life, 7 * 86400);
    assert_eq!(mit.max_life, 36000);
    assert_eq!(mit.max_renewable_life, 7 * 86400);
    assert_eq!(mit.realm_max_renewable_life, 7 * 86400);
    assert_eq!(
        mit.database_name.as_deref(),
        Some(std::path::Path::new("/var/lib/krb5kdc/principal"))
    );
}

/// A fake environment for [`KdcPaths::resolve_in`]: tests cannot set process variables.
fn fake_env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
    let vars: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name: &str| {
        vars.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| std::ffi::OsString::from(v))
    }
}

fn resolve_paths(
    vars: &[(&str, &str)],
    realm: Option<&str>,
    default_realm: Option<&str>,
) -> Result<KdcPaths, Error> {
    KdcPaths::resolve_in(&fake_env(vars), realm, || default_realm.map(str::to_owned))
}

fn kdc_dir_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(KDC_DIR).join(name)
}

#[test]
fn kdc_profile_is_the_variable_else_kdc_dir() {
    // MIT `add_kdc_config_file` (`init_os_ctx.c:340-366`): KRB5_KDC_PROFILE, else DEFAULT_KDC_PROFILE.
    assert_eq!(
        kdcconf::kdc_conf_path_in(&fake_env(&[])),
        kdc_dir_path("kdc.conf")
    );
    assert_eq!(default_kdc_profile(), kdc_dir_path("kdc.conf"));
    let alias = fake_env(&[("KRB5_KDC_CONF", "/b/kdc.conf")]);
    assert_eq!(
        kdcconf::kdc_conf_path_in(&alias),
        std::path::Path::new("/b/kdc.conf")
    );
    let both = fake_env(&[
        ("KRB5_KDC_PROFILE", "/a/kdc.conf"),
        ("KRB5_KDC_CONF", "/b/kdc.conf"),
    ]);
    assert_eq!(
        kdcconf::kdc_conf_path_in(&both),
        std::path::Path::new("/a/kdc.conf")
    );
}

#[test]
fn a_missing_profile_leaves_mit_defaults_under_kdc_dir() {
    // Live MIT 1.22.2: `KRB5_KDC_PROFILE=/nonexistent/kdc.conf kdb5_util -P pw create -s -r R`
    // creates KDC_DIR/principal and KDC_DIR/.k5.R, exit 0.
    let dir = krb5_testkit::scratch_dir("kdcpaths-missing");
    let missing = dir.join("no-such-kdc.conf");
    let missing = missing.to_str().unwrap();
    let p = resolve_paths(&[("KRB5_KDC_PROFILE", missing)], None, Some("KERBER.TEST")).unwrap();
    assert_eq!(p.profile, std::path::Path::new(missing));
    assert_eq!(p.conf, None);
    assert_eq!(p.realm.as_deref(), Some("KERBER.TEST"));
    assert_eq!(p.database_name, kdc_dir_path("principal"));
    assert_eq!(p.key_stash_file, kdc_dir_path(".k5.KERBER.TEST"));
    assert_eq!(p.acl_file, Some(kdc_dir_path("kadm5.acl")));
    assert_eq!(p.master_key_type, None);
    // A directory reads as an empty profile too; text that is not UTF-8 is refused.
    let as_dir = resolve_paths(
        &[("KRB5_KDC_PROFILE", dir.to_str().unwrap())],
        Some("R"),
        None,
    );
    assert_eq!(as_dir.unwrap().conf, None);
    let bad = dir.join("bad-kdc.conf");
    std::fs::write(&bad, b"[realms]\n\xff\n").unwrap();
    let err = resolve_paths(
        &[("KRB5_KDC_PROFILE", bad.to_str().unwrap())],
        Some("R"),
        None,
    );
    assert!(err.unwrap_err().to_string().contains("bad-kdc.conf"));
}

#[test]
fn paths_come_from_the_realms_own_stanza() {
    // MIT `get_string_param` (`alt_prof.c:310-336`): the realm's stanza, last value.
    let dir = krb5_testkit::scratch_dir("kdcpaths-stanza");
    let conf = dir.join("kdc.conf");
    std::fs::write(
        &conf,
        "[realms]\n    A.TEST = {\n        database_name = /a/principal\n        \
         key_stash_file = /a/stash\n        acl_file = /a/kadm5.acl\n        \
         master_key_type = aes256-cts-hmac-sha1-96\n    }\n    B.TEST = {\n        \
         database_name = /b/old\n        database_name = /b/principal\n    }\n",
    )
    .unwrap();
    let vars = [("KRB5_KDC_PROFILE", conf.to_str().unwrap())];
    let a = resolve_paths(&vars, None, Some("A.TEST")).unwrap();
    assert_eq!(a.database_name, std::path::Path::new("/a/principal"));
    assert_eq!(a.key_stash_file, std::path::Path::new("/a/stash"));
    assert_eq!(
        a.acl_file.as_deref(),
        Some(std::path::Path::new("/a/kadm5.acl"))
    );
    assert_eq!(
        a.master_key_type.as_deref(),
        Some("aes256-cts-hmac-sha1-96")
    );
    assert!(a.conf.is_some());
    // B.TEST's stanza has no stash, ACL or master key type: MIT's defaults, not A.TEST's.
    let b = resolve_paths(&vars, Some("B.TEST"), Some("A.TEST")).unwrap();
    assert_eq!(b.realm.as_deref(), Some("B.TEST"));
    assert_eq!(b.database_name, std::path::Path::new("/b/principal"));
    assert_eq!(b.key_stash_file, kdc_dir_path(".k5.B.TEST"));
    assert_eq!(b.acl_file, Some(kdc_dir_path("kadm5.acl")));
    assert_eq!(b.master_key_type, None);
}

#[test]
fn a_realm_with_no_stanza_gets_mit_defaults() {
    // Live MIT 1.22.2: when kdc.conf holds a stanza only for another realm, `kdb5_util create -s`
    // for the default realm writes KDC_DIR/principal and KDC_DIR/.k5.<default realm>.
    let dir = krb5_testkit::scratch_dir("kdcpaths-other");
    let conf = dir.join("kdc.conf");
    std::fs::write(
        &conf,
        "[realms]\n    EXAMPLE.COM = {\n        database_name = /x/principal\n        \
         key_stash_file = /x/.k5.EXAMPLE.COM\n    }\n",
    )
    .unwrap();
    let vars = [("KRB5_KDC_PROFILE", conf.to_str().unwrap())];
    let p = resolve_paths(&vars, None, Some("KERBER.TEST")).unwrap();
    assert_eq!(p.database_name, kdc_dir_path("principal"));
    assert_eq!(p.key_stash_file, kdc_dir_path(".k5.KERBER.TEST"));
    let named = resolve_paths(&vars, Some("EXAMPLE.COM"), Some("KERBER.TEST")).unwrap();
    assert_eq!(named.database_name, std::path::Path::new("/x/principal"));
    assert_eq!(
        named.key_stash_file,
        std::path::Path::new("/x/.k5.EXAMPLE.COM")
    );
}

#[test]
fn environment_overrides_sit_on_top() {
    let dir = krb5_testkit::scratch_dir("kdcpaths-env");
    let conf = dir.join("kdc.conf");
    std::fs::write(
        &conf,
        "[realms]\n    KERBER.TEST = {\n        database_name = /c/principal\n        \
         key_stash_file = /c/stash\n        acl_file = /c/kadm5.acl\n        \
         master_key_type = aes256-cts-hmac-sha1-96\n    }\n",
    )
    .unwrap();
    let p = resolve_paths(
        &[
            ("KRB5_KDC_CONF", conf.to_str().unwrap()),
            ("KRB5_KDC_DB", "/e/principal"),
            ("KRB5_KDC_STASH", "/e/stash"),
            ("KRB5_ACL_FILE", "/e/acl"),
            ("KRB5_MASTER_ETYPE", "aes128-cts-hmac-sha256-128"),
        ],
        None,
        None,
    )
    .unwrap();
    assert_eq!(p.realm, None);
    assert!(p.conf.is_some());
    assert_eq!(p.database_name, std::path::Path::new("/e/principal"));
    assert_eq!(p.key_stash_file, std::path::Path::new("/e/stash"));
    assert_eq!(p.acl_file.as_deref(), Some(std::path::Path::new("/e/acl")));
    assert_eq!(
        p.master_key_type.as_deref(),
        Some("aes128-cts-hmac-sha256-128")
    );
}

#[test]
fn the_acl_default_follows_a_relocated_stash_and_empty_means_none() {
    let both = [
        ("KRB5_KDC_DB", "/tmp/principal"),
        ("KRB5_KDC_STASH", "/tmp/stash"),
    ];
    let p = resolve_paths(&both, None, None).unwrap();
    assert_eq!(
        p.acl_file.as_deref(),
        Some(std::path::Path::new("/tmp/kadm5.acl"))
    );
    let p = resolve_paths(&both[1..], None, Some("R")).unwrap();
    assert_eq!(p.database_name, kdc_dir_path("principal"));
    assert_eq!(
        p.acl_file.as_deref(),
        Some(std::path::Path::new("/tmp/kadm5.acl"))
    );
    let none = resolve_paths(&[both[0], both[1], ("KRB5_ACL_FILE", "")], None, None);
    assert_eq!(none.unwrap().acl_file, None);
    let dir = krb5_testkit::scratch_dir("kdcpaths-acl");
    let conf = dir.join("kdc.conf");
    std::fs::write(&conf, "[realms]\n    R = {\n        acl_file =\n    }\n").unwrap();
    let empty = resolve_paths(
        &[("KRB5_KDC_PROFILE", conf.to_str().unwrap())],
        Some("R"),
        None,
    );
    assert_eq!(empty.unwrap().acl_file, None);
}

#[test]
fn no_realm_fails_unless_both_files_are_named() {
    // Live MIT 1.22.2: with no -r and no default_realm, kdb5_util refuses before any path,
    // even with -d and -sf: "Configuration file does not specify default realm while getting
    // default realm", exit 1.
    let dir = krb5_testkit::scratch_dir("kdcpaths-norealm");
    let conf = dir.join("kdc.conf");
    std::fs::write(
        &conf,
        "[realms]
    R = {
        database_name = /r/principal
                 key_stash_file = /r/stash
    }
",
    )
    .unwrap();
    let vars = [("KRB5_KDC_PROFILE", conf.to_str().unwrap())];
    let e = resolve_paths(&vars, None, None).unwrap_err();
    assert!(matches!(e, Error::NoDefaultRealm));
    assert_eq!(
        e.to_string(),
        "Configuration file does not specify default realm"
    );
    let stash_only = [vars[0], ("KRB5_KDC_STASH", "/s/stash")];
    assert!(matches!(
        resolve_paths(&stash_only, None, None),
        Err(Error::NoDefaultRealm)
    ));
    let both = [
        stash_only[0],
        stash_only[1],
        ("KRB5_KDC_DB", "/s/principal"),
    ];
    let p = resolve_paths(&both, None, None).unwrap();
    assert_eq!(p.realm, None);
    assert_eq!(p.database_name, std::path::Path::new("/s/principal"));
}

#[test]
fn dict_file_is_a_realm_relation_only() {
    // MIT `kadm5_get_config_params` (`alt_prof.c:486-513`): reads dict_file under
    // [realms] REALM; a [kdcdefaults] dict_file is not consulted (live: MIT logs
    // "No dictionary file specified").
    let realm = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        dict_file = /tmp/dict.txt
    }
",
    )
    .unwrap();
    assert_eq!(realm.dict_file, Some(PathBuf::from("/tmp/dict.txt")));
    let defaults = KdcConf::parse(
        r"
[kdcdefaults]
    dict_file = /tmp/dict.txt
[realms]
    KERBER.TEST = {
        max_life = 10h
    }
",
    )
    .unwrap();
    assert_eq!(defaults.dict_file, None);
}

#[test]
fn libdefaults_does_not_honour_kdcdefaults_knobs() {
    // MIT reads kdc_ports/kdc_tcp_ports/reject_bad_transit only from
    // [kdcdefaults] or a realm stanza; a copy under [libdefaults] is ignored
    // (no fallthrough).
    // MIT `init_realm` (`kdc/main.c:257-261`): the realm stanza's `kdc_listen`, then
    // `kdc_ports`.
    // MIT `initialize_realms` (`kdc/main.c:622-626`): the `[kdcdefaults]` `kdc_listen`,
    // then `kdc_ports`.
    let lib = KdcConf::parse(
        r"
[libdefaults]
    kdc_ports = 12345
    kdc_tcp_ports = 12345
    reject_bad_transit = false
    allow_rc4 = true
",
    )
    .unwrap();
    // The kdcdefaults knobs under [libdefaults] are ignored: defaults kept.
    assert_eq!(lib.kdc_listen, "88");
    assert_eq!(lib.kdc_tcp_listen, None);
    assert!(lib.reject_bad_transit, "reject_bad_transit default kept");
    // The four enctype knobs under [libdefaults] are still honoured.
    assert_eq!(lib.allow_rc4, Some(true));
    // The same knobs under [kdcdefaults] ARE honoured.
    let kdc = KdcConf::parse(
        r"
[kdcdefaults]
    kdc_ports = 12345
    reject_bad_transit = false
",
    )
    .unwrap();
    assert_eq!(kdc.kdc_listen, "12345");
    assert!(!kdc.reject_bad_transit);
}

#[test]
fn restrict_anonymous_to_tgt_from_kdcdefaults_and_realm() {
    let kdc = KdcConf::parse(
        r"
[kdcdefaults]
    restrict_anonymous_to_tgt = true
",
    )
    .unwrap();
    assert!(kdc.restrict_anon);
    let realm = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        restrict_anonymous_to_tgt = true
    }
",
    )
    .unwrap();
    assert!(realm.restrict_anon);
    let lib = KdcConf::parse(
        r"
[libdefaults]
    restrict_anonymous_to_tgt = true
",
    )
    .unwrap();
    assert!(!lib.restrict_anon);
}

#[test]
fn realm_booleans_win_over_later_kdcdefaults() {
    let conf = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        restrict_anonymous_to_tgt = false
        pkinit_require_freshness = false
        disable_pac = false
        reject_bad_transit = false
    }
[kdcdefaults]
    restrict_anonymous_to_tgt = true
    pkinit_require_freshness = true
    disable_pac = true
    reject_bad_transit = true
",
    )
    .unwrap();
    assert!(!conf.restrict_anon);
    assert!(!conf.pkinit_require_freshness);
    assert!(!conf.disable_pac);
    assert!(!conf.reject_bad_transit);
}

#[test]
fn pkinit_require_freshness_from_kdcdefaults_and_realm() {
    let kdc = KdcConf::parse(
        r"
[kdcdefaults]
    pkinit_require_freshness = true
",
    )
    .unwrap();
    assert!(kdc.pkinit_require_freshness);
    let realm = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        pkinit_require_freshness = true
    }
",
    )
    .unwrap();
    assert!(realm.pkinit_require_freshness);
    let lib = KdcConf::parse(
        r"
[libdefaults]
    pkinit_require_freshness = true
",
    )
    .unwrap();
    assert!(!lib.pkinit_require_freshness);
}

#[test]
fn host_based_and_no_host_referral_from_kdcdefaults_and_realm() {
    let kdc = KdcConf::parse(
        r"
[kdcdefaults]
    host_based_services = host
    no_host_referral = imap
",
    )
    .unwrap();
    assert_eq!(kdc.host_based_services, "host");
    assert_eq!(kdc.no_host_referral, "imap");
    let both = KdcConf::parse(
        r"
[kdcdefaults]
    host_based_services = host
[realms]
    KERBER.TEST = {
        host_based_services = smtp
        no_host_referral = *
    }
",
    )
    .unwrap();
    assert_eq!(both.host_based_services, "host smtp");
    assert_eq!(both.no_host_referral, "*");
    let lib = KdcConf::parse(
        r"
[libdefaults]
    host_based_services = host
    no_host_referral = imap
",
    )
    .unwrap();
    assert_eq!(lib.host_based_services, "");
    assert_eq!(lib.no_host_referral, "");
}

#[test]
fn disable_pac_from_kdcdefaults_and_realm() {
    let kdc = KdcConf::parse(
        r"
[kdcdefaults]
    disable_pac = true
",
    )
    .unwrap();
    assert!(kdc.disable_pac);
    let realm = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        disable_pac = true
    }
",
    )
    .unwrap();
    assert!(realm.disable_pac);
    let lib = KdcConf::parse(
        r"
[libdefaults]
    disable_pac = true
",
    )
    .unwrap();
    assert!(!lib.disable_pac);
}

#[test]
fn realm_auth_indicator_knobs() {
    let kdc = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        encrypted_challenge_indicator = encrypted_challenge
        pkinit_indicator = pkinit
        pkinit_indicator = certauth
        spake_preauth_indicator = spake
    }
",
    )
    .unwrap();
    assert_eq!(
        kdc.encrypted_challenge_indicator.as_deref(),
        Some("encrypted_challenge")
    );
    assert_eq!(kdc.pkinit_indicators, vec!["pkinit", "certauth"]);
    assert_eq!(kdc.spake_preauth_indicators, vec!["spake"]);
}

#[test]
fn parse_pkinit_identities_and_anchors() {
    let c = Krb5Conf::parse(
        r"
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        pkinit_identities = FILE:/tmp/pkinit/user.pem
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
    }
",
    )
    .unwrap();
    assert_eq!(
        c.pkinit_identities["KERBER.TEST"],
        vec!["FILE:/tmp/pkinit/user.pem".to_owned()]
    );
    assert_eq!(
        c.pkinit_anchors["KERBER.TEST"],
        vec!["FILE:/tmp/pkinit/ca.pem".to_owned()]
    );
}

#[test]
fn duration_parser() {
    assert_eq!(parse_duration_secs("10h"), Some(36000));
    assert_eq!(parse_duration_secs("7d"), Some(604_800));
    assert_eq!(parse_duration_secs("300"), Some(300));
    assert_eq!(parse_duration_secs("10h 0m 0s"), Some(36000));
    assert_eq!(parse_duration_secs("1h 30m"), Some(5400));
    assert_eq!(parse_duration_secs("7d 0h 0m 0s"), Some(604_800));
}

#[test]
fn split_krb5_config_paths_colon() {
    assert_eq!(
        split_krb5_config_paths("/a.conf:/b.conf"),
        vec![PathBuf::from("/a.conf"), PathBuf::from("/b.conf")]
    );
    assert_eq!(split_krb5_config_paths(""), [] as [std::path::PathBuf; 0]);
    assert_eq!(
        split_krb5_config_paths("/a.conf:"),
        vec![PathBuf::from("/a.conf")]
    );
}

#[test]
fn parse_capaths_client_server_hops() {
    let c = Krb5Conf::parse(
        r"
[capaths]
    A.TEST = {
        C.TEST = B.TEST
        B.TEST = .
    }
    C.TEST = {
        A.TEST = B.TEST
    }
",
    )
    .unwrap();
    assert_eq!(c.capaths["A.TEST"]["C.TEST"], ["B.TEST"]);
    assert_eq!(c.capaths["A.TEST"]["B.TEST"], ["."]);
    assert_eq!(c.capaths["C.TEST"]["A.TEST"], ["B.TEST"]);
}

#[test]
fn parse_capaths_space_separated_intermediates() {
    let c = Krb5Conf::parse(
        r"
[capaths]
    A.TEST = {
        C.TEST = B.TEST D.TEST
        B.TEST = .
    }
",
    )
    .unwrap();
    assert_eq!(c.capaths["A.TEST"]["C.TEST"], ["B.TEST", "D.TEST"]);
    assert_eq!(c.capaths["A.TEST"]["B.TEST"], ["."]);
    assert_eq!(
        c.client_realm_path("A.TEST", "C.TEST"),
        ["A.TEST", "B.TEST", "D.TEST", "C.TEST"]
    );
    assert_eq!(
        c.client_realm_path("A.TEST", "B.TEST"),
        ["A.TEST", "B.TEST"]
    );
    assert_eq!(c.client_realm_path("A.TEST", "A.TEST"), ["A.TEST"]);
    assert_eq!(
        client_realm_path(&BTreeMap::new(), "A.TEST", "C.TEST"),
        ["A.TEST", "C.TEST"]
    );
}

#[test]
fn parse_text_does_not_follow_include() {
    let c = Krb5Conf::parse(
        "include /no/such/file.conf\n[libdefaults]\n    default_realm = LOCAL.TEST\n",
    )
    .unwrap();
    assert_eq!(c.default_realm.as_deref(), Some("LOCAL.TEST"));
}

#[test]
fn ignore_acceptor_hostname_defaults_false() {
    let c = Krb5Conf::parse("[libdefaults]\n    default_realm = KERBER.TEST\n").unwrap();
    assert!(!c.ignore_acceptor_hostname);
    let on = Krb5Conf::parse("[libdefaults]\n    ignore_acceptor_hostname = true\n").unwrap();
    assert!(on.ignore_acceptor_hostname);
}

fn wild(port: u16) -> crate::listen::ListenAddr {
    crate::listen::ListenAddr { host: None, port }
}

fn at(host: &str, port: u16) -> crate::listen::ListenAddr {
    crate::listen::ListenAddr {
        host: Some(host.to_owned()),
        port,
    }
}

#[test]
fn kdc_ports_list_binds_every_port_on_the_wildcard_like_mit() {
    // The three cases MIT krb5kdc / kadmind 1.22.2 bind, read from their sockets.
    // Case 1, KLLDAP's kdc.template.conf: `kdc_ports = 750,88` and nothing else.
    let c = KdcConf::parse("[kdcdefaults]\n    kdc_ports = 750,88\n").unwrap();
    assert_eq!(c.kdc_udp_listeners().unwrap(), vec![wild(750), wild(88)]);
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(750), wild(88)]);
    assert_eq!(c.kadmind_listeners(None).unwrap(), vec![wild(749)]);
    assert_eq!(c.kpasswd_listeners().unwrap(), vec![wild(464)]);
    // Case 2: the realm stanza's lists beat [kdcdefaults], UDP and TCP apart.
    let c = KdcConf::parse(
        "[kdcdefaults]\n    kdc_ports = 750,88\n[realms]\n    R = {\n        kdc_listen = 127.0.0.2:8888 3333\n        kdc_tcp_listen = 9999\n    }\n",
    )
    .unwrap();
    assert_eq!(
        c.kdc_udp_listeners().unwrap(),
        vec![at("127.0.0.2", 8888), wild(3333)]
    );
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(9999)]);
    // Case 3: a TCP-only list leaves UDP on the default; kadmind and kpasswd lists.
    let c = KdcConf::parse(
        "[kdcdefaults]\n    kdc_tcp_ports = 7777\n[realms]\n    R = {\n        kadmind_listen = 127.0.0.3:7749\n        kpasswd_port = 7464\n    }\n",
    )
    .unwrap();
    assert_eq!(c.kdc_udp_listeners().unwrap(), vec![wild(88)]);
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(7777)]);
    assert_eq!(
        c.kadmind_listeners(None).unwrap(),
        vec![at("127.0.0.3", 7749)]
    );
    assert_eq!(c.kpasswd_listeners().unwrap(), vec![wild(7464)]);
    // No kdc.conf listener relation at all: MIT DEFAULT_KDC_PORTLIST on the wildcard.
    let c = KdcConf::default();
    assert_eq!(c.kdc_udp_listeners().unwrap(), vec![wild(88)]);
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(88)]);
}

#[test]
fn kdc_listen_beats_kdc_ports_in_the_same_section() {
    // MIT `init_realm` tries kdc_listen first and reads kdc_ports only when it is absent,
    // whatever the order in the file.
    let c = KdcConf::parse(
        "[kdcdefaults]\n    kdc_ports = 88\n    kdc_listen = 127.0.0.1:1088\n    kdc_tcp_ports = 2088\n    kdc_tcp_listen = 3088\n",
    )
    .unwrap();
    assert_eq!(c.kdc_udp_listeners().unwrap(), vec![at("127.0.0.1", 1088)]);
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(3088)]);
}

#[test]
fn listen_entries_parse_like_k5_parse_host_string() {
    use crate::listen::{listen_addrs, parse_host_string};
    assert_eq!(parse_host_string("88", 88).unwrap(), wild(88));
    assert_eq!(
        parse_host_string("kdc.example.com", 88).unwrap(),
        at("kdc.example.com", 88)
    );
    assert_eq!(
        parse_host_string("10.0.0.1:750", 88).unwrap(),
        at("10.0.0.1", 750)
    );
    assert_eq!(parse_host_string("[::1]:750", 88).unwrap(), at("::1", 750));
    assert_eq!(parse_host_string("[::]", 88).unwrap(), at("::", 88));
    for bad in ["", ":88", "10.0.0.1:", "10.0.0.1:x", "70000", "[::1]:99999"] {
        assert!(
            parse_host_string(bad, 88).is_err(),
            "{bad:?} must be refused"
        );
    }
    // `,`, `;` and space all separate; a /path entry (a UNIX socket in MIT) is skipped.
    assert_eq!(
        listen_addrs(Some("750, 88;127.0.0.1:89 /run/kdc.sock"), 88).unwrap(),
        vec![wild(750), wild(88), at("127.0.0.1", 89)]
    );
    // MIT `loop_add_address`: a wildcard removes the direct addresses on its port, and a
    // direct address on a wildcard's port (or a repeat) is dropped.
    assert_eq!(
        listen_addrs(
            Some("127.0.0.1:88 88 10.0.0.1:88 88 127.0.0.1:89 127.0.0.1:89"),
            88
        )
        .unwrap(),
        vec![wild(88), at("127.0.0.1", 89)]
    );
    assert_eq!(listen_addrs(None, 749).unwrap(), vec![wild(749)]);
    assert!(listen_addrs(Some("88,99999"), 88).is_err());
}

#[test]
fn wildcard_resolves_to_both_families() {
    let addrs = wild(88).resolve().unwrap();
    assert_eq!(
        addrs,
        vec![
            "0.0.0.0:88".parse::<std::net::SocketAddr>().unwrap(),
            "[::]:88".parse().unwrap()
        ]
    );
    assert_eq!(
        at("127.0.0.1", 750).resolve().unwrap(),
        vec!["127.0.0.1:750".parse::<std::net::SocketAddr>().unwrap()]
    );
}

#[test]
fn kadmind_port_follows_admin_server_then_kadmind_port() {
    // MIT `kadm5_get_config_params`: a port written in admin_server sets kadmind's port
    // before kadmind_port is read.
    let c = KdcConf::parse("[realms]\n    R = {\n        kadmind_port = 7749\n    }\n").unwrap();
    assert_eq!(c.kadmind_port(None), 7749);
    assert_eq!(c.kadmind_port(Some("kdc.example.com")), 7749);
    assert_eq!(c.kadmind_port(Some("kdc.example.com:8749")), 8749);
    assert_eq!(c.kadmind_port(Some("[::1]:9749")), 9749);
    let c = KdcConf::parse(
        "[realms]\n    R = {\n        admin_server = kdc.example.com:6749\n        kadmind_port = 7749\n    }\n",
    )
    .unwrap();
    assert_eq!(c.kadmind_port(Some("other:8749")), 6749);
    assert_eq!(KdcConf::default().kadmind_port(None), 749);
}

// `[logging]` (logging.rs).

fn logging_conf(kdc: &str, krb5: &str) -> (KdcConf, Krb5Conf) {
    (KdcConf::parse(kdc).unwrap(), Krb5Conf::parse(krb5).unwrap())
}

#[test]
fn the_program_key_wins_over_default_across_both_files() {
    let (k, c) = logging_conf(
        "[logging]\n    kdc = FILE:/a.log\n    default = FILE:/d.log\n",
        "[logging]\n    kdc = FILE:/b.log\n    admin_server = FILE=/k.log\n",
    );
    let kdc = LogSpecs::for_program(Some(&k), Some(&c), "kdc");
    assert_eq!(kdc.specs, ["FILE:/a.log", "FILE:/b.log"]);
    let admin = LogSpecs::for_program(Some(&k), Some(&c), "admin_server");
    assert_eq!(admin.specs, ["FILE=/k.log"]);
    assert!(!kdc.debug);
}

#[test]
fn default_only_when_the_program_has_no_relation_anywhere() {
    let (k, c) = logging_conf(
        "[logging]\n    kdc = STDERR\n",
        "[logging]\n    default = FILE:/var/log/krb5libs.log\n",
    );
    assert_eq!(
        LogSpecs::for_program(Some(&k), Some(&c), "admin_server").specs,
        ["FILE:/var/log/krb5libs.log"]
    );
    assert_eq!(
        LogSpecs::for_program(Some(&k), Some(&c), "kdc").specs,
        ["STDERR"]
    );
    assert_eq!(
        LogSpecs::for_program(None, None, "kdc"),
        LogSpecs::default()
    );
}

#[test]
fn fedora_krb5_conf_routes_both_daemons_to_files() {
    let fedora = "includedir /nonexistent-not-read-by-parse/\n\n[logging]\n    default = FILE:/var/log/krb5libs.log\n    kdc = FILE:/var/log/krb5kdc.log\n    admin_server = FILE:/var/log/kadmind.log\n\n[libdefaults]\n    dns_lookup_realm = false\n";
    let c = Krb5Conf::parse(fedora).unwrap();
    let k = KdcConf::parse("[kdcdefaults]\n    kdc_ports = 88\n").unwrap();
    assert_eq!(
        LogSpecs::for_program(Some(&k), Some(&c), "kdc").specs,
        ["FILE:/var/log/krb5kdc.log"]
    );
    assert_eq!(
        LogSpecs::for_program(Some(&k), Some(&c), "admin_server").specs,
        ["FILE:/var/log/kadmind.log"]
    );
}

#[test]
fn debug_is_the_first_value_as_a_profile_boolean() {
    for (v, want) in [
        ("T", true),
        ("y", true),
        ("on", true),
        ("nil", false),
        ("maybe", false),
    ] {
        let k = KdcConf::parse(&format!("[logging]\n    debug = {v}\n    debug = true\n")).unwrap();
        assert_eq!(
            LogSpecs::for_program(Some(&k), None, "kdc").debug,
            want,
            "{v}"
        );
    }
}

#[test]
fn relation_names_are_case_sensitive_as_in_the_profile_library() {
    let k = KdcConf::parse("[logging]\n    KDC = FILE:/upper.log\n").unwrap();
    assert_eq!(
        LogSpecs::for_program(Some(&k), None, "kdc").specs,
        Vec::<String>::new()
    );
}
