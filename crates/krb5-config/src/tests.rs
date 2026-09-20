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
            .contains("nope")
    );
    assert!(
        expand_ccache_params("FILE:/tmp/x_%{uid")
            .unwrap_err()
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
        parse_ccname("KEYRING:user:foo").unwrap_err(),
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
        parse_ccspec("KEYRING:persistent:1").unwrap_err(),
        KRB5_CC_UNKNOWN_TYPE
    );
    assert_eq!(parse_ccspec("KCM:").unwrap(), CcSpec::Kcm(String::new()));
    assert_eq!(parse_ccspec("KCM:0").unwrap(), CcSpec::Kcm("0".into()));
    assert_eq!(parse_ccspec("JUNK:x").unwrap_err(), KRB5_CC_UNKNOWN_TYPE);
    assert!(!parse_ccspec("KEYRING:x").unwrap_err().contains("G8"));
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
    assert_eq!(c.kdc_listen[0], "127.0.0.1:88");
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
    assert!(elsewhere.permitted_enctypes.is_empty());
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

#[test]
fn dict_file_is_a_realm_relation_only() {
    // MIT alt_prof.c:486-513: kadm5_get_config_params reads dict_file
    // under [realms] REALM; a [kdcdefaults] dict_file is not consulted
    // (live: MIT logs "No dictionary file specified").
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
    // [kdcdefaults] or a realm stanza (main.c:257-261,622-626); a copy
    // under [libdefaults] is ignored (R2-P8: no fallthrough).
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
    assert_eq!(lib.kdc_listen, vec!["127.0.0.1:88".to_string()]);
    assert_eq!(lib.kdc_tcp_listen, vec!["127.0.0.1:88".to_string()]);
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
    assert_eq!(kdc.kdc_listen, vec!["127.0.0.1:12345".to_string()]);
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
    assert!(lib.host_based_services.is_empty());
    assert!(lib.no_host_referral.is_empty());
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
    assert!(split_krb5_config_paths("").is_empty());
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
