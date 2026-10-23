use super::*;

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
    assert_eq!(
        rc4.permitted_enctypes,
        Some(vec!["aes256-cts".to_owned(), "arcfour-hmac".to_owned()])
    );
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
    assert_eq!(elsewhere.permitted_enctypes, None);
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

#[test]
fn libdefaults_does_not_honour_kdcdefaults_knobs() {
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
    assert_eq!(lib.kdc_listen, "88");
    assert_eq!(lib.kdc_tcp_listen, None);
    assert!(lib.reject_bad_transit, "reject_bad_transit default kept");
    assert_eq!(lib.allow_rc4, Some(true));
    let kdc = KdcConf::parse(
        r"
[kdcdefaults]
    kdc_ports = 12345
    reject_bad_transit = false
",
    )
    .unwrap();
    assert_eq!(kdc.kdc_listen, "12345");
    assert!(kdc.reject_bad_transit);
}

#[test]
fn realm_booleans_win_over_later_kdcdefaults() {
    let conf = KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        restrict_anonymous_to_tgt = false
        disable_pac = false
        reject_bad_transit = false
    }
[kdcdefaults]
    restrict_anonymous_to_tgt = true
    disable_pac = true
    reject_bad_transit = true
",
    )
    .unwrap();
    assert!(!conf.restrict_anon);
    assert!(!conf.disable_pac);
    assert!(!conf.reject_bad_transit);
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
    assert!(
        !kdc.disable_pac,
        "MIT reads disable_pac from the realm stanza only"
    );
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
fn dns_canonicalize_hostname_is_mits_tristate() {
    use crate::CanonHost;
    let unset = Krb5Conf::parse("[libdefaults]\n    default_realm = KERBER.TEST\n").unwrap();
    assert_eq!(unset.dns_canonicalize_hostname, CanonHost::True);
    let set = |v: &str| {
        Krb5Conf::parse(&format!(
            "[libdefaults]\n    dns_canonicalize_hostname = {v}\n"
        ))
        .unwrap()
        .dns_canonicalize_hostname
    };
    for v in ["fallback", "Fallback", "FALLBACK"] {
        assert_eq!(set(v), CanonHost::Fallback, "{v}");
    }
    for v in ["true", "T", "yes", "y", "1", "on"] {
        assert_eq!(set(v), CanonHost::True, "{v}");
    }
    for v in ["false", "nil", "no", "n", "0", "off"] {
        assert_eq!(set(v), CanonHost::False, "{v}");
    }
    assert_eq!(set("f"), CanonHost::True);
    let bad = Krb5Conf::parse("[libdefaults]\n    dns_canonicalize_hostname = f\n").unwrap();
    assert_eq!(bad.context_refusal, Some(crate::ProfileError::BadTristate));
}

#[test]
fn the_context_refuses_a_profile_as_mits_does() {
    use crate::ProfileError;
    let parse = |s: &str| Krb5Conf::parse(s).unwrap();
    for rel in [
        "allow_weak_crypto",
        "allow_des3",
        "allow_rc4",
        "ignore_acceptor_hostname",
        "enforce_ok_as_delegate",
    ] {
        let c = parse(&format!("[libdefaults]\n    {rel} = maybe\n"));
        assert_eq!(c.context_refusal, Some(ProfileError::BadBoolean), "{rel}");
    }
    let both =
        parse("[libdefaults]\n    dns_canonicalize_hostname = sometimes\n    allow_rc4 = maybe\n");
    assert_eq!(both.context_refusal, Some(ProfileError::BadBoolean));
    let ok = parse(
        "[libdefaults]\n    allow_weak_crypto = t\n    ignore_acceptor_hostname = Y\n    rdns = maybe\n",
    );
    assert_eq!(ok.context_refusal, None, "rdns is no context boolean");
    assert!(ok.allow_weak_crypto && ok.ignore_acceptor_hostname);
    let dir = krb5_testkit::scratch_dir("context-refusal");
    let f = dir.join("krb5.conf");
    std::fs::write(
        &f,
        "[libdefaults]\n    dns_canonicalize_hostname = sometimes\n",
    )
    .unwrap();
    let err = crate::load_krb5_conf_paths([&f]).unwrap_err();
    assert_eq!(err.init_text(), "Invalid argument");
    std::fs::write(&f, "[libdefaults]\n    allow_weak_crypto = maybe\n").unwrap();
    let err = crate::load_krb5_conf_paths([&f]).unwrap_err();
    assert_eq!(err.init_text(), "Invalid boolean value");
    std::fs::write(&f, "[libdefaults]\n    request_timeout = bogus\n").unwrap();
    let err = crate::load_krb5_conf_paths([&f]).unwrap_err();
    assert_eq!(
        err.init_text(),
        "Invalid format of Kerberos lifetime or clock skew string"
    );
    std::fs::write(&f, "[libdefaults]\n    plugin_base_dir = %{bogus}/x\n").unwrap();
    let err = crate::load_krb5_conf_paths([&f]).unwrap_err();
    assert_eq!(err.init_text(), "Invalid argument");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_contexts_first_failing_check_names_the_refusal() {
    use crate::ProfileError;
    let refusal = |s: &str| {
        Krb5Conf::parse(&format!("[libdefaults]\n{s}"))
            .unwrap()
            .context_refusal
    };
    let all = "    plugin_base_dir = %{x}\n    request_timeout = x\n    dns_canonicalize_hostname = x\n    allow_rc4 = x\n";
    assert_eq!(refusal(all), Some(ProfileError::BadBoolean));
    let no_bool =
        "    plugin_base_dir = %{x}\n    request_timeout = x\n    dns_canonicalize_hostname = x\n";
    assert_eq!(refusal(no_bool), Some(ProfileError::BadTristate));
    let no_tri = "    plugin_base_dir = %{x}\n    request_timeout = x\n";
    assert_eq!(refusal(no_tri), Some(ProfileError::BadDeltat));
    assert_eq!(
        refusal("    plugin_base_dir = %{x}\n"),
        Some(ProfileError::BadPathToken)
    );
    for good in [
        "    request_timeout = 30s\n",
        "    request_timeout = 1:00\n",
        "    plugin_base_dir = %{LIBDIR}/krb5/plugins\n",
        "    plugin_base_dir = %{LIB}/x\n",
        "    plugin_base_dir = /usr/lib/krb5/plugins\n",
    ] {
        assert_eq!(refusal(good), None, "{good}");
    }
    for bad in [
        "    plugin_base_dir = %{}/x\n",
        "    plugin_base_dir = %{TEMP\n",
        "    plugin_base_dir = %{LIBDIRX}/x\n",
    ] {
        assert_eq!(refusal(bad), Some(ProfileError::BadPathToken), "{bad}");
    }
}

#[test]
fn the_context_reads_only_top_level_relations_by_name() {
    let parse = |s: &str| Krb5Conf::parse(s).unwrap();
    for text in [
        "[libdefaults]\n    KERBER.TEST = {\n        allow_weak_crypto = maybe\n    }\n",
        "[libdefaults]\n    KERBER.TEST =\n    {\n        dns_canonicalize_hostname = sometimes\n    }\n",
        "[libdefaults]\n    Allow_Weak_Crypto = maybe\n",
        "[libdefaults]\n    Request_Timeout = bogus\n",
        "[LibDefaults]\n    allow_weak_crypto = maybe\n",
    ] {
        let c = parse(text);
        assert_eq!(c.context_refusal, None, "{text}");
        assert!(!c.allow_weak_crypto, "{text}");
    }
    let after = parse(
        "[libdefaults]\n    R = {\n        allow_weak_crypto = maybe\n        qualify_shortname = sub.test\n    }\n    allow_weak_crypto = true\n",
    );
    assert_eq!(after.context_refusal, None);
    assert!(
        after.allow_weak_crypto,
        "the top-level relation after the subsection"
    );
    assert_eq!(after.qualify_shortname, None);
}

#[test]
fn only_a_lone_brace_opens_a_subsection_and_a_star_ends_a_name() {
    let parse = |s: &str| Krb5Conf::parse(s).unwrap();
    for text in [
        "[libdefaults]\n    default_tkt_enctypes = {aes}\n    allow_weak_crypto = maybe\n",
        "[libdefaults]\n    default_tkt_enctypes = \"{\"\n    allow_weak_crypto = maybe\n",
        "[libdefaults]\n    KERBER.TEST = { # c\n    allow_weak_crypto = maybe\n",
        "[libdefaults]\n    allow_weak_crypto* = maybe\n",
        "[libdefaults]\n    allow_weak_crypto*x = maybe\n",
    ] {
        assert_eq!(
            parse(text).context_refusal,
            Some(crate::ProfileError::BadBoolean),
            "{text}"
        );
    }
    let blanks =
        parse("[libdefaults]\n    KERBER.TEST = {  \t\n        allow_weak_crypto = maybe\n    }\n");
    assert_eq!(
        blanks.context_refusal, None,
        "a `{{` with blanks after it opens one"
    );
    assert_eq!(
        parse("[libdefaults]\n    default_tkt_enctypes = {aes}\n").default_tkt_enctypes,
        parse("[libdefaults]\n    default_tkt_enctypes = \"{aes}\"\n").default_tkt_enctypes,
    );
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
    let c = KdcConf::parse("[kdcdefaults]\n    kdc_ports = 750,88\n").unwrap();
    assert_eq!(c.kdc_udp_listeners().unwrap(), vec![wild(750), wild(88)]);
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(750), wild(88)]);
    let c = KdcConf::parse(
        "[kdcdefaults]\n    kdc_ports = 750,88\n[realms]\n    R = {\n        kdc_listen = 127.0.0.2:8888 3333\n        kdc_tcp_listen = 9999\n    }\n",
    )
    .unwrap();
    assert_eq!(
        c.kdc_udp_listeners().unwrap(),
        vec![at("127.0.0.2", 8888), wild(3333)]
    );
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(9999)]);
    let c = KdcConf::parse("[kdcdefaults]\n    kdc_tcp_ports = 7777\n").unwrap();
    assert_eq!(c.kdc_udp_listeners().unwrap(), vec![wild(88)]);
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(7777)]);
    let c = KdcConf::default();
    assert_eq!(c.kdc_udp_listeners().unwrap(), vec![wild(88)]);
    assert_eq!(c.kdc_tcp_listeners().unwrap(), vec![wild(88)]);
}

#[test]
fn kadmind_port_follows_admin_server_then_kadmind_port() {
    use crate::KadmindListen;
    let p = Krb5Conf::parse_files(&["[realms]\n    R = {\n        kadmind_port = 7749\n    }\n"])
        .unwrap();
    assert_eq!(
        KadmindListen::for_realm(Some(&p), "R", None).kadmind_port,
        7749
    );
    assert_eq!(
        KadmindListen::for_realm(Some(&p), "R", Some(5749)).kadmind_port,
        5749
    );
    let p = Krb5Conf::parse_files(&[
        "[realms]\n    R = {\n        admin_server = kdc.example.com:6749\n        kadmind_port = 7749\n    }\n",
        "[realms]\n    R = {\n        admin_server = other:8749\n    }\n",
    ])
    .unwrap();
    assert_eq!(
        KadmindListen::for_realm(Some(&p), "R", Some(5749)).kadmind_port,
        8749
    );
    assert_eq!(KadmindListen::for_realm(None, "R", None).kadmind_port, 749);
}

#[test]
fn a_relation_with_no_value_needs_its_brace_on_the_next_line() {
    let bad = Krb5Conf::parse("[libdefaults]\n    kcm_socket =\n    default_realm = X.TEST\n");
    assert!(
        matches!(
            bad,
            Err(crate::Error::Profile(crate::ProfileError::Syntax, _))
        ),
        "a relation with no value parsed"
    );
    let realms = "[realms]\n    X.TEST =\n    {\n        kdc = k.x.test\n    }\n";
    let c = Krb5Conf::parse(realms).unwrap();
    assert_eq!(c.kdcs_for("X.TEST").unwrap()[0].host, "k.x.test");
    let crlf = Krb5Conf::parse(&realms.replace('\n', "\r\n")).unwrap();
    assert_eq!(crlf.kdcs_for("X.TEST").unwrap()[0].host, "k.x.test");
    let bare_crlf = "[libdefaults]\r\n    kcm_socket =\r\n    default_realm = X.TEST\r\n";
    assert!(
        matches!(
            Krb5Conf::parse(bare_crlf),
            Err(crate::Error::Profile(crate::ProfileError::Syntax, _))
        ),
        "a CRLF relation with no value parsed"
    );
    let quoted = Krb5Conf::parse("[libdefaults]\n    kcm_socket = \"\"\n").unwrap();
    assert_eq!(quoted.kcm_socket.as_deref(), Some(""));
    let before = Krb5Conf::parse("stray =\n[libdefaults]\n    default_realm = X.TEST\n").unwrap();
    assert_eq!(before.default_realm.as_deref(), Some("X.TEST"));
}

#[test]
fn kdc_conf_takes_the_subsection_brace_rule() {
    let two_line = "[realms]\n    R =\n    {\n        max_life = 2h\n    }\n";
    let conf = crate::KdcConf::parse(two_line).unwrap();
    assert_eq!(conf.realm, "R");
    assert_eq!(conf.max_life, 7200);
    let crlf = crate::KdcConf::parse(&two_line.replace('\n', "\r\n")).unwrap();
    assert_eq!(crlf.max_life, 7200);
    assert!(matches!(
        crate::KdcConf::parse("[realms]\n    R =\n    max_life = 2h\n"),
        Err(crate::Error::Profile(crate::ProfileError::Syntax, _))
    ));
}

#[test]
fn a_profile_that_is_not_utf8_loads() {
    let dir = krb5_testkit::scratch_dir("profile-latin1");
    let latin1 = |body: &str| [&b"# caf\xe9 \xff\n"[..], body.as_bytes()].concat();
    let main = dir.join("krb5.conf");
    std::fs::write(&main, latin1("[libdefaults]\n    default_realm = X.TEST\n")).unwrap();
    let conf = Krb5Conf::load_file(&main).unwrap();
    assert_eq!(conf.default_realm.as_deref(), Some("X.TEST"));
    let inc = dir.join("inc.conf");
    std::fs::write(&inc, format!("include {}\n", main.display())).unwrap();
    let included = crate::load_krb5_conf_paths([&inc]).unwrap();
    assert_eq!(included.default_realm.as_deref(), Some("X.TEST"));
    let kdc = dir.join("kdc.conf");
    std::fs::write(
        &kdc,
        latin1("[realms]\n    X.TEST = {\n        max_life = 2h\n        database_name = /x/db\n    }\n"),
    )
    .unwrap();
    assert_eq!(crate::KdcConf::load_file(&kdc).unwrap().max_life, 7200);
    let vars = [("KRB5_KDC_PROFILE", kdc.to_str().unwrap())];
    let paths = resolve_paths(&vars, Some("X.TEST"), None).unwrap();
    assert_eq!(paths.database_name, std::path::Path::new("/x/db"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unreadable_file_is_skipped_unless_no_file_loads() {
    use std::os::unix::fs::PermissionsExt as _;
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipped: root reads a mode 000 file");
        return;
    }
    let dir = krb5_testkit::scratch_dir("profile-unreadable");
    let unread = dir.join("unread.conf");
    std::fs::write(&unread, "[libdefaults]\n    default_realm = HIDDEN.TEST\n").unwrap();
    std::fs::set_permissions(&unread, std::fs::Permissions::from_mode(0o000)).unwrap();
    let main = dir.join("krb5.conf");
    std::fs::write(&main, "[libdefaults]\n    default_realm = KERBER.TEST\n").unwrap();
    let missing = dir.join("missing.conf");
    let skipped = crate::load_krb5_conf_paths([&unread, &main]).unwrap();
    assert_eq!(skipped.default_realm.as_deref(), Some("KERBER.TEST"));
    for paths in [
        vec![&unread],
        vec![&missing, &unread],
        vec![&unread, &missing],
    ] {
        let Err(e) = crate::load_krb5_conf_paths(paths) else {
            panic!("an unreadable file loaded");
        };
        assert!(
            matches!(&e, crate::Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied),
            "{e}"
        );
        assert_eq!(e.init_text(), "Permission denied");
    }
    let Err(crate::Error::Io(e)) = crate::load_krb5_conf_paths([&missing]) else {
        panic!("a missing file loaded");
    };
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    let _ = std::fs::set_permissions(&unread, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pl_realm_subsection_does_not_write_the_top_level() {
    let c = Krb5Conf::parse(
        "[libdefaults]\n    \
         KERBER.TEST = {\n        \
         forwardable = true\n        \
         proxiable = true\n        \
         canonicalize = true\n        \
         ticket_lifetime = 1h\n        \
         renew_lifetime = 2h\n        \
         verify_ap_req_nofail = true\n        \
         preferred_preauth_types = 2\n        \
         nested = {\n            \
         forwardable = true\n        \
         }\n    \
         }\n    \
         OTHER.TEST = {\n        \
         forwardable = true\n    \
         }\n",
    )
    .unwrap();
    assert!(!c.forwardable, "realm forwardable wrote the top level");
    assert!(!c.proxiable, "realm proxiable wrote the top level");
    assert!(!c.canonicalize, "realm canonicalize wrote the top level");
    assert!(
        c.ticket_lifetime.is_none(),
        "realm ticket_lifetime wrote the top level"
    );
    assert!(
        c.renew_lifetime.is_none(),
        "realm renew_lifetime wrote the top level"
    );
    assert!(
        !c.verify_ap_req_nofail,
        "realm verify_ap_req_nofail wrote the top level"
    );
    assert!(
        c.preferred_preauth_types.is_empty(),
        "realm preferred_preauth_types wrote the top level"
    );
}

#[test]
fn pl_miscased_relation_does_not_shadow_the_exact_name() {
    let c = Krb5Conf::parse(
        "[libdefaults]\n    \
         Forwardable = false\n    \
         forwardable = true\n    \
         Clockskew = 10\n    \
         clockskew = 20\n    \
         Default_realm = NO.COM\n    \
         default_realm = YES.COM\n",
    )
    .unwrap();
    assert!(c.forwardable, "Forwardable shadowed forwardable");
    assert_eq!(c.clockskew, 20, "Clockskew shadowed clockskew");
    assert_eq!(
        c.default_realm.as_deref(),
        Some("YES.COM"),
        "Default_realm shadowed default_realm"
    );
}

#[test]
fn pl_trailing_comma_stays_in_the_value() {
    let c = Krb5Conf::parse("[libdefaults]\n    default_realm = EXAMPLE.COM,\n").unwrap();
    assert_eq!(c.default_realm.as_deref(), Some("EXAMPLE.COM,"));
}

#[test]
fn pl_per_realm_keys_read_the_realm_then_the_top_level() {
    let c = Krb5Conf::parse(
        "[libdefaults]\n    \
         forwardable = false\n    \
         proxiable = false\n    \
         canonicalize = false\n    \
         ticket_lifetime = 10h\n    \
         renew_lifetime = 7d\n    \
         noaddresses = true\n    \
         preferred_preauth_types = 2\n    \
         verify_ap_req_nofail = false\n    \
         KERBER.TEST = {\n        \
         forwardable = true\n        \
         proxiable = true\n        \
         canonicalize = true\n        \
         ticket_lifetime = 1h\n        \
         renew_lifetime = 2h\n        \
         noaddresses = false\n        \
         preferred_preauth_types = 17\n        \
         verify_ap_req_nofail = true\n        \
         Forwardable = false\n        \
         clockskew = 10\n    \
         }\n    \
         OTHER.TEST = {\n        \
         preferred_preauth_types = \"\"\n    \
         }\n",
    )
    .unwrap();
    assert!(c.forwardable_for("KERBER.TEST"));
    assert!(c.proxiable_for("KERBER.TEST"));
    assert!(c.canonicalize_for("KERBER.TEST"));
    assert_eq!(c.ticket_lifetime_for("KERBER.TEST"), Some(3600));
    assert_eq!(c.renew_lifetime_for("KERBER.TEST"), Some(2 * 3600));
    assert_eq!(c.noaddresses_for("KERBER.TEST"), Some(false));
    assert_eq!(c.preferred_preauth_for("KERBER.TEST"), Some(&[17][..]));
    assert!(c.verify_ap_req_nofail_for("KERBER.TEST"));
    assert!(!c.forwardable_for("OTHER.TEST"));
    assert_eq!(c.ticket_lifetime_for("OTHER.TEST"), Some(10 * 3600));
    assert_eq!(c.renew_lifetime_for("OTHER.TEST"), Some(7 * 24 * 3600));
    assert_eq!(c.noaddresses_for("OTHER.TEST"), Some(true));
    assert_eq!(c.preferred_preauth_for("OTHER.TEST"), Some(&[][..]));
    assert!(!c.verify_ap_req_nofail_for("ABSENT.TEST"));
    assert_eq!(c.noaddresses, Some(true));
    assert!(!c.forwardable);
    assert_eq!(c.clockskew, 300);
    assert!(c.realm_libdefaults.contains_key("KERBER.TEST"));
    assert!(!c.realm_libdefaults.contains_key("nested"));
}

#[test]
fn dns_lookup_kdc_defaults_on_and_dns_fallback_fills_an_unset_relation() {
    let unset = Krb5Conf::parse("[libdefaults]\n    default_realm = KERBER.TEST\n").unwrap();
    assert!(unset.dns_lookup_kdc);
    let fallback_off = Krb5Conf::parse("[libdefaults]\n    dns_fallback = false\n").unwrap();
    assert!(!fallback_off.dns_lookup_kdc);
    let fallback_on = Krb5Conf::parse("[libdefaults]\n    dns_fallback = true\n").unwrap();
    assert!(fallback_on.dns_lookup_kdc);
    let named =
        Krb5Conf::parse("[libdefaults]\n    dns_fallback = true\n    dns_lookup_kdc = false\n")
            .unwrap();
    assert!(!named.dns_lookup_kdc);
    let named_first =
        Krb5Conf::parse("[libdefaults]\n    dns_lookup_kdc = false\n    dns_fallback = true\n")
            .unwrap();
    assert!(!named_first.dns_lookup_kdc);
    assert!(!Krb5Conf::new().dns_lookup_kdc);
}
