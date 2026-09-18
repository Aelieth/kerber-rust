//! On-disk include-tree and discover_kdc_in integration tests.

use std::path::PathBuf;

use krb5_config::{Error, Krb5Conf, discover_kdc_in, load_krb5_conf_paths};
use krb5_testkit::scratch_dir;

fn g9a_tree(tag: &str) -> PathBuf {
    let p = scratch_dir("discover-kdc").join(format!(
        "kerber-g9a-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn discover_kdc_in_reads_realms_stanza() {
    let dir = scratch_dir("discover-kdc");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!(
        "kerber-krb5-conf-{}-{}.conf",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(
        &path,
        r"
[realms]
    KERBER.TEST = {
        kdc = 10.9.8.7:1088
    }
",
    )
    .unwrap();
    let ep = discover_kdc_in([&path], "KERBER.TEST").unwrap();
    assert_eq!(ep.host, "10.9.8.7");
    assert_eq!(ep.port, 1088);
    assert!(discover_kdc_in([&path], "OTHER.TEST").is_none());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn includedir_reads_dotted_conf() {
    let root = g9a_tree("dot");
    let drop = root.join("d.d");
    std::fs::create_dir(&drop).unwrap();
    std::fs::write(
        root.join("main.conf"),
        format!(
            "includedir {}\n[libdefaults]\n    dns_lookup_kdc = false\n",
            drop.display()
        ),
    )
    .unwrap();
    std::fs::write(
        drop.join("10.conf"),
        r"
[libdefaults]
    default_realm = DOTTED.TEST
[realms]
    DOTTED.TEST = {
        kdc = 10.9.8.7:1088
    }
",
    )
    .unwrap();
    let c = Krb5Conf::load_file(root.join("main.conf")).unwrap();
    assert_eq!(c.default_realm.as_deref(), Some("DOTTED.TEST"));
    assert_eq!(c.kdcs["DOTTED.TEST"][0].host, "10.9.8.7");
    assert_eq!(c.kdcs["DOTTED.TEST"][0].port, 1088);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn two_file_merge_first_wins_scalar_appends_kdc() {
    let root = g9a_tree("merge");
    let a = root.join("a.conf");
    let b = root.join("b.conf");
    std::fs::write(
        &a,
        r"
[libdefaults]
    default_realm = FIRST.TEST
[realms]
    FIRST.TEST = {
        kdc = 10.0.0.1
        kdc = 10.0.0.2
    }
",
    )
    .unwrap();
    std::fs::write(
        &b,
        r"
[libdefaults]
    default_realm = SECOND.TEST
[realms]
    FIRST.TEST = {
        kdc = 10.0.0.3
    }
",
    )
    .unwrap();
    let c = load_krb5_conf_paths([&a, &b]).unwrap();
    assert_eq!(c.default_realm.as_deref(), Some("FIRST.TEST"));
    let kdcs: Vec<_> = c.kdcs["FIRST.TEST"]
        .iter()
        .map(|e| e.host.as_str())
        .collect();
    assert_eq!(kdcs, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    let rev = load_krb5_conf_paths([&b, &a]).unwrap();
    assert_eq!(rev.default_realm.as_deref(), Some("SECOND.TEST"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn include_then_local_keeps_included_scalar() {
    let root = g9a_tree("inc");
    let child = root.join("child.conf");
    let parent = root.join("parent.conf");
    std::fs::write(&child, "[libdefaults]\n    default_realm = CHILD.TEST\n").unwrap();
    std::fs::write(
        &parent,
        format!(
            "include {}\n[libdefaults]\n    default_realm = PARENT.TEST\n",
            child.display()
        ),
    )
    .unwrap();
    let c = Krb5Conf::load_file(&parent).unwrap();
    assert_eq!(c.default_realm.as_deref(), Some("CHILD.TEST"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn include_cycle_is_error() {
    let root = g9a_tree("cyc");
    let a = root.join("a.conf");
    let b = root.join("b.conf");
    std::fs::write(
        &a,
        format!(
            "include {}\n[libdefaults]\n    default_realm = A.TEST\n",
            b.display()
        ),
    )
    .unwrap();
    std::fs::write(
        &b,
        format!(
            "include {}\n[libdefaults]\n    default_realm = B.TEST\n",
            a.display()
        ),
    )
    .unwrap();
    let err = Krb5Conf::load_file(&a).unwrap_err();
    assert!(
        matches!(err, Error::Parse(ref s) if s.contains("cycle")),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn missing_include_is_error() {
    let root = g9a_tree("miss");
    let main = root.join("main.conf");
    std::fs::write(
        &main,
        format!(
            "include {}\n[libdefaults]\n    default_realm = X.TEST\n",
            root.join("nope.conf").display()
        ),
    )
    .unwrap();
    assert!(Krb5Conf::load_file(&main).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn missing_include_on_multi_path_is_error() {
    let root = g9a_tree("miss-merge");
    let bad = root.join("bad.conf");
    let other = root.join("other.conf");
    let absent = root.join("absent.conf");
    std::fs::write(
        &bad,
        format!(
            "include {}\n[libdefaults]\n    default_realm = BAD.TEST\n",
            root.join("nope.conf").display()
        ),
    )
    .unwrap();
    std::fs::write(&other, "[libdefaults]\n    default_realm = OTHER.TEST\n").unwrap();
    let err = load_krb5_conf_paths([&bad, &other]).unwrap_err();
    assert!(
        matches!(err, Error::Parse(ref s) if s.contains("include target not found")),
        "{err}"
    );
    let err2 = load_krb5_conf_paths([&other, &bad]).unwrap_err();
    assert!(
        matches!(err2, Error::Parse(ref s) if s.contains("include target not found")),
        "{err2}"
    );
    let skipped = load_krb5_conf_paths([&absent, &other]).unwrap();
    assert_eq!(skipped.default_realm.as_deref(), Some("OTHER.TEST"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn indented_include_at_file_start_is_ignored() {
    let root = g9a_tree("ind-start");
    let main = root.join("main.conf");
    std::fs::write(
        &main,
        format!(
            "    include {}\n[libdefaults]\n    default_realm = OK.TEST\n",
            root.join("nope.conf").display()
        ),
    )
    .unwrap();
    let c = Krb5Conf::load_file(&main).unwrap();
    assert_eq!(c.default_realm.as_deref(), Some("OK.TEST"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn indented_include_inside_section_is_error() {
    let root = g9a_tree("ind-sect");
    let main = root.join("main.conf");
    std::fs::write(
        &main,
        format!(
            "[libdefaults]\n    default_realm = X.TEST\n    include {}\n",
            root.join("nope.conf").display()
        ),
    )
    .unwrap();
    let err = Krb5Conf::load_file(&main).unwrap_err();
    assert!(
        matches!(err, Error::Parse(ref s) if s.contains("improper format")),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
