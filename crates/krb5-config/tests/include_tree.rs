//! On-disk include-tree integration tests.

#![allow(
    clippy::disallowed_methods,
    reason = "a test sets up its own profile and environment"
)]

use std::path::PathBuf;

use krb5_config::{Error, Krb5Conf, ProfileError};
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
        matches!(err, Error::Profile(ProfileError::IncludeFile, ref s) if s.contains("cycle")),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
