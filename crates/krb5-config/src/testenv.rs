//! Test overlays for `krb5_conf_paths` and `kdc_conf_path` (isolation from the host's
//! `/etc/krb5.conf`, `KRB5_KDC_PROFILE` and kdc.conf). Per thread: `TEST_KRB5_PATHS`,
//! `TEST_KDC_PROFILE`, `TEST_KRB5_ISOLATION`; process-global: `ISOLATE_SEQ`.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    pub(super) static TEST_KRB5_PATHS: RefCell<Option<Vec<PathBuf>>> = const { RefCell::new(None) };
    pub(super) static TEST_KDC_PROFILE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static TEST_KRB5_ISOLATION: RefCell<Option<IsolatedKrb5>> = const { RefCell::new(None) };
}

static ISOLATE_SEQ: AtomicU64 = AtomicU64::new(0);

struct IsolatedKrb5 {
    paths: [PathBuf; 2],
}

impl Drop for IsolatedKrb5 {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn isolate_scratch_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_TMPDIR")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR")
        && !p.is_empty()
    {
        return PathBuf::from(p).join("test-krb5");
    }
    if let Ok(p) = std::env::var("KERBER_SCRATCH")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/test-krb5"
    ))
}

/// Test overlay for [`crate::krb5_conf_paths`] (avoids the host `/etc/krb5.conf`).
pub fn set_test_krb5_paths(paths: Option<Vec<PathBuf>>) {
    TEST_KRB5_PATHS.with(|c| *c.borrow_mut() = paths);
}

/// Test overlay for [`crate::kdc_conf_path`] (avoids the host's `KRB5_KDC_PROFILE` and
/// kdc.conf).
pub fn set_test_kdc_profile(path: Option<PathBuf>) {
    TEST_KDC_PROFILE.with(|c| *c.borrow_mut() = path);
}

/// Pin a realm-only krb5.conf, so a host's `udp_preference_limit` cannot force TCP, and an empty
/// KDC profile, so neither file brings in a host's `[libdefaults]` (`permitted_enctypes`, say),
/// on this thread.
pub fn isolate_test_krb5() {
    let dir = isolate_scratch_dir();
    let _ = std::fs::create_dir_all(&dir);
    let stem = format!(
        "{}-{}",
        std::process::id(),
        ISOLATE_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let krb5 = dir.join(format!("kerber-test-krb5-{stem}.conf"));
    let kdc = dir.join(format!("kerber-test-kdc-{stem}.conf"));
    let _ = std::fs::write(
        &krb5,
        "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n",
    );
    let _ = std::fs::write(&kdc, "");
    set_test_krb5_paths(Some(vec![krb5.clone()]));
    set_test_kdc_profile(Some(kdc.clone()));
    TEST_KRB5_ISOLATION.with(|c| {
        *c.borrow_mut() = Some(IsolatedKrb5 { paths: [krb5, kdc] });
    });
}
