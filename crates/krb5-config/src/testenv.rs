//! Test overlay for `krb5_conf_paths` (host `/etc/krb5.conf`
//! isolation). Process-global: `TEST_KRB5_PATHS`,
//! `TEST_KRB5_ISOLATION`, `ISOLATE_SEQ`.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    pub(super) static TEST_KRB5_PATHS: RefCell<Option<Vec<PathBuf>>> = const { RefCell::new(None) };
    static TEST_KRB5_ISOLATION: RefCell<Option<IsolatedKrb5>> = const { RefCell::new(None) };
}

static ISOLATE_SEQ: AtomicU64 = AtomicU64::new(0);

struct IsolatedKrb5 {
    path: PathBuf,
}

impl Drop for IsolatedKrb5 {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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

/// Pin a realm-only profile so host `udp_preference_limit` cannot force TCP.
pub fn isolate_test_krb5() {
    let dir = isolate_scratch_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!(
        "kerber-test-krb5-{}-{}.conf",
        std::process::id(),
        ISOLATE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::write(
        &path,
        "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n",
    );
    set_test_krb5_paths(Some(vec![path.clone()]));
    TEST_KRB5_ISOLATION.with(|c| *c.borrow_mut() = Some(IsolatedKrb5 { path }));
}
