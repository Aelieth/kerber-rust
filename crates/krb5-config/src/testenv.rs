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

pub fn set_test_krb5_paths(paths: Option<Vec<PathBuf>>) {
    TEST_KRB5_PATHS.with(|c| *c.borrow_mut() = paths);
}

pub fn set_test_kdc_profile(path: Option<PathBuf>) {
    TEST_KDC_PROFILE.with(|c| *c.borrow_mut() = path);
}

const ISOLATED_KRB5: &str = "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n";

#[must_use]
pub fn isolated_profile() -> crate::Krb5Conf {
    crate::Krb5Conf::parse(ISOLATED_KRB5).unwrap_or_else(|_| crate::Krb5Conf::new())
}

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
    let _ = std::fs::write(&krb5, ISOLATED_KRB5);
    let _ = std::fs::write(&kdc, "");
    set_test_krb5_paths(Some(vec![krb5.clone()]));
    set_test_kdc_profile(Some(kdc.clone()));
    TEST_KRB5_ISOLATION.with(|c| {
        *c.borrow_mut() = Some(IsolatedKrb5 { paths: [krb5, kdc] });
    });
}
