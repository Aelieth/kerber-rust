//! Process-global MEMORY ccache (`cc_memory.c`).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::ccache::FileCcache;

fn table() -> std::sync::MutexGuard<'static, HashMap<String, FileCcache>> {
    static TABLE: OnceLock<Mutex<HashMap<String, FileCcache>>> = OnceLock::new();
    TABLE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Store a named MEMORY cache.
pub fn memory_store(name: impl Into<String>, cc: FileCcache) {
    table().insert(name.into(), cc);
}

/// Clone a named MEMORY cache.
#[must_use]
pub fn memory_retrieve(name: &str) -> Option<FileCcache> {
    table().get(name).cloned()
}

/// Drop a named MEMORY cache. Returns whether it existed.
#[must_use]
pub fn memory_destroy(name: &str) -> bool {
    table().remove(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileCcache, parse_principal, realm};

    #[test]
    fn memory_named_store_retrieve_destroy() {
        let (n, r) = parse_principal("user@KERBER.TEST").unwrap();
        let primary = (realm(&r), n);
        let cc = FileCcache::new(primary.clone(), Vec::new());
        let name = format!("g8a-{}", std::process::id());
        memory_store(&name, cc);
        let got = memory_retrieve(&name).expect("stored");
        assert_eq!(
            FileCcache::format_principal(&got.primary.0, &got.primary.1),
            "user@KERBER.TEST"
        );
        assert!(memory_destroy(&name));
        assert!(memory_retrieve(&name).is_none());
        assert!(!memory_destroy(&name));
    }
}
