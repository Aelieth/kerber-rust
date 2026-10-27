use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::ccache::FileCcache;

/// A poisoned lock is recovered.
fn table() -> std::sync::MutexGuard<'static, HashMap<String, FileCcache>> {
    static TABLE: OnceLock<Mutex<HashMap<String, FileCcache>>> = OnceLock::new();
    TABLE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn memory_store(name: impl Into<String>, cc: FileCcache) {
    table().insert(name.into(), cc);
}

#[must_use]
pub fn memory_retrieve(name: &str) -> Option<FileCcache> {
    table().get(name).cloned()
}

#[must_use]
pub fn memory_destroy(name: &str) -> bool {
    table().remove(name).is_some()
}
