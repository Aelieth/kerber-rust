//! Bounded, time-windowed, thread-safe replay cache.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha1::{Digest, Sha1};

/// Replay key: client, server, ctime, cusec, authenticator hash.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ReplayKey {
    /// Client principal `name@REALM`.
    pub client: String,
    /// Server principal `name@REALM`.
    pub server: String,
    /// Authenticator ctime (unix seconds).
    pub ctime: u32,
    /// Authenticator cusec.
    pub cusec: u32,
    /// SHA-1 of the authenticator ciphertext (or full authenticator DER).
    pub auth_hash: [u8; 20],
}

/// Shared replay detector. `Clone` shares the same map (does not fork state).
#[derive(Clone, Debug)]
pub struct ReplayCache {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    seen: HashMap<ReplayKey, Instant>,
    max_entries: usize,
    window: Duration,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    /// 50_000 entries, 5-minute window (typical MIT clockskew).
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(50_000, Duration::from_secs(300))
    }

    /// Custom bounds.
    #[must_use]
    pub fn with_limits(max_entries: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                seen: HashMap::new(),
                max_entries: max_entries.max(1),
                window,
            })),
        }
    }

    /// SHA-1 of authenticator ciphertext bytes.
    #[must_use]
    pub fn hash_authenticator(cipher: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(cipher);
        let out = h.finalize();
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&out);
        arr
    }

    /// Insert `key` if it has not been seen inside the window.
    ///
    /// Returns `true` if this is a replay (already present).
    #[must_use]
    pub fn check_and_store(&self, key: ReplayKey) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return true;
        };
        let now = Instant::now();
        let window = g.window;
        g.seen
            .retain(|_, t| now.saturating_duration_since(*t) < window);
        if g.seen.contains_key(&key) {
            return true;
        }
        if g.seen.len() >= g.max_entries {
            let oldest = g
                .seen
                .iter()
                .min_by_key(|(_, t)| *t)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                g.seen.remove(&oldest);
            }
        }
        g.seen.insert(key, now);
        false
    }

    /// Number of live entries (tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.seen.len())
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn key(tag: u8) -> ReplayKey {
        ReplayKey {
            client: format!("user{tag}@KERBER.TEST"),
            server: "krbtgt/KERBER.TEST@KERBER.TEST".into(),
            ctime: 1_700_000_000,
            cusec: u32::from(tag),
            auth_hash: [tag; 20],
        }
    }

    #[test]
    fn window_prune_is_not_replay() {
        let cache = ReplayCache::with_limits(8, Duration::from_millis(20));
        let k = key(1);
        assert!(!cache.check_and_store(k.clone()));
        thread::sleep(Duration::from_millis(50));
        assert!(
            !cache.check_and_store(k),
            "entries older than the window must not count as replays"
        );
    }

    #[test]
    fn cap_evicts_oldest_not_grow() {
        let cache = ReplayCache::with_limits(2, Duration::from_secs(60));
        let a = key(1);
        let b = key(2);
        let c = key(3);
        assert!(!cache.check_and_store(a.clone()));
        assert!(!cache.check_and_store(b.clone()));
        assert_eq!(cache.len(), 2);
        assert!(!cache.check_and_store(c.clone()));
        assert_eq!(cache.len(), 2, "cap must not grow unbounded");
        assert!(
            cache.check_and_store(b.clone()),
            "live entry must still be a replay"
        );
        assert!(
            cache.check_and_store(c),
            "newest live entry must still be a replay"
        );
        assert!(
            !cache.check_and_store(a),
            "evicted oldest must not count as a replay"
        );
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn poison_fails_closed() {
        let cache = ReplayCache::with_limits(8, Duration::from_secs(60));
        let inner = Arc::clone(&cache.inner);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = inner.lock().unwrap();
            panic!("poison");
        }));
        assert!(
            cache.check_and_store(key(1)),
            "a poisoned lock must be treated as a replay"
        );
    }
}
