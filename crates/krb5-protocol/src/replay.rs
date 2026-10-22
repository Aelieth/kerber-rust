use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use krb5_crypto::{EncryptionType, checksum_output_size};

const TAG_MAX: usize = 24;
const FILE2_TAG_LEN: usize = 12;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ReplayKey {
    len: u8,
    tag: [u8; TAG_MAX],
}

impl ReplayKey {
    /// A tag held whole, as MIT's memory cache holds it; past 24 bytes only those are kept.
    #[must_use]
    pub fn tag(bytes: &[u8]) -> Self {
        let n = bytes.len().min(TAG_MAX);
        let mut tag = [0; TAG_MAX];
        tag[..n].copy_from_slice(&bytes[..n]);
        Self {
            len: u8::try_from(n).unwrap_or(u8::MAX),
            tag,
        }
    }

    // MIT k5_rc_tag_from_ciphertext; see docs/parity/b1-client.md
    #[must_use]
    pub fn from_ciphertext(etype: EncryptionType, cipher: &[u8]) -> Option<Self> {
        let len = checksum_output_size(etype.checksum_type())?;
        let at = cipher.len().checked_sub(len)?;
        Some(Self::tag(&cipher[at..]))
    }

    // MIT k5_rcfile2_store; see docs/parity/b1-client.md
    #[must_use]
    pub fn file2(self) -> Self {
        let mut tag = [0; TAG_MAX];
        tag[..FILE2_TAG_LEN].copy_from_slice(&self.tag[..FILE2_TAG_LEN]);
        Self {
            len: u8::try_from(FILE2_TAG_LEN).unwrap_or(u8::MAX),
            tag,
        }
    }
}

/// Shared replay detector. `Clone` shares the same cache (does not fork state).
#[derive(Clone, Debug)]
pub struct ReplayCache {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    seen: HashSet<ReplayKey>,
    buckets: VecDeque<(u64, Vec<ReplayKey>)>,
    max_entries: usize,
    start: Instant,
    ahead: u64,
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayCache {
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(250_000)
    }

    #[must_use]
    pub fn with_limits(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                seen: HashSet::new(),
                buckets: VecDeque::new(),
                max_entries: max_entries.max(1),
                start: Instant::now(),
                ahead: 0,
            })),
        }
    }

    /// `true` for a replay. Unlike MIT's cache, a full one refuses every new tag.
    // MIT k5_memrcache_store; see docs/parity/b1-client.md
    #[must_use]
    pub fn check_and_store(&self, key: ReplayKey, skew: i64) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return true;
        };
        if g.seen.contains(&key) {
            return true;
        }
        let now = g.start.elapsed().as_secs() + g.ahead;
        while g.buckets.front().is_some_and(|(expiry, _)| *expiry < now) {
            if let Some((_, keys)) = g.buckets.pop_front() {
                for k in keys {
                    g.seen.remove(&k);
                }
            }
        }
        if g.seen.len() >= g.max_entries {
            return true;
        }
        let expiry = now + u64::try_from(skew).unwrap_or(0);
        match g.buckets.back_mut() {
            Some((e, keys)) if *e == expiry => keys.push(key),
            _ => g.buckets.push_back((expiry, vec![key])),
        }
        if g.seen.len() == 1_024 {
            // Room for 28,672 tags at once: churn just past half full would grow the set again.
            g.seen.reserve(28_672 - 1_024);
            g.buckets.reserve(512);
        }
        g.seen.insert(key);
        false
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.seen.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    fn advance(&self, secs: u64) {
        if let Ok(mut g) = self.inner.lock() {
            g.ahead += secs;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> ReplayKey {
        ReplayKey::tag(&[tag; 12])
    }

    #[test]
    fn window_prune_is_not_replay() {
        let cache = ReplayCache::with_limits(8);
        let k = key(1);
        assert!(!cache.check_and_store(k, 1));
        cache.advance(1);
        assert!(
            cache.check_and_store(k, 1),
            "a tag is a replay up to its skew"
        );
        cache.advance(1);
        assert!(
            cache.check_and_store(k, 1),
            "a held tag is looked up before the expired ones go"
        );
        assert!(!cache.check_and_store(key(2), 1));
        assert!(
            !cache.check_and_store(k, 1),
            "entries older than their skew must not count as replays"
        );
    }

    #[test]
    fn cap_evicts_oldest_not_grow() {
        let cache = ReplayCache::with_limits(2);
        let a = key(1);
        let b = key(2);
        let c = key(3);
        assert!(!cache.check_and_store(a, 60));
        assert!(!cache.check_and_store(b, 60));
        assert!(
            cache.check_and_store(c, 60),
            "a new tag is refused while the cache is full"
        );
        assert_eq!(cache.len(), 2, "cap must not grow unbounded");
        assert!(cache.check_and_store(a, 60), "a held tag is still a replay");
        cache.advance(61);
        assert!(
            !cache.check_and_store(c, 60),
            "room comes back as tags expire"
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn poison_fails_closed() {
        let cache = ReplayCache::with_limits(8);
        let inner = Arc::clone(&cache.inner);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = inner.lock().unwrap();
            panic!("poison");
        }));
        assert!(
            cache.check_and_store(key(1), 60),
            "a poisoned lock must be treated as a replay"
        );
    }
}
