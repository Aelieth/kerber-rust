//! MIT `kdc/replay.c` lookaside reply cache: a retransmitted request, keyed by
//! its exact request bytes, is answered from the cache instead of re-processed.
//!
//! MIT's KDC is single-threaded, so `replay.c` uses no locking; the Rust
//! listener runs the UDP and TCP paths on separate threads, so a shared
//! [`Lookaside`] is wrapped in a mutex ([`crate::listen`]). Direct callers of
//! `issue_as`/`issue_tgs`/`handle_request` bypass the cache, as MIT's request
//! processing does.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// MIT `STALE_TIME` (`replay.c:59`): two minutes.
pub const STALE_TIME: Duration = Duration::from_secs(120);
/// MIT `LOOKASIDE_MAX_SIZE` (`replay.c:44`): 10 MiB.
pub const MAX_SIZE: usize = 10 * 1024 * 1024;
/// Rough per-entry overhead, standing in for MIT's `sizeof(struct entry)`.
const ENTRY_OVERHEAD: usize = 64;

struct Entry {
    timein: Instant,
    /// `None` marks a request that is still being processed (MIT inserts a
    /// NULL reply); `Some` is a completed reply to resend.
    reply: Option<Vec<u8>>,
    generation: u64,
    size: usize,
}

/// The outcome of checking a request against the cache.
pub enum Check {
    /// A completed reply is cached; resend these bytes.
    Hit(Vec<u8>),
    /// The request is being processed already; drop this duplicate (MIT
    /// `KRB5KDC_ERR_DISCARD`).
    InProgress,
    /// Not seen before; the caller marked it in-progress and must process it,
    /// then call [`Lookaside::finish`].
    Fresh,
}

/// A bounded request→reply cache with stale-entry and total-size eviction.
/// The request bytes are held once, shared by the map and the FIFO, so memory
/// tracks MIT's accounting (`req_packet + reply_packet + sizeof(entry)`).
pub struct Lookaside {
    map: HashMap<Arc<[u8]>, Entry>,
    /// `(key, generation)` in insertion order; the FIFO MIT keeps in `expiration_queue`.
    /// Superseded pairs (whose generation no longer matches the map) are skipped
    /// lazily during eviction rather than removed eagerly.
    order: VecDeque<(Arc<[u8]>, u64)>,
    total: usize,
    next_gen: u64,
    max_size: usize,
    stale: Duration,
    /// Set once the size cap first forces an eviction; the KDC log line lets a
    /// soak tell the cache filling (bounded) from a leak (unbounded).
    full_logged: bool,
}

impl Default for Lookaside {
    fn default() -> Self {
        Self::with_limits(MAX_SIZE, STALE_TIME)
    }
}

impl Lookaside {
    /// A cache with the MIT default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A cache with explicit limits (tests exercise eviction with small ones).
    #[must_use]
    pub fn with_limits(max_size: usize, stale: Duration) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            total: 0,
            next_gen: 0,
            max_size,
            stale,
            full_logged: false,
        }
    }

    /// MIT `kdc_check_lookaside` + the `kdc_insert_lookaside(pkt, NULL)` marker:
    /// a hit resends the cached reply, an in-progress hit drops the duplicate,
    /// and a miss records an in-progress marker so a concurrent duplicate is
    /// dropped while this request is processed.
    pub fn check_or_mark(&mut self, req: &[u8]) -> Check {
        if let Some(e) = self.map.get(req) {
            return match &e.reply {
                Some(reply) => Check::Hit(reply.clone()),
                None => Check::InProgress,
            };
        }
        self.insert(req, None);
        Check::Fresh
    }

    /// MIT `finish_dispatch_cache`: drop the in-progress marker and cache the
    /// produced reply. A reply of `None` (a drop, or an internal error) caches
    /// nothing, like MIT removing the marker without inserting a response.
    pub fn finish(&mut self, req: &[u8], reply: Option<&[u8]>) {
        if let Some(e) = self.map.remove(req) {
            self.total -= e.size;
        }
        if let Some(bytes) = reply
            && !bytes.is_empty()
        {
            self.insert(req, Some(bytes));
        }
    }

    fn insert(&mut self, req: &[u8], reply: Option<&[u8]>) {
        let size = ENTRY_OVERHEAD + req.len() + reply.map_or(0, <[u8]>::len);
        self.evict(size);
        let generation = self.next_gen;
        self.next_gen += 1;
        let key: Arc<[u8]> = Arc::from(req);
        self.order.push_back((Arc::clone(&key), generation));
        self.total += size;
        self.map.insert(
            key,
            Entry {
                timein: Instant::now(),
                reply: reply.map(<[u8]>::to_vec),
                generation,
                size,
            },
        );
    }

    fn note_full(&mut self) {
        if self.full_logged {
            return;
        }
        self.full_logged = true;
        tracing::info!(
            event = "kdc.lookaside.full",
            component = "krb5-kdc",
            outcome = "ok",
            total_bytes = self.total,
            max_bytes = self.max_size,
            entries = self.map.len(),
        );
    }

    /// MIT `kdc_insert_lookaside`'s purge loop: from the oldest end, drop stale
    /// entries and keep dropping until `incoming` fits under `max_size`.
    fn evict(&mut self, incoming: usize) {
        let now = Instant::now();
        while let Some((key, generation)) = self.order.front().cloned() {
            match self.map.get(&*key) {
                None => {
                    self.order.pop_front();
                }
                Some(e) if e.generation != generation => {
                    self.order.pop_front();
                }
                Some(e) => {
                    let stale = now.duration_since(e.timein) > self.stale;
                    if !stale && self.total + incoming <= self.max_size {
                        break;
                    }
                    let size = e.size;
                    self.map.remove(&*key);
                    self.order.pop_front();
                    self.total -= size;
                    if !stale {
                        self.note_full();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_request_resends_the_cached_reply() {
        let mut c = Lookaside::new();
        assert!(matches!(c.check_or_mark(b"req"), Check::Fresh));
        c.finish(b"req", Some(b"reply"));
        match c.check_or_mark(b"req") {
            Check::Hit(r) => assert_eq!(r, b"reply"),
            _ => panic!("want Hit"),
        }
    }

    #[test]
    fn a_duplicate_while_in_progress_is_dropped() {
        let mut c = Lookaside::new();
        assert!(matches!(c.check_or_mark(b"req"), Check::Fresh));
        // Second arrival before finish: the marker is still None.
        assert!(matches!(c.check_or_mark(b"req"), Check::InProgress));
    }

    #[test]
    fn an_empty_reply_caches_nothing() {
        let mut c = Lookaside::new();
        assert!(matches!(c.check_or_mark(b"req"), Check::Fresh));
        c.finish(b"req", None);
        // Marker gone, nothing cached: the next arrival is fresh again.
        assert!(matches!(c.check_or_mark(b"req"), Check::Fresh));
    }

    #[test]
    fn stale_entries_are_evicted() {
        let mut c = Lookaside::with_limits(MAX_SIZE, Duration::from_millis(40));
        c.check_or_mark(b"old");
        c.finish(b"old", Some(b"r"));
        std::thread::sleep(Duration::from_millis(60));
        // Inserting a fresh entry purges the stale one first.
        c.check_or_mark(b"new");
        c.finish(b"new", Some(b"r"));
        assert!(matches!(c.check_or_mark(b"old"), Check::Fresh));
        match c.check_or_mark(b"new") {
            Check::Hit(_) => {}
            _ => panic!("fresh entry must survive"),
        }
    }

    #[test]
    fn the_request_bytes_are_held_once_for_the_map_and_the_fifo() {
        let mut c = Lookaside::new();
        c.check_or_mark(b"req");
        c.finish(b"req", Some(b"reply"));
        let (key, _) = c.order.back().expect("queued");
        // One allocation: the FIFO entry and the map key (the marker's key was
        // dropped by finish).
        assert_eq!(Arc::strong_count(key), 2);
        assert!(c.map.contains_key(&**key));
    }

    #[test]
    fn the_total_size_cap_evicts_oldest_first() {
        // Room for ~2 entries of overhead + 3-byte key + 10-byte reply.
        let cap = (ENTRY_OVERHEAD + 13) * 2 + 5;
        let mut c = Lookaside::with_limits(cap, STALE_TIME);
        for key in [b"aaa", b"bbb", b"ccc"] {
            c.check_or_mark(key);
            c.finish(key, Some(b"0123456789"));
        }
        // The oldest ("aaa") is evicted; the newest two remain.
        assert!(matches!(c.check_or_mark(b"aaa"), Check::Fresh));
        assert!(matches!(c.check_or_mark(b"ccc"), Check::Hit(_)));
        assert!(c.full_logged, "a size-cap eviction is logged once");
    }

    #[test]
    fn stale_eviction_alone_does_not_report_a_full_cache() {
        let mut c = Lookaside::with_limits(MAX_SIZE, Duration::from_millis(1));
        c.check_or_mark(b"old");
        c.finish(b"old", Some(b"r"));
        std::thread::sleep(Duration::from_millis(5));
        c.check_or_mark(b"new");
        assert!(!c.full_logged);
    }
}
