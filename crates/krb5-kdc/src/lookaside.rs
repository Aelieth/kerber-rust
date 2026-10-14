//! MIT `kdc/replay.c` lookaside reply cache: a retransmitted request, keyed by
//! its exact request bytes, is answered from the cache instead of re-processed.
//!
//! MIT's KDC is single-threaded, so `kdc/replay.c` uses no locking; the KDC's
//! one net-server loop owns its [`Lookaside`] in its dispatcher
//! ([`crate::issue::KdcDispatch`]) and uses none either. Direct callers of
//! `issue_as`/`issue_tgs`/`handle_request` bypass the cache, as MIT's request
//! processing does.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// MIT `STALE_TIME` (`kdc/replay.c:59-59`): two minutes.
pub(crate) const STALE_TIME: Duration = Duration::from_secs(120);
/// MIT `LOOKASIDE_MAX_SIZE` (`kdc/replay.c:44-44`): 10 MiB.
pub(crate) const MAX_SIZE: usize = 10 * 1024 * 1024;
/// Rough per-entry overhead, standing in for MIT's `sizeof(struct entry)`.
const ENTRY_OVERHEAD: usize = 64;

struct Entry {
    timein: Instant,
    /// `None` marks a request that is still being processed (MIT inserts a
    /// NULL reply); `Some` is a completed reply to resend.
    reply: Option<Vec<u8>>,
    /// The entry's place in the queue: slot `seq - head` of `order`.
    seq: u64,
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
pub(crate) struct Lookaside {
    map: HashMap<Arc<[u8]>, Entry>,
    /// The FIFO MIT keeps in `expiration_queue`, oldest first; slot `i` holds the entry whose
    /// `seq` is `head + i`. A discarded entry's slot is emptied at once, so it keeps none of the
    /// request's bytes, and is dropped when it reaches the front.
    order: VecDeque<Option<Arc<[u8]>>>,
    /// The `seq` of `order`'s first slot.
    head: u64,
    total: usize,
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
            head: 0,
            total: 0,
            max_size,
            stale,
            full_logged: false,
        }
    }

    /// MIT `kdc_check_lookaside` + the `kdc_insert_lookaside(pkt, NULL)` marker:
    /// a hit resends the cached reply, an in-progress hit drops the duplicate,
    /// and a miss records an in-progress marker so a concurrent duplicate is
    /// dropped while this request is processed.
    pub(crate) fn check_or_mark(&mut self, req: &[u8]) -> Check {
        if let Some(e) = self.map.get(req) {
            return match &e.reply {
                Some(reply) => Check::Hit(reply.clone()),
                None => Check::InProgress,
            };
        }
        self.insert(Arc::from(req), None);
        Check::Fresh
    }

    /// MIT `finish_dispatch_cache`: drop the in-progress marker and cache the
    /// produced reply. A reply of `None` (a drop, or an internal error) caches
    /// nothing, like MIT removing the marker without inserting a response.
    /// MIT `finish_dispatch_cache` (`dispatch.c:78-83`): the marker is removed whole, then a reply is inserted as a new entry at the queue's tail.
    pub fn finish(&mut self, req: &[u8], reply: Option<&[u8]>) {
        let key = self.discard(req);
        if let Some(bytes) = reply
            && !bytes.is_empty()
        {
            self.insert(key.unwrap_or_else(|| Arc::from(req)), Some(bytes));
        }
    }

    /// Remove `req`'s entry from the map and empty its queue slot, returning the request's bytes
    /// for reuse.
    /// MIT `discard_entry` (`kdc/replay.c:118-125`): an entry leaves the hash table and the expiration queue together, and its bytes go with it.
    fn discard(&mut self, req: &[u8]) -> Option<Arc<[u8]>> {
        let (key, e) = self.map.remove_entry(req)?;
        self.total -= e.size;
        let slot = e
            .seq
            .checked_sub(self.head)
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| self.order.get_mut(i));
        if let Some(slot) = slot {
            *slot = None;
        }
        Some(key)
    }

    fn insert(&mut self, key: Arc<[u8]>, reply: Option<&[u8]>) {
        let size = ENTRY_OVERHEAD + key.len() + reply.map_or(0, <[u8]>::len);
        self.evict(size);
        let seq = self.head + u64::try_from(self.order.len()).unwrap_or(u64::MAX);
        self.order.push_back(Some(Arc::clone(&key)));
        self.total += size;
        self.map.insert(
            key,
            Entry {
                timein: Instant::now(),
                reply: reply.map(<[u8]>::to_vec),
                seq,
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
            event = krb5_log::events::KDC_LOOKASIDE_FULL,
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
        while let Some(front) = self.order.front() {
            let live = front
                .as_ref()
                .and_then(|key| self.map.get(&**key))
                .filter(|e| e.seq == self.head)
                .map(|e| (now.duration_since(e.timein) > self.stale, e.size));
            if let Some((stale, size)) = live {
                if !stale && self.total + incoming <= self.max_size {
                    break;
                }
                if let Some(Some(key)) = self.order.pop_front() {
                    self.map.remove(&*key);
                }
                self.total -= size;
                if !stale {
                    self.note_full();
                }
            } else {
                self.order.pop_front();
            }
            self.head += 1;
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

    /// Each request's bytes are held once: by the map's key and the queue slot that share them.
    /// Before, the marker's queue slot kept a second copy of every request until it reached the
    /// front, and a dropped request's copy too, none of it counted in `total`.
    #[test]
    fn the_request_bytes_are_held_once() {
        let mut c = Lookaside::new();
        assert!(matches!(c.check_or_mark(b"answered"), Check::Fresh));
        c.finish(b"answered", Some(b"reply"));
        assert!(matches!(c.check_or_mark(b"dropped"), Check::Fresh));
        c.finish(b"dropped", None);
        let held: Vec<&Arc<[u8]>> = c.order.iter().flatten().collect();
        assert_eq!(
            held.len(),
            1,
            "one slot holds bytes: the answered request's"
        );
        let (key, _) = c.map.get_key_value(&b"answered"[..]).expect("cached");
        assert!(
            Arc::ptr_eq(key, held[0]),
            "the map and the slot share one allocation"
        );
        assert_eq!(Arc::strong_count(key), 2);
        assert_eq!(c.map.len(), 1);
        assert_eq!(c.total, ENTRY_OVERHEAD + b"answered".len() + b"reply".len());
    }

    /// An emptied slot is dropped when it reaches the front, so the queue does not grow with
    /// the requests the cache no longer holds.
    #[test]
    fn emptied_slots_leave_the_queue_from_the_front() {
        let mut c = Lookaside::with_limits(MAX_SIZE, Duration::from_millis(1));
        for req in [&b"one"[..], b"two", b"three"] {
            c.check_or_mark(req);
            c.finish(req, Some(b"r"));
        }
        std::thread::sleep(Duration::from_millis(5));
        c.check_or_mark(b"four");
        // The three stale entries are purged; the queue holds only "four"'s marker.
        assert_eq!(c.order.len(), 1);
        assert_eq!(c.map.len(), 1);
        assert!(matches!(c.check_or_mark(b"four"), Check::InProgress));
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
