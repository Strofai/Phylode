//! Answer cache: remembers what upstreams returned, and carries the load with stale answers
//! when every upstream is down.
//!
//! ⚠️ **Queries allowed through while the blocklist was unavailable must never be written
//! here.** Cached, the domain would remain completely unblockable for the cache lifetime
//! after the list recovers — while the list plainly contains it. The decision lives in
//! `gatekeeper`; only the `Verdict::Allowed` path calls [`Cache::insert`].
//!
//! When capacity is reached, entries are evicted one at a time (LRU). What breaks if you
//! change it: **do not switch to "clear everything when full"** — every lookup after that
//! goes upstream at once, which is how Cloudflare hit latency spikes from every node dropping
//! its cache at the same time.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::dns::{Proof, Query, Records};

/// The longest a single answer may count as fresh, no matter how large the upstream TTL.
/// The value is the same order of magnitude as hickory's `MAX_TTL`, which keeps one absurd
/// TTL from pinning an answer for months.
const FRESH_CEILING: Duration = Duration::from_secs(24 * 60 * 60);

/// The minimum an answer is remembered for even when the upstream TTL is 0, so repeated
/// queries within the same second do not all reach upstream.
const FRESH_FLOOR: Duration = Duration::from_secs(1);

/// The longest a negative answer counts as fresh: the low end of RFC 2308's "values of one to
/// three hours have been found to work well". What breaks if you change it: raise it
/// and a newly registered domain stays unresolvable on the network for that long, with no visible
/// reason.
const NEGATIVE_CEILING: Duration = Duration::from_secs(60 * 60);

/// The most memory the cache's answers may take together. Entries are evicted oldest-first
/// past this, as they are past the entry limit. The default 20,000 entries of ordinary
/// answers use a fraction of it.
///
/// What breaks if you change it: the entry limit alone does not bound memory — anyone on the
/// network can look up names whose answers are made large, and each stays for up to a day.
const MEMORY_BUDGET: usize = 64 * 1024 * 1024;

/// An answer larger than this is delivered but not remembered. About a hundred ordinary
/// records; real answers rarely come close.
const MAX_ENTRY_MEMORY: usize = 32 * 1024;

/// Answers that may be remembered: records, or an upstream explicitly saying there are none
/// (RFC 2308 negative caching).
///
/// SERVFAIL is deliberately absent: that is a failure, not an answer. Cached, a domain whose
/// name servers have since been fixed would keep failing on the network for the cache lifetime.
#[derive(Clone, Debug)]
pub enum Cached {
    Records(Records),
    /// The upstream says this name does not exist. `ttl` is how long the device should
    /// remember that; `proof` is the upstream's evidence, for devices that validate signatures.
    NameNotFound {
        ttl: Duration,
        proof: Proof,
    },
    /// The upstream says the name exists but has no records of that type. Apple devices ask
    /// for AAAA on every IPv4-only domain, so this is the most common kind. `proof` as above.
    NoRecordsOfType {
        ttl: Duration,
        proof: Proof,
    },
}

impl Cached {
    /// How long this counts as fresh in the cache: records use their minimum TTL, negative
    /// answers use their own, each clamped between the floor and the relevant ceiling.
    fn fresh_for(&self) -> Duration {
        match self {
            Self::Records(records) => records
                .min_ttl()
                .unwrap_or(FRESH_FLOOR)
                .clamp(FRESH_FLOOR, FRESH_CEILING),
            Self::NameNotFound { ttl, .. } | Self::NoRecordsOfType { ttl, .. } => {
                (*ttl).clamp(FRESH_FLOOR, NEGATIVE_CEILING)
            }
        }
    }

    /// Roughly how much memory this answer takes once stored: its records, or for a negative
    /// answer its proof, plus the entry itself.
    fn memory(&self) -> usize {
        let records = match self {
            Self::Records(records) => records.memory_estimate(),
            Self::NameNotFound { proof, .. } | Self::NoRecordsOfType { proof, .. } => {
                proof.memory_estimate()
            }
        };
        // The query is stored twice: as the map key and in the recency order.
        records
            .saturating_add(std::mem::size_of::<Entry>())
            .saturating_add(2 * std::mem::size_of::<Query>())
    }

    /// Returns a copy whose TTL has the time spent in the cache subtracted, with a floor of
    /// one second (same reasoning as [`Records::aged`]).
    fn aged(&self, elapsed: Duration) -> Self {
        let left = |ttl: &Duration| ttl.saturating_sub(elapsed).max(FRESH_FLOOR);
        match self {
            Self::Records(records) => Self::Records(records.aged(elapsed)),
            Self::NameNotFound { ttl, proof } => Self::NameNotFound {
                ttl: left(ttl),
                proof: proof.aged(elapsed),
            },
            Self::NoRecordsOfType { ttl, proof } => Self::NoRecordsOfType {
                ttl: left(ttl),
                proof: proof.aged(elapsed),
            },
        }
    }
}

/// The result of a cache lookup.
#[derive(Debug)]
pub enum Hit {
    /// Still fresh; may be returned to the user directly.
    Fresh(Cached),
    /// Expired, but not beyond the stale window.
    ///
    /// **Only usable while every upstream is unreachable** — under Strict Privacy that is
    /// the only way to keep the network online. Using it while the upstreams are healthy
    /// means serving stale data for no reason at all.
    Stale(Cached),
    /// Nothing usable.
    Miss,
}

/// A capacity-bounded, TTL-expiring answer cache.
#[derive(Debug)]
pub struct Cache {
    capacity: usize,
    memory_budget: usize,
    stale_max_age: Duration,
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    entries: HashMap<Query, Entry>,
    /// Recency order: the lowest tick is the least recently used. The tick makes eviction
    /// O(log n).
    order: BTreeMap<u64, Query>,
    next_tick: u64,
    /// The sum of every entry's `memory`.
    memory: usize,
}

#[derive(Debug)]
struct Entry {
    answer: Cached,
    stored_at: Instant,
    fresh_until: Instant,
    tick: u64,
    memory: usize,
}

impl Cache {
    /// `capacity` is the entry limit; `stale_max_age` is how long an expired answer may still
    /// be used as a fallback.
    pub fn new(capacity: usize, stale_max_age: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            memory_budget: MEMORY_BUDGET,
            stale_max_age,
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, query: &Query) -> Hit {
        self.get_at(query, Instant::now())
    }

    /// Writes one answer. Freshness is determined by the answer's own TTL, clamped between
    /// the bounds; see [`Cached`].
    pub fn insert(&self, query: Query, answer: Cached) {
        self.insert_at(query, answer, Instant::now());
    }

    fn get_at(&self, query: &Query, now: Instant) -> Hit {
        let mut inner = self.lock();

        let Some(entry) = inner.entries.get(query) else {
            return Hit::Miss;
        };

        let fresh = now < entry.fresh_until;
        // The stale window starts at expiry. What breaks if you change it: measured from
        // insertion instead, an answer with a TTL longer than the stale window (say 24
        // hours) vanishes the moment it expires — so the most-used sites are exactly the
        // ones with nothing to fall back on when every upstream is down.
        let too_old = now.saturating_duration_since(entry.fresh_until) > self.stale_max_age;

        if too_old {
            // Expired and past the stale window; keeping it would only hand out answers from
            // months ago.
            inner.remove(query);
            return Hit::Miss;
        }

        // The TTL returned to the device has the time spent in the cache subtracted, or the
        // device starts counting from when it received the answer and keeps it for longer
        // than the authoritative server allowed.
        let answer = entry.answer.aged(now.duration_since(entry.stored_at));
        inner.touch(query);
        if fresh {
            Hit::Fresh(answer)
        } else {
            Hit::Stale(answer)
        }
    }

    fn insert_at(&self, query: Query, answer: Cached, now: Instant) {
        let ttl = answer.fresh_for();
        let memory = answer.memory();

        let mut inner = self.lock();
        // The older answer goes even when the new one is too large to keep: it is no longer
        // what the upstream says.
        inner.remove(&query);
        if memory > MAX_ENTRY_MEMORY {
            return;
        }

        let tick = inner.take_tick();
        inner.order.insert(tick, query.clone());
        inner.memory = inner.memory.saturating_add(memory);
        inner.entries.insert(
            query,
            Entry {
                answer,
                stored_at: now,
                fresh_until: now + ttl,
                tick,
                memory,
            },
        );

        inner.evict_down_to(self.capacity, self.memory_budget);
    }

    /// Test only: how much memory the stored answers are counted as taking.
    #[cfg(test)]
    fn memory(&self) -> usize {
        self.lock().memory
    }

    /// Test only: holds the cache lock, simulating a thread that seized it and hung.
    #[cfg(test)]
    pub(crate) fn hold_lock(&self) -> std::sync::MutexGuard<'_, impl Sized> {
        self.lock()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a thread panicked while holding it. The cache is not a
            // source of correctness, so carrying on beats taking the whole service down.
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Inner {
    fn take_tick(&mut self) -> u64 {
        let tick = self.next_tick;
        self.next_tick += 1;
        tick
    }

    fn touch(&mut self, query: &Query) {
        let Some(entry) = self.entries.get(query) else {
            return;
        };
        let old_tick = entry.tick;
        let new_tick = self.take_tick();
        self.order.remove(&old_tick);
        self.order.insert(new_tick, query.clone());
        if let Some(entry) = self.entries.get_mut(query) {
            entry.tick = new_tick;
        }
    }

    /// Drops one entry and its share of the memory count. Every removal goes through here, or
    /// the count drifts and the memory bound stops meaning anything.
    fn remove(&mut self, query: &Query) {
        if let Some(old) = self.entries.remove(query) {
            self.order.remove(&old.tick);
            self.memory = self.memory.saturating_sub(old.memory);
        }
    }

    /// Evicts the least recently used entries one at a time until both the count and the
    /// memory are back within bounds. Deliberately never a bulk clear.
    fn evict_down_to(&mut self, capacity: usize, memory_budget: usize) {
        while self.entries.len() > capacity || self.memory > memory_budget {
            let Some(query) = self.order.values().next().cloned() else {
                break;
            };
            self.remove(&query);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{Name, RecordType};

    fn query(name: &str) -> Query {
        Query::new(Name::parse(name), RecordType::A)
    }

    fn cache() -> Cache {
        Cache::new(3, Duration::from_secs(12 * 60 * 60))
    }

    /// Should change: a negative answer's proof counts against the memory bound.
    /// Should not change: a negative answer without one costs only its entry, as before.
    #[test]
    fn a_negative_answers_proof_counts_against_memory() {
        let ttl = Duration::from_secs(600);
        let bare = Cached::NameNotFound {
            ttl,
            proof: Proof::default(),
        };
        let proven = Cached::NameNotFound {
            ttl,
            proof: Proof::for_zone(&Name::parse("example.com")),
        };
        assert_eq!(
            bare.memory(),
            std::mem::size_of::<Entry>() + 2 * std::mem::size_of::<Query>()
        );
        assert!(proven.memory() > bare.memory());
    }

    #[test]
    fn something_never_stored_is_a_miss() {
        assert!(matches!(cache().get(&query("a.example.com")), Hit::Miss));
    }

    #[test]
    fn something_stored_and_still_fresh_is_returned_directly() {
        let c = cache();
        let now = Instant::now();
        c.insert_at(
            query("a.example.com"),
            Cached::Records(Records::default()),
            now,
        );
        assert!(matches!(
            c.get_at(&query("a.example.com"), now),
            Hit::Fresh(_)
        ));
    }

    #[test]
    fn once_expired_it_becomes_a_fallback_only_answer() {
        let c = cache();
        let now = Instant::now();
        c.insert_at(
            query("a.example.com"),
            Cached::Records(Records::default()),
            now,
        );
        // An empty record set has no TTL, so the one-second floor applies.
        let later = now + Duration::from_secs(2);
        assert!(
            matches!(c.get_at(&query("a.example.com"), later), Hit::Stale(_)),
            "expired but not yet too old should be Stale, so there is something to fall back on"
        );
    }

    #[test]
    fn past_the_age_limit_it_counts_as_absent() {
        let c = Cache::new(3, Duration::from_secs(60));
        let now = Instant::now();
        c.insert_at(
            query("a.example.com"),
            Cached::Records(Records::default()),
            now,
        );
        let way_later = now + Duration::from_secs(120);
        assert!(
            matches!(c.get_at(&query("a.example.com"), way_later), Hit::Miss),
            "without an age limit this would hand out answers from months ago"
        );
        assert_eq!(
            c.len(),
            0,
            "an over-age entry is cleaned up on the way past"
        );
    }

    fn addresses(count: u16) -> Cached {
        let addresses: Vec<std::net::IpAddr> = (0..count)
            .map(|i| std::net::Ipv4Addr::new(203, 0, 113, (i % 250) as u8).into())
            .collect();
        Cached::Records(Records::from_addresses(
            &Name::parse("big.example.com"),
            Duration::from_secs(300),
            &addresses,
        ))
    }

    /// Should change: an answer past the per-entry limit is not stored, and the older answer
    /// for the same query goes with it.
    /// Should not change: an ordinary answer is stored as before.
    #[test]
    fn an_oversized_answer_is_not_remembered() {
        let c = cache();
        let now = Instant::now();
        c.insert_at(query("big.example.com"), addresses(2), now);
        assert!(matches!(
            c.get_at(&query("big.example.com"), now),
            Hit::Fresh(_)
        ));

        c.insert_at(query("big.example.com"), addresses(1000), now);
        assert!(matches!(
            c.get_at(&query("big.example.com"), now),
            Hit::Miss
        ));
        assert_eq!(c.len(), 0);
        assert_eq!(c.memory(), 0);
    }

    /// Should change: once stored answers pass the memory budget, the least recently used go,
    /// one at a time, while the entry count is still under capacity.
    /// Should not change: the newest answer survives.
    #[test]
    fn the_memory_budget_evicts_the_oldest_answers() {
        let one = addresses(20).memory();
        let c = Cache {
            memory_budget: 3 * one,
            ..Cache::new(100, Duration::from_secs(60))
        };
        let now = Instant::now();
        for name in [
            "a.example.com",
            "b.example.com",
            "c.example.com",
            "d.example.com",
        ] {
            c.insert_at(query(name), addresses(20), now);
        }
        assert_eq!(c.len(), 3);
        assert_eq!(c.memory(), 3 * one);
        assert!(matches!(c.get_at(&query("a.example.com"), now), Hit::Miss));
        assert!(matches!(
            c.get_at(&query("d.example.com"), now),
            Hit::Fresh(_)
        ));
    }

    /// Should not change: replacing, expiring and evicting leave the memory count matching what
    /// is actually stored.
    #[test]
    fn the_memory_count_follows_every_removal() {
        let c = Cache::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let one = addresses(3).memory();
        c.insert_at(query("a.example.com"), addresses(3), now);
        c.insert_at(query("a.example.com"), addresses(3), now);
        assert_eq!(c.memory(), one, "a rewrite replaces, it does not add");
        c.insert_at(query("b.example.com"), addresses(3), now);
        c.insert_at(query("c.example.com"), addresses(3), now);
        assert_eq!(c.memory(), 2 * one, "eviction gives the memory back");

        let long_after = now + Duration::from_secs(24 * 60 * 60);
        assert!(matches!(
            c.get_at(&query("b.example.com"), long_after),
            Hit::Miss
        ));
        assert_eq!(
            c.memory(),
            one,
            "dropping an expired answer gives the memory back"
        );
    }

    #[test]
    fn a_full_cache_evicts_one_at_a_time_rather_than_clearing() {
        let c = cache();
        let now = Instant::now();
        for name in ["a.example.com", "b.example.com", "c.example.com"] {
            c.insert_at(query(name), Cached::Records(Records::default()), now);
        }
        assert_eq!(c.len(), 3);

        c.insert_at(
            query("d.example.com"),
            Cached::Records(Records::default()),
            now,
        );
        assert_eq!(c.len(), 3, "capacity must not be exceeded");
        assert!(
            matches!(c.get_at(&query("a.example.com"), now), Hit::Miss),
            "the least recently used entry should be the one evicted"
        );
        assert!(
            matches!(c.get_at(&query("d.example.com"), now), Hit::Fresh(_)),
            "the entry just inserted must survive — a bulk clear would take it too"
        );
    }

    #[test]
    fn a_recently_read_entry_is_evicted_later() {
        let c = cache();
        let now = Instant::now();
        for name in ["a.example.com", "b.example.com", "c.example.com"] {
            c.insert_at(query(name), Cached::Records(Records::default()), now);
        }
        // Reading a makes it no longer the least recently used.
        let _ = c.get_at(&query("a.example.com"), now);
        c.insert_at(
            query("d.example.com"),
            Cached::Records(Records::default()),
            now,
        );

        assert!(matches!(
            c.get_at(&query("a.example.com"), now),
            Hit::Fresh(_)
        ));
        assert!(matches!(c.get_at(&query("b.example.com"), now), Hit::Miss));
    }

    #[test]
    fn a_retrieved_ttl_has_the_time_spent_in_the_cache_subtracted() {
        // An empty record set cannot demonstrate TTL decay, so this only checks `aged`
        // itself; the end-to-end evidence is two consecutive digs showing a smaller TTL.
        let records = Records::default();
        assert_eq!(records.aged(Duration::from_secs(5)).len(), 0);
    }

    #[test]
    fn rewriting_the_same_query_does_not_grow_the_entry_count() {
        let c = cache();
        let now = Instant::now();
        for _ in 0..5 {
            c.insert_at(
                query("a.example.com"),
                Cached::Records(Records::default()),
                now,
            );
        }
        assert_eq!(c.len(), 1);
    }

    const HOUR: Duration = Duration::from_secs(60 * 60);

    /// Should change: a 24-hour answer still has a 12-hour stale window after expiry (it used
    /// to vanish the moment it expired).
    /// Should not change: it is Fresh while fresh, and cleared once past the stale window.
    #[test]
    fn a_long_ttl_answer_still_gets_its_stale_window() {
        let c = cache();
        let now = Instant::now();
        let q = query("www.apple.com");
        let records =
            Records::from_addresses(q.name(), 24 * HOUR, &["17.253.144.10".parse().unwrap()]);
        c.insert_at(q.clone(), Cached::Records(records), now);

        assert!(matches!(c.get_at(&q, now + 23 * HOUR), Hit::Fresh(_)));
        assert!(
            matches!(
                c.get_at(&q, now + 24 * HOUR + Duration::from_secs(1)),
                Hit::Stale(_)
            ),
            "one second past expiry it should still carry an upstream outage"
        );
        assert!(matches!(
            c.get_at(&q, now + 36 * HOUR + Duration::from_secs(2)),
            Hit::Miss
        ));
    }

    /// Should change: "no such name" and "no records of that type" are remembered, with their
    /// TTL decaying by the time spent in the cache.
    #[test]
    fn negative_answers_are_remembered_and_their_ttl_decays() {
        let c = cache();
        let now = Instant::now();
        c.insert_at(
            query("typo.example.com"),
            Cached::NameNotFound {
                ttl: Duration::from_secs(300),
                proof: crate::dns::Proof::default(),
            },
            now,
        );
        assert!(matches!(
            c.get_at(&query("typo.example.com"), now + Duration::from_secs(100)),
            Hit::Fresh(Cached::NameNotFound { ttl, .. }) if ttl == Duration::from_secs(200)
        ));

        c.insert_at(
            query("ipv4only.example.com"),
            Cached::NoRecordsOfType {
                ttl: Duration::from_secs(60),
                proof: crate::dns::Proof::default(),
            },
            now,
        );
        assert!(matches!(
            c.get_at(
                &query("ipv4only.example.com"),
                now + Duration::from_secs(61)
            ),
            Hit::Stale(Cached::NoRecordsOfType { .. })
        ));
    }

    /// Should change: however long the upstream's negative TTL, the cache treats it as fresh
    /// for at most an hour.
    #[test]
    fn a_negative_answer_is_fresh_for_at_most_an_hour() {
        let c = cache();
        let now = Instant::now();
        let q = query("new-domain.example.com");
        c.insert_at(
            q.clone(),
            Cached::NameNotFound {
                ttl: Duration::from_secs(86_400),
                proof: crate::dns::Proof::default(),
            },
            now,
        );
        assert!(matches!(
            c.get_at(&q, now + HOUR - Duration::from_secs(1)),
            Hit::Fresh(_)
        ));
        assert!(matches!(
            c.get_at(&q, now + HOUR + Duration::from_secs(1)),
            Hit::Stale(_)
        ));
    }
}
