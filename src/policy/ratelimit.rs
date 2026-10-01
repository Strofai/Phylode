//! Per-source query rate limit: when one device asks too many times inside a window, the
//! rest of that window goes unanswered.
//!
//! What breaks if you change it: over the limit we **do not respond**, rather than returning
//! REFUSED. A REFUSED makes the device immediately move to the next resolver on its list —
//! typically an unfiltered one from the ISP.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum queries per window. Ours: Apple, Anthropic and Cloudflare publish no per-device
/// figure for a home resolver.
///
/// One page load on a cold cache takes dozens of queries, so a limit counted in tens per
/// second would catch normal use; 1000 a minute leaves room for several at once.
/// What breaks if you change it: set it too low and wrongly limited devices fall back to an
/// unfiltered resolver.
pub const MAX_PER_WINDOW: u32 = 1000;

/// Window length. Ours: a minute is long enough that one busy page load does not decide it.
pub const WINDOW: Duration = Duration::from_secs(60);

/// Maximum number of sources tracked at once. This one is ours, not an industry value: a
/// home has a few dozen devices and an office or school a few hundred, so 4096 leaves an
/// order of magnitude of headroom. What breaks if you change it: without a cap, packets with forged
/// source addresses could grow this table without bound — which is exactly what the cap is
/// for.
const MAX_TRACKED: usize = 4096;

/// Whether this query gets a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Yes,
    /// Over the limit, no response. `first` marks the first time the limit was exceeded in
    /// this window — only that one is journalled, or a flood would flood the journal too.
    No {
        first: bool,
    },
}

/// How many sources a full table forgets at once when none of its windows has ended: the
/// least recently seen eighth. Making room in batches costs one pass over the table per batch
/// of new sources rather than one per packet.
const FORGET_AT_ONCE: usize = MAX_TRACKED / 8;

#[derive(Debug)]
struct Window {
    started: Instant,
    seen: u32,
    last_seen: Instant,
}

/// A fixed window counted separately per source.
#[derive(Debug, Default)]
pub struct RateLimit {
    clients: Mutex<HashMap<IpAddr, Window>>,
}

impl RateLimit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Counts one query and reports whether to answer it. The loopback address is exempt —
    /// the gatekeeper's own health check goes through it, and limiting that makes a healthy
    /// service restart itself repeatedly.
    pub fn check(&self, client: IpAddr, now: Instant) -> Admit {
        if client.is_loopback() {
            return Admit::Yes;
        }
        let Ok(mut clients) = self.clients.lock() else {
            // A poisoned lock (another thread panicked holding it) means no limiting:
            // keeping the network online matters more than blocking more (principle 1).
            return Admit::Yes;
        };
        if !clients.contains_key(&client) && clients.len() >= MAX_TRACKED {
            make_room(&mut clients, now);
        }
        let window = clients.entry(client).or_insert(Window {
            started: now,
            seen: 0,
            last_seen: now,
        });
        if now.duration_since(window.started) >= WINDOW {
            window.started = now;
            window.seen = 0;
        }
        window.last_seen = now;
        window.seen = window.seen.saturating_add(1);
        if window.seen <= MAX_PER_WINDOW {
            Admit::Yes
        } else {
            Admit::No {
                first: window.seen == MAX_PER_WINDOW + 1,
            }
        }
    }
}

/// Frees space in a full table: windows that have ended go first, and if none has, the least
/// recently seen sources are forgotten — the way bounded tables in Apple's Private Cloud
/// Compute make room.
///
/// What breaks if you change it: turning new sources away instead lets anyone who fills the
/// table with forged addresses query without limit from their own; forgetting the busiest
/// sources instead lets a flooding device keep resetting its own count. A forgotten source
/// only starts counting again, so this never blocks a device wrongly.
fn make_room(clients: &mut HashMap<IpAddr, Window>, now: Instant) {
    clients.retain(|_, window| now.duration_since(window.started) < WINDOW);
    if clients.len() < MAX_TRACKED {
        return;
    }
    let mut last_seen: Vec<Instant> = clients.values().map(|window| window.last_seen).collect();
    let cutoff = *last_seen.select_nth_unstable(FORGET_AT_ONCE - 1).1;
    clients.retain(|_, window| window.last_seen > cutoff);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct private address for each `n`, standing in for forged sources.
    fn forged(n: u32) -> IpAddr {
        IpAddr::from((0x0a00_0000 + n).to_be_bytes())
    }

    fn device(n: u8) -> IpAddr {
        IpAddr::from([192, 168, 1, n])
    }

    /// Should change: from the query that exceeds the limit onward there is no response, and
    /// only the first excess is journalled.
    #[test]
    fn queries_over_the_limit_get_no_response() {
        let limit = RateLimit::new();
        let now = Instant::now();
        for _ in 0..MAX_PER_WINDOW {
            assert_eq!(limit.check(device(2), now), Admit::Yes);
        }
        assert_eq!(limit.check(device(2), now), Admit::No { first: true });
        assert_eq!(limit.check(device(2), now), Admit::No { first: false });
    }

    /// Should not change: other devices, the next window, and the loopback address are all
    /// unaffected.
    #[test]
    fn only_that_device_is_limited_and_the_next_window_resets_it() {
        let limit = RateLimit::new();
        let now = Instant::now();
        for _ in 0..=MAX_PER_WINDOW {
            limit.check(device(2), now);
        }
        assert_eq!(
            limit.check(device(3), now),
            Admit::Yes,
            "other devices are unaffected"
        );
        assert_eq!(
            limit.check(device(2), now + WINDOW),
            Admit::Yes,
            "the next window starts counting again"
        );

        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..=MAX_PER_WINDOW {
            assert_eq!(
                limit.check(loopback, now),
                Admit::Yes,
                "the health check comes from loopback and must never be limited"
            );
        }
    }

    /// Should change: a source that first appears once the table is full is still counted, so
    /// filling the table with forged addresses does not free another address from its limit.
    /// Should not change: its queries up to the limit are answered.
    #[test]
    fn a_source_arriving_at_a_full_table_is_still_limited() {
        let limit = RateLimit::new();
        let start = Instant::now();
        for n in 0..MAX_TRACKED as u32 {
            limit.check(forged(n), start);
        }
        let later = start + Duration::from_secs(1);
        for _ in 0..MAX_PER_WINDOW {
            assert_eq!(limit.check(device(250), later), Admit::Yes);
        }
        assert_eq!(limit.check(device(250), later), Admit::No { first: true });
    }

    /// Should change: while new forged sources keep arriving, a device that keeps querying
    /// stays counted and reaches its limit.
    /// Should not change: the table never grows past its cap.
    #[test]
    fn a_busy_device_stays_counted_through_a_flood_of_new_sources() {
        let limit = RateLimit::new();
        let start = Instant::now();
        for n in 0..MAX_TRACKED as u32 {
            limit.check(forged(n), start);
        }
        for i in 0..MAX_PER_WINDOW {
            let now = start + Duration::from_millis(u64::from(i) + 1);
            assert_eq!(limit.check(device(250), now), Admit::Yes);
            for k in 0..8 {
                limit.check(forged(MAX_TRACKED as u32 + i * 8 + k), now);
            }
            assert!(limit.clients.lock().unwrap().len() <= MAX_TRACKED);
        }
        let end = start + Duration::from_millis(u64::from(MAX_PER_WINDOW) + 1);
        assert_eq!(limit.check(device(250), end), Admit::No { first: true });
    }

    /// Should change: making room forgets a whole batch at once, so the next new sources are
    /// added without another pass over the table.
    /// Should not change: windows that have ended are cleared first.
    #[test]
    fn a_full_table_makes_room_in_batches_and_drops_ended_windows_first() {
        let limit = RateLimit::new();
        let start = Instant::now();
        for n in 0..MAX_TRACKED as u32 {
            limit.check(forged(n), start + Duration::from_nanos(u64::from(n)));
        }
        let later = start + Duration::from_secs(1);
        limit.check(device(250), later);
        assert_eq!(
            limit.clients.lock().unwrap().len(),
            MAX_TRACKED - FORGET_AT_ONCE + 1
        );

        let ended = RateLimit::new();
        for n in 0..MAX_TRACKED as u32 {
            ended.check(forged(n), start);
        }
        ended.check(device(251), start + WINDOW);
        assert_eq!(
            ended.clients.lock().unwrap().len(),
            1,
            "every window from the first minute has ended, so all of them make way"
        );
    }
}
