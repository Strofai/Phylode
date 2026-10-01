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

#[derive(Debug)]
struct Window {
    started: Instant,
    seen: u32,
}

/// A fixed window counted separately per source.
#[derive(Debug, Default)]
pub struct RateLimit {
    clients: Mutex<Clients>,
}

#[derive(Debug, Default)]
struct Clients {
    windows: HashMap<IpAddr, Window>,
    /// No window ends before this moment, so a full table is not worth sweeping until then.
    /// `None` means not yet known.
    /// What breaks if you change it: sweeping for every new source while the table is full
    /// costs a pass over every entry per packet, under the lock every query takes.
    sweep_after: Option<Instant>,
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
        let Clients {
            windows,
            sweep_after,
        } = &mut *clients;
        if !windows.contains_key(&client) && windows.len() >= MAX_TRACKED {
            if sweep_after.is_none_or(|after| now >= after) {
                windows.retain(|_, w| now.duration_since(w.started) < WINDOW);
                *sweep_after = windows.values().map(|w| w.started + WINDOW).min();
            }
            if windows.len() >= MAX_TRACKED {
                // Table full and this is a new source: do not track it, answer as usual.
                // Better to under-limit one device than to wrongly block a real one. A sender
                // forging source addresses is not bounded by per-source limits anyway: every
                // forged address gets a window of its own.
                return Admit::Yes;
            }
        }
        let window = windows.entry(client).or_insert(Window {
            started: now,
            seen: 0,
        });
        if now.duration_since(window.started) >= WINDOW {
            *window = Window {
                started: now,
                seen: 0,
            };
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Should change: the number of tracked sources is capped rather than growing without
    /// bound. Should not change: a new source arriving with a full table is still answered.
    #[test]
    fn the_number_of_tracked_sources_is_capped() {
        let limit = RateLimit::new();
        let now = Instant::now();
        for n in 0..MAX_TRACKED as u32 {
            limit.check(IpAddr::from((0x0a00_0000 + n).to_be_bytes()), now);
        }
        assert_eq!(limit.check(device(250), now), Admit::Yes);
        assert_eq!(limit.clients.lock().unwrap().windows.len(), MAX_TRACKED);

        // Once the window passes, stale entries are cleared and new sources are tracked again.
        limit.check(device(251), now + WINDOW);
        assert!(limit.clients.lock().unwrap().windows.len() < MAX_TRACKED);
    }

    /// Should change: with a full table of windows that have not ended, the next sweep waits
    /// until the oldest one ends instead of running for every new source.
    /// Should not change: new sources are still answered meanwhile.
    #[test]
    fn a_full_table_is_not_swept_again_before_a_window_can_end() {
        let limit = RateLimit::new();
        let start = Instant::now();
        for n in 0..MAX_TRACKED as u32 {
            limit.check(IpAddr::from((0x0a00_0000 + n).to_be_bytes()), start);
        }
        let later = start + Duration::from_secs(30);
        assert_eq!(limit.check(device(250), later), Admit::Yes);
        assert_eq!(
            limit.clients.lock().unwrap().sweep_after,
            Some(start + WINDOW),
            "the oldest window began at the start, so none can end before a minute after it"
        );
        assert_eq!(limit.check(device(251), later), Admit::Yes);
    }
}
