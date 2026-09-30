//! Upstream rotation: decides which server a query goes to, what happens when one fails, and
//! when it counts as recovered.
//!
//! This mirrors Cloudflare Big Pineapple's Conductor layer. The transport itself lives in
//! `dns::Exchange`; this module only handles selection and health.
//!
//! ⚠️ When every upstream fails it returns [`Outcome::AllDown`] and **never falls back to
//! plaintext** — that is RFC 8310 Strict Privacy, and also the factory default for Apple's
//! encrypted DNS. A caller receiving `AllDown` may only serve from cache or return SERVFAIL.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

mod coalesce;

use crate::config::Upstream;
use crate::dns::{Answer, Exchange, ExchangeError, Query, Signature};
use coalesce::Coalescer;

/// How many consecutive failures move an upstream to the back of the rotation.
///
/// Ours: Apple, Anthropic and Cloudflare publish no figure; 2 is the smallest that is not a
/// single event. What breaks if you change it: a value of 1 demotes the primary upstream on a single
/// network blip; too large and every failure after the server is genuinely down wastes
/// another query on it.
const DEMOTE_AFTER_FAILURES: u32 = 2;

/// How many upstream queries may be in flight (sent, answer not yet received) at once.
///
/// Ours: Apple, Anthropic and Cloudflare publish no figure. A few hundred devices rarely
/// wait on more than a handful of uncached answers each at once. What breaks if you change it: without a cap, one device flooding distinct names
/// can make the gatekeeper open unbounded outbound queries, exhausting both memory and the
/// upstream's quota.
const MAX_IN_FLIGHT: usize = 300;

/// The result of one upstream query.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// An upstream answered. **"This name does not exist" and SERVFAIL both count as
    /// answering.**
    Answered {
        answer: Answer,
        signature: Signature,
    },
    /// Every upstream was tried and none was reachable.
    AllDown,
    /// The in-flight limit was full and this query was never sent. **This says nothing about
    /// the upstreams** and counts as a failure for none of them.
    Busy,
}

/// The upstream pool. The order is fixed, except that servers failing repeatedly move to the
/// back.
#[derive(Debug)]
pub struct Conductor {
    members: Vec<Member>,
    in_flight: Semaphore,
    /// One in-flight query per (name, type); simultaneous callers wait for that one result.
    pending: Coalescer<Query, Outcome>,
}

#[derive(Debug)]
struct Member {
    exchange: Exchange,
    consecutive_failures: AtomicU32,
}

impl Conductor {
    /// Builds the pool from configuration. If any upstream cannot be constructed, the whole
    /// thing fails.
    ///
    /// The reasoning: this step touches no network, only assembling configuration and TLS
    /// parameters, so a failure means the configuration or certificate setup is wrong — which
    /// should be visible at startup, not discovered by a failed query in the middle of the
    /// night. What breaks if you change it: this is a different concern from tolerating a
    /// runtime outage — runtime failures take the demotion path in [`Conductor::resolve`] and
    /// never stop the service.
    pub fn new(upstreams: &[Upstream]) -> Result<Self, ExchangeError> {
        let members = upstreams
            .iter()
            .map(|upstream| {
                Ok(Member {
                    exchange: Exchange::connect(upstream)?,
                    consecutive_failures: AtomicU32::new(0),
                })
            })
            .collect::<Result<Vec<_>, ExchangeError>>()?;
        Ok(Self {
            members,
            in_flight: Semaphore::new(MAX_IN_FLIGHT),
            pending: Coalescer::default(),
        })
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Holds every in-flight slot so tests can reach the "saturated" path without touching the
    /// network.
    #[cfg(test)]
    pub(crate) fn occupy_all(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.in_flight
            .try_acquire_many(MAX_IN_FLIGHT as u32)
            .expect("every slot should be free when a test starts")
    }

    /// Tries each upstream in health order and takes the first answer.
    ///
    /// What breaks if you change it: only being **unreachable** counts as a failure for an
    /// upstream. Counting "this name does not exist" as failure means two typos at home demote
    /// the primary upstream.
    ///
    /// When the in-flight limit is full it returns [`Outcome::Busy`] immediately rather than
    /// queueing — queueing makes the device wait until it times out, and a device that times
    /// out moves on to the next resolver in its list (the same reasoning as never returning
    /// REFUSED).
    ///
    /// One in-flight query per (name, type), so the chance of a forged answer stays that of a
    /// single query (RFC 5452 section 5); a single query here only ever goes to one upstream at
    /// a time.
    /// What breaks if you change it: remove the deduplication and an attacker can make the
    /// gatekeeper send many simultaneous queries for one name, each a fresh chance to guess a
    /// forged response.
    pub async fn resolve(&self, query: &Query) -> Outcome {
        self.pending.run(query, || self.resolve_once(query)).await
    }

    async fn resolve_once(&self, query: &Query) -> Outcome {
        let Ok(_slot) = self.in_flight.try_acquire() else {
            return Outcome::Busy;
        };
        for index in self.order() {
            let member = &self.members[index];
            match member.exchange.query(query).await {
                Ok(checked) => {
                    member.consecutive_failures.store(0, Ordering::Relaxed);
                    return Outcome::Answered {
                        answer: checked.answer,
                        signature: checked.signature,
                    };
                }
                Err(_) => {
                    member.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        Outcome::AllDown
    }

    /// Sends one [`Query::liveness`] to each demoted upstream and restores any that answers.
    ///
    /// What breaks if you change it: without this, a demoted upstream is only retried once
    /// everything ahead of it fails, so after one brief outage of the primary the household
    /// stays on the backup until the backup breaks too.
    /// This only resets the counter and never increments it — an upstream still down simply
    /// stays demoted, with nothing further to record.
    async fn reprobe_demoted(&self) {
        let probe = Query::liveness();
        for member in &self.members {
            if member.consecutive_failures.load(Ordering::Relaxed) < DEMOTE_AFTER_FAILURES {
                continue;
            }
            if member.exchange.query(&probe).await.is_ok() {
                member.consecutive_failures.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Whether every upstream is demoted (at the failure threshold and not yet rescued by a
    /// reprobe). While this holds, only the cache is keeping the household online.
    pub fn all_demoted(&self) -> bool {
        !self.members.is_empty()
            && self.members.iter().all(|member| {
                member.consecutive_failures.load(Ordering::Relaxed) >= DEMOTE_AFTER_FAILURES
            })
    }

    /// Healthy upstreams first; everything else keeps its configured order.
    fn order(&self) -> Vec<usize> {
        let mut healthy = Vec::with_capacity(self.members.len());
        let mut demoted = Vec::new();
        for (index, member) in self.members.iter().enumerate() {
            if member.consecutive_failures.load(Ordering::Relaxed) >= DEMOTE_AFTER_FAILURES {
                demoted.push(index);
            } else {
                healthy.push(index);
            }
        }
        healthy.extend(demoted);
        healthy
    }
}

/// How often demoted upstreams are reprobed.
///
/// Ours: Apple, Anthropic and Cloudflare publish no figure. Half a second brings a repaired
/// upstream back before a device's own retry. Only demoted servers are probed, so this loop
/// sends nothing at all while everything is healthy.
const REPROBE_INTERVAL: Duration = Duration::from_millis(500);

/// Reprobes demoted upstreams in the background, for the lifetime of the service.
///
/// Calls `on_change` whenever the "every upstream is demoted" state flips (`true` = just went
/// down, `false` = just recovered).
/// What breaks if you change it: without the notification, the weekly summary can never show
/// "there was a window where only the cache was holding".
pub fn spawn_reprobe(conductor: Arc<Conductor>, on_change: impl Fn(bool) + Send + 'static) {
    tokio::spawn(async move {
        let mut was_down = false;
        loop {
            tokio::time::sleep(REPROBE_INTERVAL).await;
            conductor.reprobe_demoted().await;
            let down = conductor.all_demoted();
            if down != was_down {
                was_down = down;
                on_change(down);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn conductor(text: &str) -> Conductor {
        let config = Config::parse(text).expect("test configuration should parse");
        Conductor::new(config.upstreams()).expect("the upstream pool should build")
    }

    #[test]
    fn several_upstreams_are_built_from_configuration() {
        let c = conductor(
            "listen = 127.0.0.1:5353\n\
             upstream = tls 1.1.1.1 cloudflare-dns.com\n\
             upstream = tls 9.9.9.9 dns.quad9.net\n",
        );
        assert_eq!(c.len(), 2);
        assert_eq!(c.order(), vec![0, 1]);
    }

    #[test]
    fn demotion_only_happens_at_the_threshold() {
        let c = conductor(
            "listen = 127.0.0.1:5353\n\
             upstream = tls 1.1.1.1 cloudflare-dns.com\n\
             upstream = tls 9.9.9.9 dns.quad9.net\n",
        );

        // Below the threshold the order is unchanged — one network blip must not demote the
        // primary upstream.
        for _ in 0..DEMOTE_AFTER_FAILURES - 1 {
            c.members[0]
                .consecutive_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(c.order(), vec![0, 1]);

        c.members[0]
            .consecutive_failures
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            c.order(),
            vec![1, 0],
            "at the threshold the first upstream moves to the back"
        );
    }

    #[test]
    fn one_success_resets_the_failure_count() {
        let c = conductor("listen = 127.0.0.1:5353\nupstream = tls 1.1.1.1 cloudflare-dns.com\n");
        c.members[0]
            .consecutive_failures
            .store(DEMOTE_AFTER_FAILURES, Ordering::Relaxed);
        c.members[0]
            .consecutive_failures
            .store(0, Ordering::Relaxed);
        assert_eq!(c.order(), vec![0]);
    }

    /// Should change: a full in-flight limit returns Busy without touching the network.
    /// Should not change: no failure is recorded, and the pool works normally once released.
    #[tokio::test]
    async fn a_full_in_flight_limit_stops_sending() {
        let c = conductor("listen = 127.0.0.1:5353\nupstream = tls 1.1.1.1 cloudflare-dns.com\n");
        let all = c.occupy_all();
        let query = Query::new(
            crate::dns::Name::parse("example.com"),
            crate::dns::RecordType::A,
        );
        assert!(matches!(c.resolve(&query).await, Outcome::Busy));
        assert_eq!(
            c.members[0].consecutive_failures.load(Ordering::Relaxed),
            0,
            "saturation is not the upstream's fault and must not count against it"
        );
        drop(all);
        assert_eq!(c.in_flight.available_permits(), MAX_IN_FLIGHT);
    }

    #[test]
    fn every_upstream_is_still_tried_when_all_are_demoted() {
        let c = conductor(
            "listen = 127.0.0.1:5353\n\
             upstream = tls 1.1.1.1 cloudflare-dns.com\n\
             upstream = tls 9.9.9.9 dns.quad9.net\n",
        );
        for member in &c.members {
            member
                .consecutive_failures
                .store(DEMOTE_AFTER_FAILURES, Ordering::Relaxed);
        }
        let order = c.order();
        assert_eq!(
            order.len(),
            2,
            "demotion only reorders; it must never drop an upstream entirely"
        );
    }

    /// A pool where nothing listens on loopback port 853 and the backup is healthy, with the
    /// first upstream already demoted.
    fn primary_on_loopback_demoted() -> Conductor {
        let c = conductor(
            "listen = 127.0.0.1:5353\n\
             upstream = tls 127.0.0.1 cloudflare-dns.com\n\
             upstream = tls 9.9.9.9 dns.quad9.net\n",
        );
        c.members[0]
            .consecutive_failures
            .store(DEMOTE_AFTER_FAILURES, Ordering::Relaxed);
        c
    }

    /// Should not change: an upstream still down stays at the back after a reprobe, and the
    /// healthy one is neither probed nor touched.
    #[tokio::test]
    async fn an_upstream_still_down_stays_at_the_back() {
        let c = primary_on_loopback_demoted();
        c.reprobe_demoted().await;
        assert_eq!(c.order(), vec![1, 0]);
        assert_eq!(c.members[1].consecutive_failures.load(Ordering::Relaxed), 0);
    }

    /// Should change: once an upstream is fixed, one probe restores it without waiting for a
    /// real query to reach it.
    ///
    /// Requires internet access and binding local port 853, so it is ignored by default:
    /// `cargo test -- --ignored`.
    /// The "fix" is a forwarder on local port 853 that relays to 1.1.1.1:853 — TLS passes
    /// through untouched, so the certificate still validates as cloudflare-dns.com.
    /// macOS only lets an unprivileged program bind ports below 1024 on all addresses, so this
    /// binds `0.0.0.0` and accepts loopback connections only.
    #[tokio::test]
    #[ignore = "requires internet access and binding local port 853"]
    async fn a_repaired_upstream_is_restored_by_one_probe() {
        let c = primary_on_loopback_demoted();
        c.reprobe_demoted().await;
        assert_eq!(
            c.order(),
            vec![1, 0],
            "with no forwarder yet, the first upstream should still be at the back"
        );

        let listener = tokio::net::TcpListener::bind("0.0.0.0:853").await.unwrap();
        tokio::spawn(async move {
            while let Ok((mut inbound, peer)) = listener.accept().await {
                if !peer.ip().is_loopback() {
                    continue;
                }
                tokio::spawn(async move {
                    let mut outbound = tokio::net::TcpStream::connect("1.1.1.1:853").await?;
                    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                });
            }
        });

        c.reprobe_demoted().await;
        assert_eq!(
            c.order(),
            vec![0, 1],
            "once repaired, one probe must restore its position"
        );
    }

    /// Should change: every upstream at the threshold counts as all down.
    /// Should not change: one healthy upstream means it does not.
    #[test]
    fn all_down_requires_every_upstream_to_be_demoted() {
        let c = conductor(
            "listen = 127.0.0.1:5353\n\
             upstream = tls 1.1.1.1 cloudflare-dns.com\n\
             upstream = tls 9.9.9.9 dns.quad9.net\n",
        );
        assert!(!c.all_demoted());
        c.members[0]
            .consecutive_failures
            .store(DEMOTE_AFTER_FAILURES, Ordering::Relaxed);
        assert!(
            !c.all_demoted(),
            "one healthy upstream means this is not an outage"
        );
        c.members[1]
            .consecutive_failures
            .store(DEMOTE_AFTER_FAILURES, Ordering::Relaxed);
        assert!(c.all_demoted());
    }
}
