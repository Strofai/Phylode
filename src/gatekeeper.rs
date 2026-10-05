//! Joins the policy layer, cache, upstream rotation and journal: a query comes in and this
//! decides whether it is blocked, allowed, or forwarded.
//!
//! This is the only seam between the layers. What breaks if you change it: the decision
//! logic may live only here — spread into `dns` or `upstream`, a change to resolution
//! silently changes what gets blocked.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::cache::{Cache, Cached, Hit};
use crate::dns::{Answer, Query, RecordType, Responder, Response, Signature};
use crate::health;
use crate::journal::{Disposition, EventKind, Journal, Record, USER_ALLOWED};
use crate::policy::{
    self, Admit, Allowlist, Blocklist, RateLimit, RebindGuard, Rebinding, ServedNetworks, Verdict,
};
use crate::upstream::{Conductor, Outcome};

/// Whether this round's answer may be written to the cache.
///
/// ⚠️ This is where the "fail-open allows are never cached" rule lands, deliberately as a
/// named type rather than a bool — a caller reading `forward(query, true)` cannot tell what
/// `true` means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheWrite {
    /// The list was checked and confirmed this should not be blocked; the answer may be
    /// remembered.
    Allowed,
    /// The list is currently unavailable and this allow exists only to keep the network
    /// online. **The answer must not be remembered** — cached, the domain would stay
    /// reachable for the cache lifetime even after the list recovers.
    Forbidden,
}

/// The gatekeeper itself.
#[derive(Debug)]
pub struct Gatekeeper {
    allowlist: Allowlist,
    blocklist: Blocklist,
    cache: Arc<Cache>,
    conductor: Arc<Conductor>,
    journal: Option<Journal>,
    block_ttl: Duration,
    rebind_guard: RebindGuard,
    rate_limit: RateLimit,
    /// The Apple hard rules' own allowance, counted apart from `rate_limit`.
    apple_rate_limit: RateLimit,
    served: ServedNetworks,
    own_addresses: Vec<IpAddr>,
}

impl Gatekeeper {
    /// Tells the gatekeeper which addresses it is bound to, so it can recognize health check
    /// probes arriving from them.
    ///
    /// What breaks if you change it: bound to a LAN address without calling this, probes are
    /// treated as ordinary queries — journalled and sent upstream.
    pub fn serving_on(mut self, addresses: Vec<IpAddr>) -> Self {
        self.own_addresses = addresses;
        self
    }

    /// Which devices get answers; without this, the private ranges only.
    pub fn answering(mut self, served: ServedNetworks) -> Self {
        self.served = served;
        self
    }

    pub fn new(
        allowlist: Allowlist,
        blocklist: Blocklist,
        cache: Arc<Cache>,
        conductor: Arc<Conductor>,
        journal: Option<Journal>,
        block_ttl: Duration,
        rebind_guard: RebindGuard,
    ) -> Self {
        Self {
            allowlist,
            blocklist,
            cache,
            conductor,
            journal,
            block_ttl,
            rebind_guard,
            rate_limit: RateLimit::new(),
            apple_rate_limit: RateLimit::new(),
            served: ServedNetworks::new(&[]),
            own_addresses: Vec::new(),
        }
    }

    async fn forward(&self, query: &Query, write: CacheWrite) -> (Response, Disposition) {
        // A fresh cache entry is returned directly. A stale one is held back — it is only
        // used if every upstream really is down.
        //
        // Everything in the cache has already passed the rebinding check (failures never
        // get cached), so it is not re-checked here.
        // What breaks if you change it: after removing an internal-domain exception, answers
        // already in the cache are still served, for as long as their TTL lasts.
        let stale = match self.cache.get(query) {
            Hit::Fresh(cached) => return (response_of(cached), disposition_for(write)),
            Hit::Stale(cached) => Some(response_of(cached)),
            Hit::Miss => None,
        };

        match self.conductor.resolve(query).await {
            Outcome::Answered { answer, signature } => {
                self.deliver(query, answer, write, signature)
            }
            // Every upstream is down. **Never fall back to plaintext** (RFC 8310 Strict
            // Privacy). Carry on with a stale answer if there is one, and only fail if there
            // is not — this is what product principle 1 looks like in code.
            Outcome::AllDown => match stale {
                Some(response) => (response, disposition_for(write)),
                None => (Response::Failure, Disposition::Failed),
            },
            // The in-flight limit is full: same fallback as every upstream being down, but
            // the journal has to say that the gatekeeper itself was saturated.
            Outcome::Busy => match stale {
                Some(response) => (response, disposition_for(write)),
                None => (Response::Failure, Disposition::Overloaded),
            },
        }
    }

    /// Translates an upstream answer into what goes back to the device, deciding on the way
    /// whether it is cached and which category the journal records.
    ///
    /// Negative answers (name does not exist, no records of that type) are cached too;
    /// SERVFAIL is not ([`Cached`] has no variant for it).
    ///
    /// Answers whose signatures the upstream flagged are served as usual (report-only mode)
    /// but **never cached**: when this later becomes enforcing, stale answers must not keep
    /// being served.
    fn deliver(
        &self,
        query: &Query,
        answer: Answer,
        write: CacheWrite,
        signature: Signature,
    ) -> (Response, Disposition) {
        let disposition = disposition_with(write, signature);
        let cacheable = write == CacheWrite::Allowed && signature == Signature::NotFlagged;
        match answer {
            Answer::Records(records) => {
                // Rebinding defence: an upstream answer pointing into the local network is
                // discarded whole. **Never cached**, for the same reason as a fail-open
                // allow — cached, the domain would keep getting the discarded result for the
                // cache lifetime even after the exception is configured.
                if self
                    .rebind_guard
                    .inspect(query.name().as_str(), &records.addresses())
                    == Rebinding::Blocked
                {
                    // Return NOERROR with an SOA rather than "no such domain": the name does
                    // exist, we are just not handing over that answer. The SOA is required,
                    // and without it devices retry endlessly.
                    return (
                        Response::NoRecords {
                            ttl: self.block_ttl,
                        },
                        Disposition::Rebind,
                    );
                }
                if cacheable {
                    self.cache
                        .insert(query.clone(), Cached::Records(records.clone()));
                }
                (Response::Answer(records), disposition)
            }
            Answer::NameNotFound { ttl } => {
                if cacheable {
                    self.cache
                        .insert(query.clone(), Cached::NameNotFound { ttl });
                }
                (Response::NotFound { ttl }, disposition)
            }
            Answer::NoRecordsOfType { ttl } => {
                if cacheable {
                    self.cache
                        .insert(query.clone(), Cached::NoRecordsOfType { ttl });
                }
                (Response::NoRecords { ttl }, disposition)
            }
            // The upstream answered, and answered with a failure. **This is not the upstream
            // being down**; report the failure honestly and let the journal name who failed.
            Answer::ServerFailure => (Response::Failure, Disposition::ServFail),
        }
    }

    /// The first alias target in an answer that is on the blocklist and has not been allowed
    /// by the user.
    fn cloaked_target(&self, records: &crate::dns::Records) -> Option<String> {
        records.alias_targets().into_iter().find(|target| {
            self.blocklist.lookup(target) == Verdict::Blocked && !self.allowlist.allows(target)
        })
    }

    /// Whether `client` gets any response, counting this request against its rate limit.
    /// `apple_service` counts the request against the Apple allowance instead of the ordinary
    /// one; it does not exempt it from the served networks.
    ///
    /// A device outside the served networks is not one of the devices this is for: it is not
    /// journalled, and only its first request is recorded as an event. A device querying too
    /// often goes unanswered for the rest of the window, with only the first excess recorded —
    /// a flood would otherwise flood the journal too.
    ///
    /// What breaks if you change it: the two allowances must stay apart. Shared, a device that
    /// used up its ordinary allowance (and source addresses on a LAN can be forged) could not
    /// reach captive/push and falls back to an unfiltered resolver. Exempting Apple's hosts
    /// altogether instead lets any device send made-up names under `push.apple.com` without end.
    fn admit(&self, client: IpAddr, apple_service: bool) -> bool {
        if let Admit::No { first } = self.served.admit(client) {
            if first && let Some(journal) = self.journal.as_ref() {
                journal.event(EventKind::OutsideClient, client.to_string());
            }
            return false;
        }
        let (limit, kind) = if apple_service {
            (&self.apple_rate_limit, "queries for Apple's services")
        } else {
            (&self.rate_limit, "queries")
        };
        if let Admit::No { first } = limit.check(client, Instant::now()) {
            if first && let Some(journal) = self.journal.as_ref() {
                journal.event(
                    EventKind::RateLimited,
                    format!(
                        "{client} made more than {} {kind} in one minute",
                        crate::policy::ratelimit::MAX_PER_WINDOW
                    ),
                );
            }
            return false;
        }
        true
    }

    fn log(
        &self,
        query: &Query,
        client: IpAddr,
        disposition: Disposition,
        reason: impl Into<Cow<'static, str>>,
    ) {
        let Some(journal) = self.journal.as_ref() else {
            return;
        };
        journal.record(Record {
            at: SystemTime::now(),
            client,
            name: query.name().to_string(),
            record_type: record_type_name(query.record_type()),
            disposition,
            reason: reason_for(disposition, reason.into()),
        });
    }
}

/// The "why" line in the journal. A disposition only decided during forwarding has to state
/// its own reason; it cannot reuse the one the caller wrote during the list check.
///
/// What breaks if you change it: without this layer, a discarded answer is journalled as
/// "rebind + blocklist unavailable, allowing" — a disposition and a reason that contradict
/// each other, and that line is what a person reads.
fn reason_for(disposition: Disposition, from_caller: Cow<'static, str>) -> Cow<'static, str> {
    let own = match disposition {
        Disposition::Rebind => "answer pointed into the local network; discarded whole",
        Disposition::Failed => "every upstream unreachable and nothing in the cache",
        Disposition::Overloaded => {
            "too many queries in flight upstream; this one was not sent and the cache was empty"
        }
        Disposition::ServFail => {
            "upstream returned a failure (usually that domain's own name servers)"
        }
        Disposition::DnssecBogus => "signature failed to validate; allowed and recorded per config",
        Disposition::Blocked
        | Disposition::Allowed
        | Disposition::FailOpen
        | Disposition::Local => return from_caller,
    };
    Cow::Borrowed(own)
}

/// How a cached answer is shaped on the way back to the device — identical to one arriving
/// straight from upstream.
fn response_of(cached: Cached) -> Response {
    match cached {
        Cached::Records(records) => Response::Answer(records),
        Cached::NameNotFound { ttl } => Response::NotFound { ttl },
        Cached::NoRecordsOfType { ttl } => Response::NoRecords { ttl },
    }
}

/// Which category an allowed answer is journalled as. A fail-open allow wins: item 6 of the
/// weekly summary ("was there a window with no protection?") depends on it, and if it gets
/// overwritten that window disappears silently.
fn disposition_with(write: CacheWrite, signature: Signature) -> Disposition {
    match (write, signature) {
        (CacheWrite::Forbidden, _) => Disposition::FailOpen,
        (CacheWrite::Allowed, Signature::Bogus) => Disposition::DnssecBogus,
        (CacheWrite::Allowed, Signature::NotFlagged) => Disposition::Allowed,
    }
}

fn disposition_for(write: CacheWrite) -> Disposition {
    match write {
        CacheWrite::Allowed => Disposition::Allowed,
        CacheWrite::Forbidden => Disposition::FailOpen,
    }
}

/// The record type as the journal writes it; only a type without a name costs an allocation.
fn record_type_name(record_type: RecordType) -> Cow<'static, str> {
    match record_type {
        RecordType::A => Cow::Borrowed("A"),
        RecordType::Aaaa => Cow::Borrowed("AAAA"),
        RecordType::Https => Cow::Borrowed("HTTPS"),
        RecordType::Other(value) => Cow::Owned(format!("TYPE{value}")),
    }
}

impl Responder for Gatekeeper {
    async fn respond(&self, query: &Query, client: IpAddr) -> Response {
        // The own-probe check below comes first on purpose: a probe from this Mac's own
        // address must be answered even when that address is outside the served networks, or
        // the health check restarts a healthy service.
        //
        // The gatekeeper's own probe: answered right here, without touching the lists, the
        // upstreams, or **the query journal**. It is nobody's browsing, and in the
        // statistics it would only ever be noise.
        // Not touching the upstreams is equally deliberate: the health check must still pass
        // while the internet is down, or one outage turns into an endless restart loop.
        if health::is_probe(query.name().as_str(), client, &self.own_addresses) {
            // Walk through the allowlist, blocklist and cache locks before answering: if any
            // of the three seizes up, the probe cannot be answered and the health check sees
            // "alive but stuck". What breaks if you change it: drop these three lines and
            // all three kinds of deadlock read as healthy.
            let _ = self.allowlist.allows(query.name().as_str());
            let _ = self.blocklist.lookup(query.name().as_str());
            let _ = self.cache.get(query);
            return Response::NotFound {
                ttl: self.block_ttl,
            };
        }

        if !self.admit(client, Allowlist::hard_allows(query.name().as_str())) {
            return Response::Ignored;
        }

        // Names that only mean something inside the network are answered locally with "does
        // not exist" rather than sent upstream: leaking local hostnames and private
        // address reverse lookups would violate product principle 3. Domains configured as
        // internal exceptions are forwarded as usual.
        if policy::local_zone::is_local(query.name().as_str())
            && !self.rebind_guard.is_internal_domain(query.name().as_str())
        {
            self.log(
                query,
                client,
                Disposition::Local,
                "internal network name; not sent outside",
            );
            return Response::NotFound {
                ttl: self.block_ttl,
            };
        }

        // The allowlist wins over the blocklist, and over the blocklist's loading state.
        // The Apple hard rules live inside it and must pass under all circumstances.
        // An allowlist hit still goes through the forwarding path's own verdict rather than
        // being hardcoded as "allowed" — when every upstream is down, or the answer is
        // dropped by the rebinding defence, the journal has to say what actually happened.
        let name = query.name().as_str();
        if self.allowlist.allows(name) {
            let reason = if Allowlist::hard_allows(name) {
                APPLE_SERVICE
            } else {
                USER_ALLOWED
            };
            let (response, disposition) = self.forward(query, CacheWrite::Allowed).await;
            self.log(query, client, disposition, reason);
            return response;
        }

        let Some(write) = cache_write_for(self.blocklist.lookup(name)) else {
            self.log(query, client, Disposition::Blocked, "blocklist");
            return Response::Blocked {
                ttl: self.block_ttl,
            };
        };
        let (response, disposition) = self.forward(query, write).await;
        if write == CacheWrite::Forbidden {
            self.log(
                query,
                client,
                disposition,
                "blocklist unavailable, allowing",
            );
            return response;
        }
        // CNAME cloaking: the name itself is not on a list, but its alias points at a domain
        // that is. Answers coming back out of the cache pass through here too, so they are
        // re-judged after a list update.
        if let Response::Answer(records) = &response
            && let Some(target) = self.cloaked_target(records)
        {
            self.log(
                query,
                client,
                Disposition::Blocked,
                format!("blocklist (alias points at {target})"),
            );
            return Response::Blocked {
                ttl: self.block_ttl,
            };
        }
        self.log(query, client, disposition, "");
        response
    }

    fn admits(&self, client: IpAddr) -> bool {
        self.admit(client, false)
    }
}

/// The journal reason for a query answered because an Apple hard rule allows it.
const APPLE_SERVICE: &str = "Apple service, always allowed";

/// What a blocklist verdict permits for the answer: `None` means block, and a list that is not
/// loaded forwards without caching.
///
/// What breaks if you change it: mapping `Unavailable` to [`CacheWrite::Allowed`] caches the
/// allows made while nothing was being checked, so those domains stay reachable after the list
/// comes back.
fn cache_write_for(verdict: Verdict) -> Option<CacheWrite> {
    match verdict {
        Verdict::Blocked => None,
        Verdict::Allowed => Some(CacheWrite::Allowed),
        Verdict::Unavailable => Some(CacheWrite::Forbidden),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::dns::Name;

    fn parts(blocklist: Blocklist) -> (Gatekeeper, Arc<Cache>) {
        parts_with(blocklist, None)
    }

    fn parts_with(blocklist: Blocklist, journal: Option<Journal>) -> (Gatekeeper, Arc<Cache>) {
        parts_full(blocklist, journal, RebindGuard::new())
    }

    fn parts_full(
        blocklist: Blocklist,
        journal: Option<Journal>,
        rebind_guard: RebindGuard,
    ) -> (Gatekeeper, Arc<Cache>) {
        let config =
            Config::parse("listen = 127.0.0.1:5353\nupstream = tls 1.1.1.1 cloudflare-dns.com\n")
                .unwrap();
        let conductor = Arc::new(Conductor::new(config.upstreams()).unwrap());
        let cache = Arc::new(Cache::new(100, Duration::from_secs(60 * 60)));
        let gatekeeper = Gatekeeper::new(
            Allowlist::new(),
            blocklist,
            Arc::clone(&cache),
            conductor,
            journal,
            Duration::from_secs(2),
            rebind_guard,
        );
        (gatekeeper, cache)
    }

    fn query(name: &str) -> Query {
        Query::new(Name::parse(name), RecordType::A)
    }

    fn localhost() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[tokio::test]
    async fn a_blocklist_hit_returns_a_block_with_the_configured_ttl() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("ads.example.com");
        let (gatekeeper, _) = parts(blocklist);
        match gatekeeper
            .respond(&query("ads.example.com"), localhost())
            .await
        {
            Response::Blocked { ttl } => assert_eq!(ttl, Duration::from_secs(2)),
            other => panic!("a blocked domain must get an unreachable address; got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subdomains_are_blocked_along_with_the_parent() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("example.com");
        let (gatekeeper, _) = parts(blocklist);
        assert!(matches!(
            gatekeeper
                .respond(&query("tracker.ads.example.com"), localhost())
                .await,
            Response::Blocked { .. }
        ));
    }

    #[tokio::test]
    async fn a_blocked_query_never_touches_the_cache() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("ads.example.com");
        let (gatekeeper, cache) = parts(blocklist);
        let _ = gatekeeper
            .respond(&query("ads.example.com"), localhost())
            .await;
        assert_eq!(
            cache.len(),
            0,
            "a blocked answer neither needs nor belongs in the cache"
        );
    }

    #[tokio::test]
    async fn apple_hard_rules_beat_the_blocklist() {
        // Even with Apple's domains deliberately put on the blocklist, they must pass.
        let blocklist = Blocklist::new();
        blocklist.load_from_str("captive.apple.com\npush.apple.com\n");
        let (gatekeeper, _) = parts(blocklist);

        for name in ["captive.apple.com", "1-courier.push.apple.com"] {
            let reply = gatekeeper.respond(&query(name), localhost()).await;
            assert!(
                !matches!(reply, Response::Blocked { .. }),
                "{name} was blocked — every iPhone on the network would pop up login windows or \
                 stop receiving messages"
            );
        }
    }

    #[tokio::test]
    async fn health_check_probes_stay_out_of_the_user_visible_journal() {
        // Mixed in, a probe every 10 seconds would drown the weekly statistics.
        let dir = std::env::temp_dir().join(format!(
            "phylode-gatekeeper-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = crate::journal::Journal::start(
            dir.clone(),
            10,
            crate::journal::LocalZone::fixed_hours(8),
        )
        .unwrap();

        // Put the probe's own name on the blocklist too, proving it takes its own path
        // rather than the list path.
        let blocklist = Blocklist::new();
        blocklist.load_from_str(&format!("ads.example.com\n{}\n", crate::health::PROBE_NAME));
        let (gatekeeper, cache) = parts_with(blocklist, Some(journal));

        let reply = gatekeeper
            .respond(&query(crate::health::PROBE_NAME), localhost())
            .await;
        assert!(
            matches!(reply, Response::NotFound { .. }),
            "the probe must be answered here, never falling through to the lists or upstream"
        );
        let _ = gatekeeper
            .respond(&query("ads.example.com"), localhost())
            .await;
        assert_eq!(cache.len(), 0);

        tokio::time::sleep(crate::journal::FLUSH_INTERVAL * 2).await;
        let mut written = String::new();
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            written.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
        }
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            written.contains("ads.example.com"),
            "an ordinary query must be journalled, or this test proves nothing"
        );
        assert!(
            !written.contains(crate::health::PROBE_NAME),
            "a health check probe appeared in the journal"
        );
    }

    /// Should change: bound to a LAN address, probes from our own address are answered here
    /// and not journalled.
    /// Should not change: another device querying the same name follows the ordinary rules
    /// and **is journalled** (this must not become an unlogged back door).
    #[tokio::test]
    async fn our_own_probe_is_recognized_when_bound_to_a_lan_address() {
        let dir = std::env::temp_dir().join(format!("phylode-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = crate::journal::Journal::start(
            dir.clone(),
            10,
            crate::journal::LocalZone::fixed_hours(8),
        )
        .unwrap();
        let ourselves: IpAddr = "192.168.0.192".parse().unwrap();
        let other_device: IpAddr = "192.168.0.20".parse().unwrap();
        let (gatekeeper, _) = parts_with(Blocklist::new(), Some(journal));
        let gatekeeper = gatekeeper.serving_on(vec![ourselves]);
        let q = query(crate::health::PROBE_NAME);

        assert!(matches!(
            gatekeeper.respond(&q, ourselves).await,
            Response::NotFound { .. }
        ));
        let _ = gatekeeper.respond(&q, other_device).await;

        tokio::time::sleep(crate::journal::FLUSH_INTERVAL * 2).await;
        let mut written = String::new();
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            written.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            written.contains("192.168.0.20\thealth-check"),
            "another device's query must be journalled, or this is an unlogged back door"
        );
        assert!(
            !written.contains("192.168.0.192"),
            "our own probe must not appear in the journal"
        );
    }

    /// Should change: local hostnames and private-address reverse lookups are answered
    /// locally with "does not exist" rather than sent upstream.
    /// Should not change: domains configured as internal exceptions are still forwarded, and
    /// so are public names.
    #[tokio::test]
    async fn internal_names_are_never_sent_upstream() {
        let (gatekeeper, _) = parts_full(
            Blocklist::new(),
            None,
            RebindGuard::with_internal_domains(["corp"]),
        );
        // Saturate the upstream slots: anything actually forwarded gets a failure, while
        // anything answered locally gets "does not exist".
        let _all = gatekeeper.conductor.occupy_all();
        let device: IpAddr = "192.168.0.20".parse().unwrap();

        for name in [
            "macbook.router.home",
            "printer.local",
            "1.0.168.192.in-addr.arpa",
        ] {
            assert!(
                matches!(
                    gatekeeper.respond(&query(name), device).await,
                    Response::NotFound { .. }
                ),
                "{name} should be answered locally"
            );
        }
        for name in ["wiki.corp", "www.example.com"] {
            assert!(
                matches!(
                    gatekeeper.respond(&query(name), device).await,
                    Response::Failure
                ),
                "{name} should still be forwarded"
            );
        }
        assert_eq!(Disposition::Local.as_str(), "local");
    }

    /// Should change: an alias pointing at a blocklisted domain is blocked (CNAME cloaking).
    /// Should not change: a name the user allowed is not blocked, and an alias target that is
    /// not on a list answers as usual.
    #[tokio::test]
    async fn an_alias_pointing_at_a_blocklisted_domain_is_blocked() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("evil.net\n");
        let (gatekeeper, cache) = parts(blocklist);
        let device: IpAddr = "192.168.0.20".parse().unwrap();
        let ttl = Duration::from_secs(300);
        let address: IpAddr = "93.184.216.34".parse().unwrap();

        let cloaked = query("metrics.example.com");
        cache.insert(
            cloaked.clone(),
            Cached::Records(crate::dns::Records::with_cname(
                cloaked.name(),
                ttl,
                "tracker.evil.net",
                address,
            )),
        );
        let clean = query("www.example.com");
        cache.insert(
            clean.clone(),
            Cached::Records(crate::dns::Records::with_cname(
                clean.name(),
                ttl,
                "cdn.example.org",
                address,
            )),
        );

        assert!(matches!(
            gatekeeper.respond(&cloaked, device).await,
            Response::Blocked { .. }
        ));
        assert!(matches!(
            gatekeeper.respond(&clean, device).await,
            Response::Answer(_)
        ));

        gatekeeper.allowlist.load_from_str("tracker.evil.net\n");
        assert!(
            matches!(
                gatekeeper.respond(&cloaked, device).await,
                Response::Answer(_)
            ),
            "once the user allows the alias target, it must stop being a reason to block"
        );
    }

    /// Should change: an HTTPS or SVCB record sending devices to a blocklisted endpoint is
    /// blocked, as a CNAME to it is.
    /// Should not change: a record whose endpoint is the name itself (`.`) answers as usual.
    #[tokio::test]
    async fn a_service_binding_to_a_blocklisted_endpoint_is_blocked() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("evil.net\n");
        let (gatekeeper, cache) = parts(blocklist);
        let device: IpAddr = "192.168.0.20".parse().unwrap();
        for (name, target, https, blocked) in [
            ("shop.example.com", "tracker.evil.net.", true, true),
            ("api.example.com", "tracker.evil.net.", false, true),
            ("www.example.com", ".", true, false),
        ] {
            let asked = Query::new(crate::dns::Name::parse(name), RecordType::Https);
            cache.insert(
                asked.clone(),
                Cached::Records(crate::dns::Records::with_service_binding(
                    asked.name(),
                    target,
                    https,
                )),
            );
            let response = gatekeeper.respond(&asked, device).await;
            assert_eq!(
                matches!(response, Response::Blocked { .. }),
                blocked,
                "{name} -> {target}"
            );
        }
    }

    /// Should change: an alias pointing at a listed internationalized domain is blocked, as a
    /// direct query for that domain is.
    #[tokio::test]
    async fn an_alias_to_a_listed_internationalized_domain_is_blocked() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("xn--bcher-kva.example\n");
        let (gatekeeper, cache) = parts(blocklist);
        let device: IpAddr = "192.168.0.20".parse().unwrap();
        let cloaked = query("metrics.example.com");
        cache.insert(
            cloaked.clone(),
            Cached::Records(crate::dns::Records::with_cname(
                cloaked.name(),
                Duration::from_secs(300),
                "xn--bcher-kva.example",
                "93.184.216.34".parse().unwrap(),
            )),
        );

        assert!(matches!(
            gatekeeper
                .respond(&query("xn--bcher-kva.example"), device)
                .await,
            Response::Blocked { .. }
        ));
        assert!(matches!(
            gatekeeper.respond(&cloaked, device).await,
            Response::Blocked { .. }
        ));
    }

    #[tokio::test]
    async fn apple_hard_rules_still_apply_while_the_blocklist_is_unavailable() {
        // They must pass even in the state where no list has loaded at all.
        let (gatekeeper, _) = parts(Blocklist::new());
        let reply = gatekeeper
            .respond(&query("captive.apple.com"), localhost())
            .await;
        assert!(!matches!(reply, Response::Blocked { .. }));
    }

    /// Should change: a domain the user allowed is journalled with the user-allowed reason, and
    /// an Apple hard rule with its own reason, so the weekly summary lists only the first.
    /// Should not change: both are answered.
    #[tokio::test]
    async fn user_allows_and_apple_hard_rules_are_journalled_apart() {
        let dir = std::env::temp_dir().join(format!("phylode-allowed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::start(dir.clone(), 10, crate::journal::LocalZone::utc()).unwrap();
        let (gatekeeper, cache) = parts_with(Blocklist::new(), Some(journal));
        gatekeeper.allowlist.load_from_str("shop.example.com\n");
        let address: IpAddr = "93.184.216.34".parse().unwrap();
        for name in ["shop.example.com", "captive.apple.com"] {
            let q = query(name);
            let records =
                crate::dns::Records::from_addresses(q.name(), Duration::from_secs(300), &[address]);
            cache.insert(q.clone(), Cached::Records(records));
            assert!(matches!(
                gatekeeper.respond(&q, localhost()).await,
                Response::Answer(_)
            ));
        }

        tokio::time::sleep(crate::journal::FLUSH_INTERVAL * 2).await;
        let mut written = String::new();
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            written.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            written.contains("shop.example.com\tA\tallowed\tallowlist\n"),
            "{written}"
        );
        assert!(
            written.contains("captive.apple.com\tA\tallowed\tApple service, always allowed\n"),
            "{written}"
        );
    }

    /// Should change: a device outside the served networks gets no response, even for a
    /// blocked domain or an Apple hard rule.
    /// Should not change: a device on the network is answered as usual.
    #[tokio::test]
    async fn devices_outside_the_served_networks_get_no_response() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("ads.example.com");
        let (gatekeeper, _) = parts(blocklist);
        let outsider: IpAddr = "203.0.113.9".parse().unwrap();
        let on_network: IpAddr = "192.168.1.20".parse().unwrap();
        for name in ["ads.example.com", "captive.apple.com"] {
            assert!(matches!(
                gatekeeper.respond(&query(name), outsider).await,
                Response::Ignored
            ));
        }
        assert!(matches!(
            gatekeeper
                .respond(&query("ads.example.com"), on_network)
                .await,
            Response::Blocked { .. }
        ));
    }

    #[test]
    fn an_unavailable_list_takes_the_cache_forbidden_path() {
        // The heart of the fail-open rule: both branches forward, but with different write
        // permissions.
        let empty = Blocklist::new();
        assert_eq!(empty.lookup("example.com"), Verdict::Unavailable);

        let loaded = Blocklist::new();
        loaded.load_from_str("ads.example.com");
        assert_eq!(loaded.lookup("example.com"), Verdict::Allowed);
        assert_eq!(loaded.lookup("ads.example.com"), Verdict::Blocked);

        assert_eq!(cache_write_for(Verdict::Allowed), Some(CacheWrite::Allowed));
        assert_eq!(
            cache_write_for(Verdict::Unavailable),
            Some(CacheWrite::Forbidden)
        );
        assert_eq!(cache_write_for(Verdict::Blocked), None);
    }

    #[test]
    fn a_fail_open_allow_is_journalled_distinctly_from_an_ordinary_allow() {
        // The weekly summary has to be able to say "there was no protection during this
        // window", so the two cannot be recorded as the same thing.
        assert_eq!(disposition_for(CacheWrite::Allowed), Disposition::Allowed);
        assert_eq!(
            disposition_for(CacheWrite::Forbidden),
            Disposition::FailOpen
        );
    }

    #[test]
    fn record_type_names_as_written_to_the_journal() {
        assert_eq!(record_type_name(RecordType::A), "A");
        assert_eq!(record_type_name(RecordType::Aaaa), "AAAA");
        assert_eq!(record_type_name(RecordType::Other(15)), "TYPE15");
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test addresses must parse")
    }

    /// Builds an answer as it would come back from upstream. The 300-second TTL is typical
    /// of a real A record.
    fn upstream_answer(name: &str, addresses: &[IpAddr]) -> (Query, Answer) {
        let q = query(name);
        let records =
            crate::dns::Records::from_addresses(q.name(), Duration::from_secs(300), addresses);
        (q, Answer::Records(records))
    }

    #[test]
    fn an_answer_pointing_inward_is_discarded_and_not_cached() {
        // The technique for turning a browser into a pivot into the LAN.
        let (gatekeeper, cache) = parts(Blocklist::new());
        let (q, answer) = upstream_answer("evil.example.com", &[ip("192.168.0.1")]);

        let (response, disposition) =
            gatekeeper.deliver(&q, answer, CacheWrite::Allowed, Signature::NotFlagged);

        assert!(
            matches!(response, Response::NoRecords { ttl } if ttl == Duration::from_secs(2)),
            "should be NOERROR with an SOA and a short TTL; got {response:?}"
        );
        assert_eq!(disposition, Disposition::Rebind);
        assert_eq!(cache.len(), 0, "a discarded answer must not be cached");
    }

    #[test]
    fn mixing_in_a_public_address_does_not_get_past_it() {
        // An attacker bets that we filter individual records instead of dropping the batch.
        let (gatekeeper, cache) = parts(Blocklist::new());
        let (q, answer) = upstream_answer("evil.example.com", &[ip("1.1.1.1"), ip("10.0.0.5")]);

        let (_, disposition) =
            gatekeeper.deliver(&q, answer, CacheWrite::Allowed, Signature::NotFlagged);

        assert_eq!(disposition, Disposition::Rebind);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn an_ordinary_public_answer_is_served_and_cached() {
        // The control: without this passing, the two tests above prove nothing — everything
        // might simply be getting blocked.
        let (gatekeeper, cache) = parts(Blocklist::new());
        let (q, answer) = upstream_answer("www.example.com", &[ip("93.184.216.34")]);

        let (response, disposition) =
            gatekeeper.deliver(&q, answer, CacheWrite::Allowed, Signature::NotFlagged);

        assert!(matches!(response, Response::Answer(_)));
        assert_eq!(disposition, Disposition::Allowed);
        assert_eq!(cache.len(), 1);
    }

    /// Should change: "no such name" and "no records of that type" are cached, so the same
    /// query does not go upstream twice.
    /// Should not change: the device still receives the upstream's TTL, and an uncached
    /// query still fails while the upstream slots are full.
    #[tokio::test]
    async fn negative_answers_are_cached_and_not_asked_twice() {
        let (gatekeeper, cache) = parts(Blocklist::new());
        let ttl = Duration::from_secs(300);
        let typo = query("typo.example.com");
        let ipv4_only = Query::new(Name::parse("ipv4only.example.com"), RecordType::Aaaa);

        let (response, _) = gatekeeper.deliver(
            &typo,
            Answer::NameNotFound { ttl },
            CacheWrite::Allowed,
            Signature::NotFlagged,
        );
        assert!(matches!(response, Response::NotFound { ttl: t } if t == ttl));
        gatekeeper.deliver(
            &ipv4_only,
            Answer::NoRecordsOfType { ttl },
            CacheWrite::Allowed,
            Signature::NotFlagged,
        );
        assert_eq!(cache.len(), 2);

        // Saturate the upstream slots: anything actually sent can only fail, so getting an
        // answer proves it came from the cache.
        let _all = gatekeeper.conductor.occupy_all();
        let device: IpAddr = "192.168.0.20".parse().unwrap();
        assert!(matches!(
            gatekeeper.respond(&typo, device).await,
            Response::NotFound { .. }
        ));
        assert!(matches!(
            gatekeeper.respond(&ipv4_only, device).await,
            Response::NoRecords { .. }
        ));
        assert!(
            matches!(
                gatekeeper
                    .respond(&query("never-seen.example.com"), device)
                    .await,
                Response::Failure
            ),
            "control: something never cached must fail while the upstreams are saturated"
        );
    }

    /// Should not change: fail-open allows, bogus signatures and SERVFAIL are never cached.
    #[test]
    fn answers_that_must_not_be_remembered_are_not_cached() {
        let (gatekeeper, cache) = parts(Blocklist::new());
        let ttl = Duration::from_secs(300);
        let q = query("typo.example.com");

        gatekeeper.deliver(
            &q,
            Answer::NameNotFound { ttl },
            CacheWrite::Forbidden,
            Signature::NotFlagged,
        );
        gatekeeper.deliver(
            &q,
            Answer::NameNotFound { ttl },
            CacheWrite::Allowed,
            Signature::Bogus,
        );
        gatekeeper.deliver(
            &q,
            Answer::ServerFailure,
            CacheWrite::Allowed,
            Signature::NotFlagged,
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_configured_internal_domain_may_point_inward() {
        let (gatekeeper, cache) = parts_full(
            Blocklist::new(),
            None,
            RebindGuard::with_internal_domains(["home.arpa"]),
        );
        let (q, answer) = upstream_answer("nas.home.arpa", &[ip("192.168.0.9")]);

        let (response, disposition) =
            gatekeeper.deliver(&q, answer, CacheWrite::Allowed, Signature::NotFlagged);

        assert!(matches!(response, Response::Answer(_)));
        assert_eq!(disposition, Disposition::Allowed);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_discarded_answer_is_still_journalled_as_rebinding_during_a_list_outage() {
        // A list outage means "no filtering"; a rebinding attempt means "someone is
        // targeting the network". The two differ in severity and must not be merged.
        let (gatekeeper, _) = parts(Blocklist::new());
        let (q, answer) = upstream_answer("evil.example.com", &[ip("192.168.0.1")]);

        let (_, disposition) =
            gatekeeper.deliver(&q, answer, CacheWrite::Forbidden, Signature::NotFlagged);

        assert_eq!(disposition, Disposition::Rebind);
    }

    #[test]
    fn a_discarded_answer_has_its_own_code_in_the_journal() {
        // Part of the file format; the weekly summary uses it to recognize this category.
        assert_eq!(Disposition::Rebind.as_str(), "rebind");
    }

    #[test]
    fn the_journalled_reason_matches_the_disposition() {
        // Found while exercising the real binary: a disposition decided during forwarding
        // that reuses the caller's reason reads as "rebind + blocklist unavailable,
        // allowing", which looks like the query was allowed.
        assert_eq!(
            reason_for(
                Disposition::Rebind,
                "blocklist unavailable, allowing".into()
            ),
            "answer pointed into the local network; discarded whole"
        );
        assert_eq!(
            reason_for(
                Disposition::Failed,
                "blocklist unavailable, allowing".into()
            ),
            "every upstream unreachable and nothing in the cache"
        );
        assert!(
            reason_for(Disposition::Overloaded, "".into()).contains("too many"),
            "saturation must not be described as the upstream being down"
        );
        // The three decided during the list check keep the caller's reason.
        for disposition in [
            Disposition::Blocked,
            Disposition::Allowed,
            Disposition::FailOpen,
        ] {
            assert_eq!(reason_for(disposition, "blocklist".into()), "blocklist");
        }
    }

    /// Should change: an answer with a flagged signature is journalled as dnssec-bogus.
    /// Should not change: a fail-open allow is still journalled as fail-open.
    #[test]
    fn a_bogus_signature_is_served_as_usual_but_categorized_differently() {
        assert_eq!(
            disposition_with(CacheWrite::Allowed, Signature::Bogus),
            Disposition::DnssecBogus
        );
        assert_eq!(
            disposition_with(CacheWrite::Allowed, Signature::NotFlagged),
            Disposition::Allowed
        );
        assert_eq!(
            disposition_with(CacheWrite::Forbidden, Signature::Bogus),
            Disposition::FailOpen,
            "a window with no protection must not be overwritten"
        );
    }

    /// Should change: with the upstream slots full and nothing cached, the query fails and is
    /// journalled as overloaded.
    /// Should not change: no network is touched, and no upstream is marked as failed.
    #[tokio::test]
    async fn too_many_in_flight_queries_fail_rather_than_queue() {
        let (gatekeeper, _) = parts(Blocklist::new());
        let _all = gatekeeper.conductor.occupy_all();
        let (response, disposition) = gatekeeper
            .forward(&query("busy.example.com"), CacheWrite::Allowed)
            .await;
        assert!(matches!(response, Response::Failure));
        assert_eq!(disposition, Disposition::Overloaded);
    }

    /// Should change: a device past the limit gets no response.
    /// Should not change: other devices are still blocked normally, and queries under the
    /// limit are still answered.
    #[tokio::test]
    async fn a_device_querying_too_often_gets_no_response() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("ads.example.com");
        let (gatekeeper, _) = parts(blocklist);
        let noisy: IpAddr = "192.168.1.20".parse().unwrap();
        let other_device: IpAddr = "192.168.1.21".parse().unwrap();
        let q = query("ads.example.com");
        for _ in 0..crate::policy::ratelimit::MAX_PER_WINDOW {
            assert!(matches!(
                gatekeeper.respond(&q, noisy).await,
                Response::Blocked { .. }
            ));
        }
        assert!(matches!(
            gatekeeper.respond(&q, noisy).await,
            Response::Ignored
        ));
        assert!(matches!(
            gatekeeper.respond(&q, other_device).await,
            Response::Blocked { .. }
        ));

        // Apple hard rules are exempt from rate limiting. Saturate the upstream slots first
        // so this answers without needing the network.
        let _all = gatekeeper.conductor.occupy_all();
        assert!(
            !matches!(
                gatekeeper.respond(&query("captive.apple.com"), noisy).await,
                Response::Ignored
            ),
            "a rate-limited device that cannot reach captive.apple.com falls back to an \
             unfiltered resolver"
        );
    }

    /// Should change: Apple's hosts have a limit of their own, so made-up names under
    /// `push.apple.com` can no longer be sent without end.
    /// Should not change: using up the Apple allowance leaves the ordinary one untouched, and
    /// the other way round (the test above).
    #[tokio::test]
    async fn apple_hosts_have_their_own_allowance() {
        let blocklist = Blocklist::new();
        blocklist.load_from_str("ads.example.com");
        let (gatekeeper, _) = parts(blocklist);
        let _all = gatekeeper.conductor.occupy_all();
        let noisy: IpAddr = "192.168.1.20".parse().unwrap();
        for n in 0..crate::policy::ratelimit::MAX_PER_WINDOW {
            let made_up = query(&format!("x{n}.push.apple.com"));
            assert!(!matches!(
                gatekeeper.respond(&made_up, noisy).await,
                Response::Ignored
            ));
        }
        assert!(matches!(
            gatekeeper
                .respond(&query("over.push.apple.com"), noisy)
                .await,
            Response::Ignored
        ));
        assert!(matches!(
            gatekeeper.respond(&query("ads.example.com"), noisy).await,
            Response::Blocked { .. }
        ));
    }

    /// Should change: with the cache lock seized, the health check probe cannot be answered
    /// (it used to be answered at the door and counted as healthy regardless).
    /// Should not change: once the lock is released it answers as usual (the control).
    #[test]
    fn a_seized_cache_lock_stops_the_health_probe_being_answered() {
        let (gatekeeper, cache) = parts(Blocklist::new());
        let gatekeeper = Arc::new(gatekeeper);
        let probe = query(health::PROBE_NAME);

        let held = cache.hold_lock();
        let (sender, answered) = std::sync::mpsc::channel();
        let asker = Arc::clone(&gatekeeper);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = sender.send(runtime.block_on(asker.respond(&probe, localhost())));
        });

        assert!(
            answered.recv_timeout(Duration::from_millis(300)).is_err(),
            "nothing should be answerable while the cache lock is held"
        );
        drop(held);
        assert!(
            matches!(
                answered.recv_timeout(Duration::from_secs(2)),
                Ok(Response::NotFound { .. })
            ),
            "it must answer again once the lock is released"
        );
    }
}
