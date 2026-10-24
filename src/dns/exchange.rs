//! Outbound query transport: sends one [`Query`] to one upstream resolver and returns
//! [`Records`].
//!
//! This module only handles getting the packet out. **Which upstream to pick, what to do when
//! one fails, and how health is scored all live in `upstream`** — the same protocol/rotation
//! split Cloudflare's 1.1.1.1 resolver (Big Pineapple) uses.
//!
//! What breaks if you change it: **only encrypted protocols exist here**. Adding a plaintext
//! option opens a downgrade path, violating RFC 8310 Strict Privacy.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use hickory_proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, Query as WireQuery, ResponseCode,
};
use hickory_proto::rr::{Name as WireName, RecordType as WireRecordType};
use hickory_resolver::config::{NameServerConfig, ResolverOpts};
use hickory_resolver::net::DnsHandle;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use hickory_server::net::{DnsError, NetError, NoRecords};
use thiserror::Error;

use super::{Answer, Proof, Query, RecordType, Records};
use crate::config::{Upstream, UpstreamProtocol};

/// How long one outbound query waits on one upstream. On timeout it moves to the next
/// candidate rather than waiting indefinitely.
///
/// Ours: Apple, Anthropic and Cloudflare publish no figure. Two seconds is far past any
/// healthy encrypted answer, and short enough that the device, which waits on us, is still
/// waiting when the next upstream answers.
/// What breaks if you change it: too large and one dead upstream stalls the user's page for
/// that long; too small and a slow network makes healthy upstreams look like failures.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// The DoH query path. The RFC 8484 convention, used by every major provider today.
const DOH_PATH: &str = "/dns-query";

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("could not establish a connection to upstream {server_name}: {source}")]
    Connect {
        server_name: String,
        #[source]
        source: hickory_server::net::NetError,
    },
    #[error("query to upstream {server_name} failed: {source}")]
    Query {
        server_name: String,
        #[source]
        source: hickory_server::net::NetError,
    },
}

/// Whether the upstream flagged this answer's signature as failing validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signature {
    /// The upstream raised no objection: the signature validated, or the domain is unsigned.
    NotFlagged,
    /// Signature validation failed upstream (it returned SERVFAIL), and the answer only came
    /// back on the retry with the CD flag set.
    ///
    /// The gatekeeper refuses such an answer unless the user allowed the domain; the retry is
    /// what lets the journal say why the domain failed.
    Bogus,
}

/// An upstream answer, plus whether the upstream flagged its signature.
#[derive(Clone, Debug)]
pub struct Checked {
    pub(crate) answer: Answer,
    pub(crate) signature: Signature,
}

/// Whether the upstream validates signatures before answering (the CD flag, RFC 4035 §3.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Checking {
    /// CD clear: the upstream validates, and answers SERVFAIL when validation fails.
    Enabled,
    /// CD set: the upstream returns the answer as-is.
    Disabled,
}

/// An encrypted channel to one upstream resolver.
///
/// This sends hand-built queries through hickory's `NameServerPool` rather than its high-level
/// resolver, because the high-level resolver cannot set the CD (Checking Disabled) flag — and
/// that flag is what retrieves an answer when signature validation fails.
#[derive(Clone)]
pub struct Exchange {
    pool: Arc<NameServerPool<TokioRuntimeProvider>>,
    server_name: String,
}

impl std::fmt::Debug for Exchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Exchange")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl Exchange {
    /// Builds the channel. The address is the configured IP and the hostname is only used to
    /// validate the certificate, so this step needs no DNS lookup of its own — and therefore
    /// cannot end up querying itself.
    pub fn connect(upstream: &Upstream) -> Result<Self, ExchangeError> {
        let server_name: Arc<str> = Arc::from(upstream.server_name());
        let name_server = match upstream.protocol() {
            UpstreamProtocol::Tls => NameServerConfig::tls(upstream.ip(), Arc::clone(&server_name)),
            UpstreamProtocol::Https => NameServerConfig::https(
                upstream.ip(),
                Arc::clone(&server_name),
                Some(Arc::from(DOH_PATH)),
            ),
        };

        let mut options = ResolverOpts::default();
        options.timeout = QUERY_TIMEOUT;
        // Caching is our `cache` module's job; disabled here so one answer is not stored
        // twice with two different expiry times.
        options.cache_size = 0;
        // Upstream certificates are validated against the macOS system trust store (via
        // rustls-platform-verifier, enabled in Cargo.toml), so root certificates update with
        // the OS. What breaks if you go back to a bundled list: on the day a root rolls over,
        // every upstream fails validation at once.
        let tls = TlsConfig::new().map_err(|source| ExchangeError::Connect {
            server_name: upstream.server_name().to_string(),
            source,
        })?;
        let pool = NameServerPool::from_config(
            [name_server],
            Arc::new(PoolContext::new(options, tls)),
            TokioRuntimeProvider::default(),
        );

        Ok(Self {
            pool: Arc::new(pool),
            server_name: upstream.server_name().to_string(),
        })
    }

    /// Sends one query to this upstream.
    ///
    /// What breaks if you change it: **"no such name" and "cannot reach this upstream" must
    /// return separately.** Merged into one `Err`, every typo becomes "the server is broken",
    /// and an upstream that answered correctly gets a failure recorded — two of those and it
    /// is demoted.
    ///
    /// **A SERVFAIL is also not "unreachable"**: the upstream did answer. In that case the
    /// query is retried with the CD flag — getting an answer means signature validation failed
    /// upstream ([`Signature::Bogus`]); another SERVFAIL means the upstream honestly reported a
    /// failure (usually that domain's own name servers), returning
    /// [`Answer::ServerFailure`]. Neither counts as a failure for this upstream, or two
    /// queries for one badly signed domain would demote a perfectly healthy server.
    pub async fn query(&self, query: &Query) -> Result<Checked, ExchangeError> {
        let first = self.send(query, Checking::Enabled).await;
        if !is_server_failure(&first) {
            return self.classify(first).map(|answer| Checked {
                answer,
                signature: Signature::NotFlagged,
            });
        }
        let retried = self.send(query, Checking::Disabled).await;
        if is_server_failure(&retried) {
            return Ok(Checked {
                answer: Answer::ServerFailure,
                signature: Signature::NotFlagged,
            });
        }
        self.classify(retried).map(|answer| Checked {
            answer,
            signature: Signature::Bogus,
        })
    }

    /// Sends one query. With `Checking::Disabled`, the CD flag asks the upstream not to
    /// validate signatures and to return the answer as-is.
    ///
    /// What breaks if you change it: names must go through `from_utf8`, which converts
    /// non-ASCII domains to their `xn--` punycode form. Switching to `from_ascii` makes every
    /// internationalized domain fail — and those failures get counted against the upstream.
    async fn send(&self, query: &Query, checking: Checking) -> Result<DnsResponse, NetError> {
        let name = WireName::from_utf8(format!("{}.", query.name()))
            .map_err(|_| NetError::from("query name is not a valid domain"))?;
        let mut message = Message::query();
        message.add_query(WireQuery::query(
            name,
            wire_record_type(query.record_type()),
        ));
        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = checking == Checking::Disabled;
        message.set_edns(signatures_requested());
        let request = DnsRequest::new(message, DnsRequestOptions::default());
        match self.pool.send(request).next().await {
            Some(result) => result,
            None => Err(NetError::from("the upstream returned nothing at all")),
        }
    }

    fn classify(&self, result: Result<DnsResponse, NetError>) -> Result<Answer, ExchangeError> {
        match result {
            Ok(response) => Ok(Answer::Records(Records::from_wire(
                response.answers.to_vec(),
                response.authorities.to_vec(),
            ))),
            Err(NetError::Dns(DnsError::NoRecordsFound(empty))) => Ok(negative(&empty)),
            // Any other response code (REFUSED, NOTIMP, FORMERR…) is still an answer: counted
            // as the upstream failing, a device asking for zone transfers would demote it.
            Err(NetError::Dns(DnsError::ResponseCode(_))) => Ok(Answer::ServerFailure),
            Err(source) => Err(ExchangeError::Query {
                server_name: self.server_name.clone(),
                source,
            }),
        }
    }
}

fn is_server_failure(result: &Result<DnsResponse, NetError>) -> bool {
    matches!(
        result,
        Err(NetError::Dns(DnsError::ResponseCode(
            ResponseCode::ServFail
        )))
    )
}

/// The EDNS every upstream query carries: the DO bit, so the upstream includes signatures and
/// the records proving a name or type does not exist (RFC 3225; RFC 4035 §3.2.1), and the same
/// UDP size this server offers devices. Set on every query whether or not the device validates,
/// so one cached copy serves both kinds of device.
///
/// What breaks if you change it: without the DO bit the upstream sends no signatures, and every
/// device that validates them (Apple's `requiresDNSSECValidation`) can reach nothing at all.
fn signatures_requested() -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(super::server::MAX_UDP_PAYLOAD);
    edns.set_dnssec_ok(true);
    edns
}

/// Used when the upstream gives no negative caching time.
///
/// ⚠️ Ours, with no industry source. Short is safer than long: a newly registered domain
/// remembered as "does not exist" for too long is unreachable on the network for that whole time,
/// with no visible reason.
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// The longest a device is told to remember "does not exist": the low end of RFC 2308's "one
/// to three hours", as the cache's own ceiling is.
/// What breaks if you change it: a newly registered domain stays unreachable on a device for
/// whatever the upstream asked, a day or more, after the cache here has long forgotten it.
const MAX_NEGATIVE_TTL: Duration = Duration::from_secs(60 * 60);

/// Translates an upstream's negative response into an answer. The response code decides
/// between "the name does not exist" and "no records of that type". The proof keeps the
/// upstream's authority section with its TTLs cut to the same limit, so a device that
/// validates signatures remembers the answer no longer than any other device.
fn negative(empty: &NoRecords) -> Answer {
    let ttl = empty.negative_ttl.map_or(DEFAULT_NEGATIVE_TTL, |seconds| {
        Duration::from_secs(u64::from(seconds)).min(MAX_NEGATIVE_TTL)
    });
    let ceiling = u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX);
    let authority = empty
        .authorities
        .as_deref()
        .map(<[_]>::to_vec)
        .unwrap_or_default();
    let proof = Proof::from_wire(authority, ceiling);
    if empty.response_code == ResponseCode::NXDomain {
        Answer::NameNotFound { ttl, proof }
    } else {
        Answer::NoRecordsOfType { ttl, proof }
    }
}

fn wire_record_type(record_type: RecordType) -> WireRecordType {
    match record_type {
        RecordType::A => WireRecordType::A,
        RecordType::Aaaa => WireRecordType::AAAA,
        RecordType::Https => WireRecordType::HTTPS,
        RecordType::Other(value) => WireRecordType::from(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(text: &str) -> Upstream {
        let config =
            crate::config::Config::parse(&format!("listen = 127.0.0.1:5353\nupstream = {text}"))
                .expect("test configuration should parse");
        config.upstreams()[0].clone()
    }

    #[test]
    fn building_a_channel_needs_no_dns_lookup() {
        // The configuration gives only an IP and a certificate name, so connect neither will
        // nor can resolve a hostname.
        let exchange = Exchange::connect(&upstream("tls 1.1.1.1 cloudflare-dns.com"))
            .expect("building a channel from an IP should succeed");
        assert!(format!("{exchange:?}").contains("cloudflare-dns.com"));
    }

    #[test]
    fn both_doh_and_dot_can_be_built() {
        assert!(Exchange::connect(&upstream("https 9.9.9.9 dns.quad9.net")).is_ok());
        assert!(Exchange::connect(&upstream("tls 9.9.9.9 dns.quad9.net")).is_ok());
    }

    fn empty_response(code: ResponseCode, negative_ttl: Option<u32>) -> NoRecords {
        let name: hickory_proto::rr::Name = "example.com.".parse().unwrap();
        let query = hickory_proto::op::Query::query(name, WireRecordType::A);
        let mut empty = NoRecords::new(query, code);
        empty.negative_ttl = negative_ttl;
        empty
    }

    #[test]
    fn no_such_name_and_no_such_type_stay_distinct() {
        // Merged, an IPv4-only site asked for AAAA makes the device conclude the whole domain
        // does not exist and stop trying IPv4 as well.
        assert!(matches!(
            negative(&empty_response(ResponseCode::NXDomain, Some(30))),
            Answer::NameNotFound { ttl, .. } if ttl == Duration::from_secs(30)
        ));
        assert!(matches!(
            negative(&empty_response(ResponseCode::NoError, Some(30))),
            Answer::NoRecordsOfType { .. }
        ));
    }

    /// Should change: a negative time longer than an hour is cut to an hour.
    /// Should not change: shorter ones pass through as given.
    #[test]
    fn a_negative_answer_is_remembered_for_at_most_an_hour() {
        assert!(matches!(
            negative(&empty_response(ResponseCode::NXDomain, Some(86_400))),
            Answer::NameNotFound { ttl, .. } if ttl == Duration::from_secs(3600)
        ));
        assert!(matches!(
            negative(&empty_response(ResponseCode::NoError, Some(900))),
            Answer::NoRecordsOfType { ttl, .. } if ttl == Duration::from_secs(900)
        ));
    }

    /// Should change: the upstream's authority section is kept as the proof, with each TTL cut
    /// to the same hour as the answer itself.
    /// Should not change: no record of the proof is dropped or reordered.
    #[test]
    fn a_negative_answer_keeps_the_upstreams_proof() {
        let zone = crate::dns::Proof::for_zone(&super::super::Name::parse("example.com"));
        let mut authority = zone.as_wire().to_vec();
        for record in &mut authority {
            record.ttl = 86_400;
        }
        let mut empty = empty_response(ResponseCode::NXDomain, Some(86_400));
        empty.authorities = Some(authority.into());

        let Answer::NameNotFound { ttl, proof } = negative(&empty) else {
            panic!("an NXDOMAIN is a name not found");
        };
        assert_eq!(ttl, Duration::from_secs(3600));
        let kinds: Vec<_> = proof.as_wire().iter().map(|r| r.record_type()).collect();
        assert_eq!(kinds, [WireRecordType::SOA, WireRecordType::RRSIG]);
        assert!(proof.as_wire().iter().all(|record| record.ttl == 3600));
    }

    /// Should change: every query to an upstream asks for signatures (the DO bit).
    #[test]
    fn upstream_queries_ask_for_signatures() {
        assert!(signatures_requested().flags().dnssec_ok);
    }

    /// Should change: an upstream that answers with a refusal or "not implemented" (as it does
    /// for zone transfers and other unusual types) has answered, so it is an answered failure.
    /// Should not change: a connection that never answers is still the upstream's failure.
    #[test]
    fn a_refusal_from_the_upstream_is_an_answer_not_an_outage() {
        let exchange = Exchange::connect(&upstream("tls 1.1.1.1 cloudflare-dns.com")).unwrap();
        for code in [
            ResponseCode::Refused,
            ResponseCode::NotImp,
            ResponseCode::FormErr,
        ] {
            assert!(
                matches!(
                    exchange.classify(Err(NetError::Dns(DnsError::ResponseCode(code)))),
                    Ok(Answer::ServerFailure)
                ),
                "{code:?}"
            );
        }
        assert!(
            exchange
                .classify(Err(NetError::from("the connection timed out")))
                .is_err()
        );
    }

    #[test]
    fn a_missing_negative_ttl_falls_back_to_the_default() {
        assert!(matches!(
            negative(&empty_response(ResponseCode::NXDomain, None)),
            Answer::NameNotFound { ttl, .. } if ttl == DEFAULT_NEGATIVE_TTL
        ));
    }

    /// Should not change: a non-ASCII domain is still converted to punycode on the way out and
    /// never fails at packet assembly.
    #[test]
    fn a_non_ascii_domain_converts_to_a_sendable_name() {
        let name = WireName::from_utf8("δοκιμή.example.").expect("it must convert");
        assert!(name.to_ascii().starts_with("xn--"), "{name}");
    }

    #[test]
    fn record_types_map_to_their_wire_values() {
        assert_eq!(wire_record_type(RecordType::A), WireRecordType::A);
        assert_eq!(wire_record_type(RecordType::Aaaa), WireRecordType::AAAA);
        assert_eq!(
            wire_record_type(RecordType::Other(u16::from(WireRecordType::MX))),
            WireRecordType::MX
        );
    }
}
