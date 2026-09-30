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
    DnsRequest, DnsRequestOptions, DnsResponse, Message, Query as WireQuery, ResponseCode,
};
use hickory_proto::rr::{Name as WireName, RecordType as WireRecordType};
use hickory_resolver::config::{NameServerConfig, ResolverOpts};
use hickory_resolver::net::DnsHandle;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use hickory_server::net::{DnsError, NetError, NoRecords};
use thiserror::Error;

use super::{Answer, Query, RecordType, Records};
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
    /// ⚠️ This is report-only by decision: such answers are served to the device as usual and
    /// merely recorded. Switching to enforcement needs an explicit decision.
    Bogus,
}

/// An upstream answer, plus whether the upstream flagged its signature.
#[derive(Clone, Debug)]
pub struct Checked {
    pub answer: Answer,
    pub signature: Signature,
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
        let first = self.send(query, false).await;
        if !is_server_failure(&first) {
            return self.classify(first).map(|answer| Checked {
                answer,
                signature: Signature::NotFlagged,
            });
        }
        let retried = self.send(query, true).await;
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

    /// Sends one query. With `checking_disabled` true, the CD flag asks the upstream not to
    /// validate signatures and to return the answer as-is.
    ///
    /// What breaks if you change it: names must go through `from_utf8`, which converts
    /// non-ASCII domains to their `xn--` punycode form. Switching to `from_ascii` makes every
    /// internationalized domain fail — and those failures get counted against the upstream.
    async fn send(&self, query: &Query, checking_disabled: bool) -> Result<DnsResponse, NetError> {
        let name = WireName::from_utf8(format!("{}.", query.name()))
            .map_err(|_| NetError::from("query name is not a valid domain"))?;
        let mut message = Message::query();
        message.add_query(WireQuery::query(
            name,
            wire_record_type(query.record_type()),
        ));
        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = checking_disabled;
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
            ))),
            Err(NetError::Dns(DnsError::NoRecordsFound(empty))) => Ok(negative(&empty)),
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

/// Used when the upstream gives no negative caching time.
///
/// ⚠️ Ours, with no industry source. Short is safer than long: a newly registered domain
/// remembered as "does not exist" for too long is unreachable at home for that whole time,
/// with no visible reason.
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// Translates an upstream's negative response into an answer. The response code decides
/// between "the name does not exist" and "no records of that type".
fn negative(empty: &NoRecords) -> Answer {
    let ttl = empty.negative_ttl.map_or(DEFAULT_NEGATIVE_TTL, |seconds| {
        Duration::from_secs(u64::from(seconds))
    });
    if empty.response_code == ResponseCode::NXDomain {
        Answer::NameNotFound { ttl }
    } else {
        Answer::NoRecordsOfType { ttl }
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
            Answer::NameNotFound { ttl } if ttl == Duration::from_secs(30)
        ));
        assert!(matches!(
            negative(&empty_response(ResponseCode::NoError, Some(30))),
            Answer::NoRecordsOfType { .. }
        ));
    }

    #[test]
    fn a_missing_negative_ttl_falls_back_to_the_default() {
        assert!(matches!(
            negative(&empty_response(ResponseCode::NXDomain, None)),
            Answer::NameNotFound { ttl } if ttl == DEFAULT_NEGATIVE_TTL
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
