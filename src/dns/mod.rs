//! Protocol layer: **the only place in the project that touches an external DNS library**.
//!
//! Every other module sees only the [`Name`], [`Query`] and [`Response`] defined here, never
//! the underlying types.
//! What breaks if you change it: letting an external library's types leak outside this module
//! forfeits the ability to swap the protocol layer out later — the incremental replacement
//! approach Cloudflare used.

mod exchange;
mod launchd;
mod probe;
mod server;

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use hickory_proto::rr::{RData, Record, RecordType as WireRecordType};

pub use exchange::{Checked, Exchange, ExchangeError, Signature};
pub use launchd::LaunchdError;
pub use probe::{ProbeError, self_probe};
pub use server::{LAUNCHD_TCP_SOCKET, LAUNCHD_UDP_SOCKET, Listener, serve};

/// Fuzz entry point, only compiled under `cargo fuzz`. See `server::fuzz`.
#[cfg(fuzzing)]
pub use server::fuzz::request as fuzz_request;

/// Fuzz entry point: treats arbitrary bytes as a packet from upstream and extracts the answer
/// section, returning `None` if it does not parse. Only compiled under `cargo fuzz`; what
/// happens next goes through the public interface in `fuzz/fuzz_targets/upstream.rs`.
#[cfg(fuzzing)]
pub fn fuzz_upstream_records(data: &[u8]) -> Option<Records> {
    let message = hickory_proto::op::Message::from_vec(data).ok()?;
    Some(Records::from_wire(message.answers.to_vec()))
}

/// A DNS domain name. Always lowercase with no trailing dot, so comparison is
/// case-insensitive.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Name(String);

impl Name {
    /// The name as a string: lowercase, no trailing dot. The policy layer matches on this.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Builds from text already in ASCII form, normalizing to lowercase with no trailing dot.
    /// Unicode is kept as it is; text a person typed goes through [`Name::from_typed`].
    pub fn parse(text: &str) -> Self {
        Self(text.trim_end_matches('.').to_ascii_lowercase())
    }

    /// Builds from a name a person typed, converting an internationalized domain to the
    /// `xn--` form queries arrive in. Returns `None` for text that is not a domain.
    ///
    /// What breaks if you change it: skip the conversion and `phylode allow bücher.de` is
    /// stored in Unicode, which no query ever matches — the allow silently does nothing.
    pub fn from_typed(text: &str) -> Option<Self> {
        let wire = hickory_proto::rr::Name::from_utf8(text.trim()).ok()?;
        Self::from_wire(&wire)
    }

    /// Builds from a wire-format name. Returns `None` for anything that does not convert back
    /// to a valid domain — for instance a non-ASCII name sent as raw UTF-8 bytes (Apple devices
    /// convert to `xn--` punycode first, so this is not normally reached).
    ///
    /// What breaks if you change it: let such a name through and it travels to the upstream
    /// layer escaped as a `\344…` string, fails to convert to a domain before sending, and is
    /// counted as that upstream failing — two malformed packets would demote a healthy server.
    fn from_wire(name: &hickory_proto::rr::Name) -> Option<Self> {
        let text = name.to_ascii();
        hickory_proto::rr::Name::from_utf8(&text).ok()?;
        Some(Self::parse(&text))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A query's record type. Only those needing distinct handling are named; the rest fall under
/// [`RecordType::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    Aaaa,
    Https,
    Other(u16),
}

impl RecordType {
    fn from_wire(value: WireRecordType) -> Self {
        match value {
            WireRecordType::A => Self::A,
            WireRecordType::AAAA => Self::Aaaa,
            WireRecordType::HTTPS => Self::Https,
            other => Self::Other(u16::from(other)),
        }
    }
}

/// A query already decoded from wire format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Query {
    name: Name,
    record_type: RecordType,
}

impl Query {
    pub fn new(name: Name, record_type: RecordType) -> Self {
        Self { name, record_type }
    }

    /// The query used to check an upstream is alive: the root NS, which every working resolver
    /// answers at once from its cache. It carries no domain anyone looked up, so sending it to any upstream
    /// leaks nothing about what the network is looking up (product principle 3).
    pub fn liveness() -> Self {
        Self {
            name: Name(String::new()),
            record_type: RecordType::Other(u16::from(WireRecordType::NS)),
        }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }
}

/// A record set from upstream or the cache. The contents are not exposed; it is passed around
/// whole.
#[derive(Clone, Debug, Default)]
pub struct Records(Vec<Record>);

impl Records {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The smallest TTL in this set, which decides how long it is cached. `None` when empty.
    pub fn min_ttl(&self) -> Option<Duration> {
        self.0
            .iter()
            .map(|record| Duration::from_secs(u64::from(record.ttl)))
            .min()
    }

    /// Returns a copy with `elapsed` subtracted from each TTL, floored at one second.
    ///
    /// Used when serving from cache. What breaks if you change it: returning the TTL as stored
    /// makes the device start counting from the moment it receives the answer, keeping it for
    /// longer than the authoritative server allowed.
    pub fn aged(&self, elapsed: Duration) -> Self {
        let seconds = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
        Self(
            self.0
                .iter()
                .map(|record| {
                    let mut aged = record.clone();
                    aged.ttl = aged.ttl.saturating_sub(seconds).max(1);
                    aged
                })
                .collect(),
        )
    }

    /// Every address in this set a device might connect to: A/AAAA, plus the `ipv4hint` and
    /// `ipv6hint` of HTTPS/SVCB records (RFC 9460 §7.3 — Safari queries the HTTPS type first
    /// and connects straight to the hinted address). The rebinding defence uses this to see
    /// where an answer points.
    ///
    /// What breaks if you change it: miss one address-bearing record type and that type slips
    /// past the rebinding defence entirely.
    pub fn addresses(&self) -> Vec<IpAddr> {
        use hickory_proto::rr::rdata::svcb::{SVCB, SvcParamValue};

        let hints = |svcb: &SVCB| -> Vec<IpAddr> {
            svcb.svc_params
                .iter()
                .flat_map(|(_, value)| match value {
                    SvcParamValue::Ipv4Hint(hint) => {
                        hint.0.iter().map(|a| IpAddr::V4(a.0)).collect()
                    }
                    SvcParamValue::Ipv6Hint(hint) => {
                        hint.0.iter().map(|a| IpAddr::V6(a.0)).collect()
                    }
                    _ => Vec::new(),
                })
                .collect()
        };
        self.0
            .iter()
            .flat_map(|record| match &record.data {
                RData::A(a) => vec![IpAddr::V4(a.0)],
                RData::AAAA(aaaa) => vec![IpAddr::V6(aaaa.0)],
                RData::HTTPS(https) => hints(&https.0),
                RData::SVCB(svcb) => hints(svcb),
                _ => Vec::new(),
            })
            .collect()
    }

    /// The names this set's CNAMEs point to, normalized exactly as query names are
    /// ([`Name::from_wire`]: `xn--` punycode, lowercase, no trailing dot).
    /// The gatekeeper matches these against the blocklist to catch CNAME cloaking: a
    /// first-party-looking subdomain that actually resolves to a tracker.
    ///
    /// What breaks if you change it: the library's `to_string` decodes punycode to Unicode,
    /// which no blocklist entry is written in, so an internationalized tracker behind an alias
    /// would pass.
    pub fn cname_targets(&self) -> Vec<String> {
        self.0
            .iter()
            .filter_map(|record| match &record.data {
                RData::CNAME(target) => Name::from_wire(&target.0).map(|name| name.0),
                _ => None,
            })
            .collect()
    }

    /// Test only: builds A/AAAA records from a set of addresses.
    ///
    /// Only compiled for tests. The layers above need to test "given this upstream answer, this
    /// is what happens", while the real construction path [`Records::from_wire`] is reachable
    /// only from within this module.
    #[cfg(test)]
    pub fn from_addresses(name: &Name, ttl: Duration, addresses: &[IpAddr]) -> Self {
        use hickory_proto::rr::rdata::{A, AAAA};

        let wire: hickory_proto::rr::Name =
            format!("{name}.").parse().expect("test names should parse");
        let seconds = u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX);
        Self(
            addresses
                .iter()
                .map(|address| {
                    let data = match address {
                        IpAddr::V4(v4) => RData::A(A(*v4)),
                        IpAddr::V6(v6) => RData::AAAA(AAAA(*v6)),
                    };
                    Record::from_rdata(wire.clone(), seconds, data)
                })
                .collect(),
        )
    }

    /// Test only: `name` is an alias for `target`, and `target` resolves to `address` — the
    /// shape of CNAME cloaking.
    #[cfg(test)]
    pub fn with_cname(name: &Name, ttl: Duration, target: &str, address: IpAddr) -> Self {
        use hickory_proto::rr::rdata::CNAME;

        let wire: hickory_proto::rr::Name =
            format!("{name}.").parse().expect("test names should parse");
        let target_wire: hickory_proto::rr::Name = format!("{target}.")
            .parse()
            .expect("test names should parse");
        let seconds = u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX);
        let mut records = vec![Record::from_rdata(
            wire,
            seconds,
            RData::CNAME(CNAME(target_wire.clone())),
        )];
        records.extend(Self::from_addresses(&Name::parse(target), ttl, &[address]).0);
        Self(records)
    }

    fn from_wire(records: Vec<Record>) -> Self {
        Self(records)
    }

    fn as_wire(&self) -> &[Record] {
        &self.0
    }
}

/// What came back from upstream.
///
/// ⚠️ **"This name does not exist" is an answer, not a failure.**
/// What breaks if you change it: merge negative answers with "unreachable" into one `Err` and
/// every typo on the network returns "the server is broken", while the healthy upstream that
/// answered correctly gets a failure recorded — two of those and it is demoted.
#[derive(Clone, Debug)]
pub enum Answer {
    /// Records were returned.
    Records(Records),
    /// The upstream says this name does not exist (NXDOMAIN).
    NameNotFound { ttl: Duration },
    /// The upstream says the name exists but has no records of this type (RFC 2308 NODATA).
    /// An IPv4-only domain asked for AAAA lands here, which is very common.
    NoRecordsOfType { ttl: Duration },
    /// The upstream answered, and answered SERVFAIL (including on the CD retry). **This
    /// upstream is not broken** — usually that domain's own name servers are, and the next
    /// upstream would say the same.
    ServerFailure,
}

/// What to return for a query.
///
/// ⚠️ **There is deliberately no "refused" variant.** Returning `REFUSED` makes devices retry
/// immediately, causing a storm, and pushes them to the next resolver on their list —
/// filtering stops applying on the spot. Adding this variant back dismantles the filtering.
#[derive(Clone, Debug)]
pub enum Response {
    /// An ordinary answer.
    Answer(Records),
    /// Blocked by a list: returns an address that can never connect (`0.0.0.0` or `::`), and
    /// "no records of this type" for other types. `ttl` decides how long the device remembers
    /// it.
    ///
    /// This matches Cloudflare: 1.1.1.1 for Families and Cloudflare Gateway return `0.0.0.0`
    /// by default.
    Blocked { ttl: Duration },
    /// The name does not exist; `ttl` decides how long the device remembers that.
    NotFound { ttl: Duration },
    /// The name exists but has no records of this type. Returns NOERROR with an SOA and no
    /// answer records.
    NoRecords { ttl: Duration },
    /// A server-side failure (every upstream down and nothing in the cache).
    Failure,
    /// Return nothing at all. Used for a source outside the served networks and for a device
    /// querying too often — any answer would be continuing to serve it, and a REFUSED would
    /// send it to an unfiltered resolver.
    Ignored,
}

/// Decides what to return for a received query. The server knows only this interface.
///
/// `client` is the device that asked. The journal records it as a device identifier, but
/// **it is not part of the cache key** — the answer for one domain is the same for every
/// device.
pub trait Responder: Send + Sync + 'static {
    fn respond(&self, query: &Query, client: IpAddr) -> impl Future<Output = Response> + Send;

    /// Whether `client` is served at all, counting this against the same limits as `respond`.
    /// Asked once per TCP connection before it takes a slot, and for each request the server
    /// answers by itself (an unsupported opcode or class, an ANY query, a malformed name).
    /// What breaks if you change it: returning true unconditionally lets any source on the
    /// internet get error replies — usable for reflection — and fill every TCP slot.
    fn admits(&self, client: IpAddr) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercased_and_lose_the_trailing_dot() {
        let wire: hickory_proto::rr::Name = "ADS.Example.COM.".parse().unwrap();
        assert_eq!(
            Name::from_wire(&wire)
                .expect("an ordinary domain must be accepted")
                .as_str(),
            "ads.example.com"
        );
    }

    /// Should change: a name sent as raw UTF-8 bytes is rejected at the boundary.
    /// Should not change: the same domain in `xn--` punycode is accepted.
    #[test]
    fn a_name_that_does_not_convert_back_is_rejected_at_the_boundary() {
        let raw = hickory_proto::rr::Name::from_labels(vec!["δοκιμή".as_bytes(), b"com"]).unwrap();
        assert_eq!(Name::from_wire(&raw), None);

        let encoded: hickory_proto::rr::Name = "xn--fiq228c.com.".parse().unwrap();
        assert_eq!(
            Name::from_wire(&encoded).map(|name| name.as_str().to_string()),
            Some("xn--fiq228c.com".to_string())
        );
    }

    #[test]
    fn only_record_types_needing_distinct_handling_are_named() {
        assert_eq!(RecordType::from_wire(WireRecordType::A), RecordType::A);
        assert_eq!(
            RecordType::from_wire(WireRecordType::AAAA),
            RecordType::Aaaa
        );
        assert!(matches!(
            RecordType::from_wire(WireRecordType::MX),
            RecordType::Other(_)
        ));
    }

    #[test]
    fn an_empty_record_set_has_no_minimum_ttl() {
        assert_eq!(Records::default().min_ttl(), None);
        assert!(Records::default().is_empty());
    }

    /// Should change: the address hints in an HTTPS record count towards where an answer
    /// points. Should not change: ordinary A records are unaffected.
    #[test]
    fn address_hints_in_https_records_count_as_addresses() {
        use hickory_proto::rr::rdata::svcb::{IpHint, SVCB, SvcParamKey, SvcParamValue};
        use hickory_proto::rr::rdata::{A, HTTPS};

        let wire: hickory_proto::rr::Name = "evil.example.com.".parse().unwrap();
        let https = SVCB::new(
            1,
            wire.clone(),
            vec![(
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(192, 168, 0, 1)])),
            )],
        );
        let records = Records::from_wire(vec![
            Record::from_rdata(wire.clone(), 300, RData::HTTPS(HTTPS(https))),
            Record::from_rdata(wire, 300, RData::A(A::new(93, 184, 216, 34))),
        ]);
        let addresses = records.addresses();
        assert!(addresses.contains(&"192.168.0.1".parse().unwrap()));
        assert!(addresses.contains(&"93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn alias_targets_are_extracted() {
        let records = Records::with_cname(
            &Name::parse("metrics.example.com"),
            Duration::from_secs(60),
            "Tracker.Evil.NET",
            "1.2.3.4".parse().unwrap(),
        );
        assert_eq!(
            records.cname_targets(),
            vec!["tracker.evil.net".to_string()]
        );
    }

    /// Should change: an internationalized alias target stays in `xn--` punycode, the form
    /// blocklists and query names use, so a list entry for it matches.
    /// Should not change: the conversion is the same one query names go through.
    #[test]
    fn internationalized_alias_targets_stay_in_punycode() {
        let records = Records::with_cname(
            &Name::parse("metrics.example.com"),
            Duration::from_secs(60),
            "XN--FIQ228C.com",
            "1.2.3.4".parse().unwrap(),
        );
        assert_eq!(records.cname_targets(), vec!["xn--fiq228c.com".to_string()]);
    }
}
