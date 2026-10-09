//! Configuration file: a minimal `key = value` format, parsed here rather than pulling in a
//! serialization library.
//!
//! The configuration file is trusted local input (only an administrator can write it; it holds
//! no secrets, hence mode 644), so the parser does not need to withstand hostile input.
//! Anything arriving from the network goes through the `dns` module's parser instead.
//! What breaks if you change it: that judgement rests on the file being written only by the
//! service and its owner — do not make this read from the network.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

/// How long a device may cache a blocked response.
///
/// It must stay in single-digit seconds. Set it higher and after the user allows a domain the
/// device keeps using the cached block, so the allow appears not to have worked. The limit is
/// enforced in [`Config::parse`].
const BLOCK_TTL_MAX: Duration = Duration::from_secs(9);

const DEFAULT_BLOCK_TTL: Duration = Duration::from_secs(2);
const DEFAULT_CACHE_CAPACITY: usize = 20_000;
const DEFAULT_STALE_MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);
const DEFAULT_JOURNAL_RETENTION_DAYS: u32 = 10;

/// The longest the journal may be kept: ten years. What breaks if you change it: the date
/// arithmetic that finds expired days cannot reach far beyond this, and a value it cannot
/// handle stops the journal writer for good.
const MAX_JOURNAL_RETENTION_DAYS: u32 = 3650;

/// Why the configuration file cannot be used.
///
/// What breaks if you change it: messages name the line and the setting, never what is written
/// there. They reach the service log, and `phylode diagnose` copies that log into reports
/// people post publicly — a host name or address in the file would go with it.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("line {line} is not in the form `key = value`")]
    MissingEquals { line: usize },
    #[error(
        "line {line} is not a setting Phylode knows; check its spelling against the comments \
         in the default configuration"
    )]
    UnknownKey { line: usize },
    #[error("line {line} has a value `{key}` cannot use")]
    BadValue { line: usize, key: String },
    #[error(
        "line {line} serves every address, which would let anyone on the internet use this \
         Mac, including to attack others; list only the networks your devices are on, such as \
         198.51.100.0/24"
    )]
    EveryAddress { line: usize },
    #[error(
        "block_ttl_secs is {}, above the limit of {} — devices would keep a blocked answer that \
         long, so allowing a domain would appear not to work",
        got.as_secs(),
        max.as_secs()
    )]
    BlockTtlTooLong { got: Duration, max: Duration },
    #[error(
        "no upstream server is set; add a line such as `upstream = tls 1.1.1.1 cloudflare-dns.com`"
    )]
    NoUpstream,
    #[error("no listen address is set; add a line such as `listen = 0.0.0.0:53`")]
    NoListen,
    #[error("the file could not be opened: {source}")]
    Io {
        #[source]
        source: std::io::Error,
    },
}

/// The encrypted protocol an upstream uses. There is never a plaintext option.
///
/// What breaks if you change it: adding a plaintext option opens a downgrade path, violating
/// RFC 8310 Strict Privacy. Any protocol added here must itself be encrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
}

/// How much the daily lists block: one of HaGeZi's tiers, each with the Threat Intelligence
/// Feeds on top. The list updater reads this setting and downloads the matching tier; the
/// service only reports it.
///
/// What breaks if you change it: the names must match what `deploy/update-blocklists.sh`
/// recognizes, or the updater falls back to `standard` while `status` says otherwise. There is
/// deliberately no tier above `strict`: HaGeZi warns that Ultimate stops apps working, and
/// keeping the network usable comes first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Protection {
    /// HaGeZi Multi NORMAL: for a network where nobody will unblock a site.
    Relaxed,
    /// HaGeZi Multi PRO, the tier HaGeZi recommends.
    #[default]
    Standard,
    /// HaGeZi Multi PRO++: blocks more, occasionally a site someone needs.
    Strict,
}

impl Protection {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "relaxed" => Some(Self::Relaxed),
            "standard" => Some(Self::Standard),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    /// The word written in the configuration file.
    pub fn name(self) -> &'static str {
        match self {
            Self::Relaxed => "relaxed",
            Self::Standard => "standard",
            Self::Strict => "strict",
        }
    }

    /// The lists this tier downloads, as their maintainer names them.
    pub fn lists(self) -> &'static str {
        match self {
            Self::Relaxed => "HaGeZi Multi NORMAL plus Threat Intelligence Feeds",
            Self::Standard => "HaGeZi Multi PRO plus Threat Intelligence Feeds",
            Self::Strict => "HaGeZi Multi PRO++ plus Threat Intelligence Feeds",
        }
    }
}

/// How much of each lookup the journal keeps, from `journal`. Each level keeps less than the
/// one before.
///
/// What breaks if you change it: what a level leaves out is never written, so switching back
/// cannot recover it; and the weekly summary must say "cannot tell" rather than "none" for
/// what it no longer sees.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JournalDetail {
    /// Device, domain and time of every lookup.
    #[default]
    All,
    /// Domain and time of every lookup, without the device.
    Domains,
    /// Only the day and the outcome of each lookup, so the summary can count them.
    Zero,
}

impl JournalDetail {
    /// Reads `All`, `Domains` or `Zero`, in any letter case: a lowercase word should not stop
    /// the service from starting.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "all" => Some(Self::All),
            "domains" => Some(Self::Domains),
            "zero" => Some(Self::Zero),
            _ => None,
        }
    }

    /// The word as the configuration file and `status` write it.
    pub fn name(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::Domains => "Domains",
            Self::Zero => "Zero",
        }
    }

    /// Whether this level writes something `other` leaves out.
    pub fn keeps_more_than(self, other: Self) -> bool {
        let rank = |level| match level {
            Self::Zero => 0,
            Self::Domains => 1,
            Self::All => 2,
        };
        rank(self) > rank(other)
    }
}

/// One upstream resolver. The address is always an IP; the hostname is only used to validate
/// the certificate.
///
/// What breaks if you change it: replacing `ip` with a hostname makes the service query itself
/// in order to resolve its own upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    protocol: UpstreamProtocol,
    ip: IpAddr,
    server_name: String,
}

impl Upstream {
    pub fn protocol(&self) -> UpstreamProtocol {
        self.protocol
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The name the TLS certificate must validate as.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Parses the three-field form `tls 1.1.1.1 cloudflare-dns.com`.
    fn parse(value: &str) -> Option<Self> {
        let mut fields = value.split_whitespace();
        let protocol = match fields.next()? {
            "tls" => UpstreamProtocol::Tls,
            "https" => UpstreamProtocol::Https,
            _ => return None,
        };
        let ip = fields.next()?.parse().ok()?;
        let server_name = fields.next()?.to_string();
        if server_name.is_empty() || fields.next().is_some() {
            return None;
        }
        Some(Self {
            protocol,
            ip,
            server_name,
        })
    }
}

/// A block of addresses written as `address/prefix length`, such as `192.0.2.0/24` or
/// `2001:db8::/32`. Bits past the prefix are ignored, so `192.0.2.7/24` is the same network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// `prefix` longer than the address family allows is `None`.
    pub fn new(address: IpAddr, prefix: u8) -> Option<Self> {
        let bits = if address.is_ipv4() { 32 } else { 128 };
        (prefix <= bits).then_some(Self { address, prefix })
    }

    /// Whether `ip` falls inside this network. An IPv4 address never matches an IPv6 network,
    /// or the other way round.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

impl std::str::FromStr for IpNetwork {
    type Err = ();

    fn from_str(text: &str) -> Result<Self, ()> {
        let (address, prefix) = text.split_once('/').ok_or(())?;
        let address = address.trim().parse().map_err(|_| ())?;
        let prefix = prefix.trim().parse().map_err(|_| ())?;
        Self::new(address, prefix).ok_or(())
    }
}

/// The service's full configuration. The fields are private, so holding a `Config` means it
/// passed validation.
#[derive(Clone, Debug)]
pub struct Config {
    listen: Vec<SocketAddr>,
    upstreams: Vec<Upstream>,
    blocklists: Vec<PathBuf>,
    allowlist: Option<PathBuf>,
    user_blocklist: Option<PathBuf>,
    block_ttl: Duration,
    journal_dir: PathBuf,
    journal_retention_days: u32,
    cache_capacity: usize,
    stale_max_age: Duration,
    internal_domains: Vec<String>,
    served_networks: Vec<IpNetwork>,
    protection: Protection,
    journal: JournalDetail,
}

impl Config {
    /// Which tier of lists the updater downloads; see [`Protection`].
    pub fn protection(&self) -> Protection {
        self.protection
    }

    /// How much of each lookup the journal keeps; see [`JournalDetail`].
    pub fn journal(&self) -> JournalDetail {
        self.journal
    }

    pub fn listen(&self) -> &[SocketAddr] {
        &self.listen
    }

    pub fn upstreams(&self) -> &[Upstream] {
        &self.upstreams
    }

    pub fn blocklists(&self) -> &[PathBuf] {
        &self.blocklists
    }

    pub fn allowlist(&self) -> Option<&Path> {
        self.allowlist.as_deref()
    }

    /// The list `phylode block` writes. It may not exist yet.
    pub fn user_blocklist(&self) -> Option<&Path> {
        self.user_blocklist.as_deref()
    }

    pub fn block_ttl(&self) -> Duration {
        self.block_ttl
    }

    pub fn journal_dir(&self) -> &Path {
        &self.journal_dir
    }

    pub fn journal_retention_days(&self) -> u32 {
        self.journal_retention_days
    }

    pub fn cache_capacity(&self) -> usize {
        self.cache_capacity
    }

    /// How long an expired cache entry may still be served while every upstream is down.
    pub fn stale_max_age(&self) -> Duration {
        self.stale_max_age
    }

    /// Domains permitted to resolve to local network addresses. **Empty by default** — any
    /// domain not listed here has its answer discarded whole if it resolves inward (DNS
    /// rebinding defence).
    ///
    /// What breaks if you change it: this list switches the rebinding defence off for those
    /// domains, so only put names that genuinely belong to your network in it.
    pub fn internal_domains(&self) -> &[String] {
        &self.internal_domains
    }

    /// Networks whose devices may use the service beyond the private ranges that are always
    /// served, from `serve_network` lines; see `policy::ServedNetworks`.
    pub fn served_networks(&self) -> &[IpNetwork] {
        &self.served_networks
    }

    /// Reads and validates the file at `path`. The error does not repeat the path; callers
    /// name the file when they report it.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io { source })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut listen = Vec::new();
        let mut upstreams = Vec::new();
        let mut blocklists = Vec::new();
        let mut allowlist = None;
        let mut user_blocklist = None;
        let mut block_ttl = DEFAULT_BLOCK_TTL;
        let mut journal_dir = PathBuf::from("/var/log/phylode");
        let mut journal_retention_days = DEFAULT_JOURNAL_RETENTION_DAYS;
        let mut cache_capacity = DEFAULT_CACHE_CAPACITY;
        let mut stale_max_age = DEFAULT_STALE_MAX_AGE;
        let mut internal_domains = Vec::new();
        let mut served_networks = Vec::new();
        let mut protection = Protection::default();
        let mut journal = JournalDetail::default();

        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let content = strip_comment(raw);
            if content.is_empty() {
                continue;
            }

            let (key, value) = content
                .split_once('=')
                .ok_or(ConfigError::MissingEquals { line })?;
            let key = key.trim();
            let value = unquote(value.trim());

            // Only called from the arms below, so `key` is always one of Phylode's settings.
            let bad = || ConfigError::BadValue {
                line,
                key: key.to_string(),
            };

            match key {
                "listen" => listen.push(value.parse().map_err(|_| bad())?),
                "upstream" => {
                    let upstream = Upstream::parse(value).ok_or_else(bad)?;
                    // A repeated line is not a second server: when it fails, every query waits
                    // for it twice before the next real one is tried.
                    if upstreams.contains(&upstream) {
                        return Err(bad());
                    }
                    upstreams.push(upstream);
                }
                "blocklist" => blocklists.push(PathBuf::from(value)),
                "allowlist" => allowlist = Some(PathBuf::from(value)),
                "user_blocklist" => user_blocklist = Some(PathBuf::from(value)),
                "block_ttl_secs" => {
                    block_ttl = Duration::from_secs(value.parse().map_err(|_| bad())?);
                }
                "journal_dir" => journal_dir = PathBuf::from(value),
                "journal_retention_days" => {
                    journal_retention_days = value
                        .parse()
                        .ok()
                        .filter(|days| *days <= MAX_JOURNAL_RETENTION_DAYS)
                        .ok_or_else(bad)?;
                }
                "cache_capacity" => cache_capacity = value.parse().map_err(|_| bad())?,
                "stale_max_age_secs" => {
                    stale_max_age = Duration::from_secs(value.parse().map_err(|_| bad())?);
                }
                "internal_domain" => {
                    if value.is_empty() {
                        return Err(bad());
                    }
                    internal_domains.push(value.to_string());
                }
                "serve_network" => {
                    let network: IpNetwork = value.parse().map_err(|()| bad())?;
                    // A /0 answers the whole internet: an open resolver, usable for reflection.
                    if network.prefix == 0 {
                        return Err(ConfigError::EveryAddress { line });
                    }
                    served_networks.push(network);
                }
                "protection" => protection = Protection::parse(value).ok_or_else(bad)?,
                "journal" => journal = JournalDetail::parse(value).ok_or_else(bad)?,
                _ => {
                    return Err(ConfigError::UnknownKey { line });
                }
            }
        }

        if block_ttl > BLOCK_TTL_MAX {
            return Err(ConfigError::BlockTtlTooLong {
                got: block_ttl,
                max: BLOCK_TTL_MAX,
            });
        }
        if listen.is_empty() {
            return Err(ConfigError::NoListen);
        }
        if upstreams.is_empty() {
            return Err(ConfigError::NoUpstream);
        }

        Ok(Self {
            listen,
            upstreams,
            blocklists,
            allowlist,
            user_blocklist,
            block_ttl,
            journal_dir,
            journal_retention_days,
            cache_capacity,
            stale_max_age,
            internal_domains,
            served_networks,
            protection,
            journal,
        })
    }
}

fn strip_comment(raw: &str) -> &str {
    raw.split('#').next().unwrap_or("").trim()
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        listen = 127.0.0.1:5353
        upstream = "tls 1.1.1.1 cloudflare-dns.com"
    "#;

    #[test]
    fn a_minimal_configuration_fills_in_the_defaults() {
        let config = Config::parse(MINIMAL).expect("a minimal configuration should parse");
        assert_eq!(config.listen(), ["127.0.0.1:5353".parse().unwrap()]);
        assert_eq!(config.block_ttl(), DEFAULT_BLOCK_TTL);
        assert_eq!(config.stale_max_age(), DEFAULT_STALE_MAX_AGE);
        assert_eq!(config.journal_retention_days(), 10);
    }

    /// Should change: a retention past ten years, and an upstream listed twice, are refused.
    /// Should not change: ten years exactly, and two different upstreams, are accepted.
    #[test]
    fn retention_is_bounded_and_upstreams_are_not_repeated() {
        let with = |extra: &str| Config::parse(&format!("{MINIMAL}\n{extra}"));
        assert_eq!(
            with("journal_retention_days = 3650")
                .unwrap()
                .journal_retention_days(),
            3650
        );
        for days in ["3651", "4294967295"] {
            assert!(matches!(
                with(&format!("journal_retention_days = {days}")),
                Err(ConfigError::BadValue { .. })
            ));
        }
        assert!(matches!(
            with(r#"upstream = "tls 1.1.1.1 cloudflare-dns.com""#),
            Err(ConfigError::BadValue { line: 5, .. })
        ));
        assert_eq!(
            with(r#"upstream = "https 9.9.9.9 dns.quad9.net""#)
                .unwrap()
                .upstreams()
                .len(),
            2
        );
    }

    /// Should change: each level is read from `journal`, written capitalized or not.
    /// Should not change: without the line the journal keeps everything, and any other word
    /// is refused rather than guessed.
    #[test]
    fn journal_is_one_of_three_levels() {
        assert_eq!(
            Config::parse(MINIMAL).unwrap().journal(),
            JournalDetail::All
        );
        for (word, level) in [
            ("All", JournalDetail::All),
            ("Domains", JournalDetail::Domains),
            ("Zero", JournalDetail::Zero),
        ] {
            for written in [word.to_string(), word.to_ascii_lowercase()] {
                let text = format!("{MINIMAL}\njournal = {written}");
                assert_eq!(Config::parse(&text).unwrap().journal(), level);
            }
            assert_eq!(level.name(), word);
        }
        for word in ["full", "none", ""] {
            let text = format!("{MINIMAL}\njournal = {word}");
            assert!(
                matches!(Config::parse(&text), Err(ConfigError::BadValue { .. })),
                "{word:?}"
            );
        }
    }

    /// Should change: each of the three tiers is read from `protection`.
    /// Should not change: without the line it is `standard`, today's lists, and any other word
    /// is refused rather than quietly read as a tier.
    #[test]
    fn protection_is_one_of_three_tiers() {
        assert_eq!(
            Config::parse(MINIMAL).unwrap().protection(),
            Protection::Standard
        );
        for (word, tier) in [
            ("relaxed", Protection::Relaxed),
            ("standard", Protection::Standard),
            ("strict", Protection::Strict),
        ] {
            let text = format!("{MINIMAL}\nprotection = {word}");
            assert_eq!(Config::parse(&text).unwrap().protection(), tier);
            assert_eq!(tier.name(), word);
        }
        for word in ["ultimate", "Strict", ""] {
            let text = format!("{MINIMAL}\nprotection = {word}");
            assert!(
                matches!(Config::parse(&text), Err(ConfigError::BadValue { .. })),
                "{word:?}"
            );
        }
    }

    #[test]
    fn an_upstream_splits_into_protocol_address_and_certificate_name() {
        let config = Config::parse(MINIMAL).unwrap();
        let up = &config.upstreams()[0];
        assert_eq!(up.protocol(), UpstreamProtocol::Tls);
        assert_eq!(up.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(up.server_name(), "cloudflare-dns.com");
    }

    #[test]
    fn a_hostname_as_an_upstream_is_rejected() {
        // A hostname would make the service query itself to resolve its own upstream, so only
        // IP addresses are accepted.
        let text = "listen = 127.0.0.1:5353\nupstream = tls cloudflare-dns.com cloudflare-dns.com";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::BadValue { .. })
        ));
    }

    #[test]
    fn there_is_no_plaintext_upstream_option() {
        let text = "listen = 127.0.0.1:5353\nupstream = udp 1.1.1.1 cloudflare-dns.com";
        assert!(matches!(
            Config::parse(text),
            Err(ConfigError::BadValue { .. })
        ));
    }

    #[test]
    fn too_large_a_blocked_response_ttl_refuses_to_start() {
        let text = format!("{MINIMAL}\nblock_ttl_secs = 3600");
        assert!(matches!(
            Config::parse(&text),
            Err(ConfigError::BlockTtlTooLong { .. })
        ));
    }

    #[test]
    fn no_upstream_means_no_start() {
        assert!(matches!(
            Config::parse("listen = 127.0.0.1:5353"),
            Err(ConfigError::NoUpstream)
        ));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let text = "# comment\n\n listen = 127.0.0.1:5353 # trailing comment\nupstream = tls 9.9.9.9 dns.quad9.net\n";
        let config = Config::parse(text).expect("it should parse");
        assert_eq!(config.upstreams().len(), 1);
    }

    #[test]
    fn an_unrecognized_key_is_an_error_rather_than_silently_ignored() {
        let text = format!("{MINIMAL}\nblock_evrything = yes");
        assert!(matches!(
            Config::parse(&text),
            Err(ConfigError::UnknownKey { .. })
        ));
    }

    /// Should change: a serve_network covering every address is refused, so the Mac cannot be
    /// configured into a resolver anyone on the internet can use.
    /// Should not change: an ordinary public network, IPv4 or IPv6, is still accepted.
    #[test]
    fn serving_every_address_is_refused() {
        for everything in ["0.0.0.0/0", "::/0"] {
            let text = format!("{MINIMAL}\nserve_network = {everything}");
            let error = Config::parse(&text).expect_err("this would be an open resolver");
            assert!(
                matches!(error, ConfigError::EveryAddress { line: 5 }),
                "{error:?}"
            );
            assert!(error.to_string().contains("anyone"), "{error}");
        }
        for network in ["198.51.100.0/24", "2001:db8:1:2::/64"] {
            let text = format!("{MINIMAL}\nserve_network = {network}");
            assert_eq!(Config::parse(&text).unwrap().served_networks().len(), 1);
        }
    }

    /// Should change: an error names the line and, for a bad value, the setting — never the
    /// text written there. The service log carries these messages, and the diagnostics report
    /// copies the service log into public issues.
    #[test]
    fn errors_never_repeat_what_the_file_says() {
        for (extra, written) in [
            ("printer.home.example", "printer.home.example"),
            ("nas.home.example = 1", "nas.home.example"),
            ("serve_network = 192.0.2.7/99", "192.0.2.7"),
        ] {
            let message = Config::parse(&format!("{MINIMAL}\n{extra}"))
                .expect_err("each of these lines is wrong")
                .to_string();
            assert!(message.contains("line "), "{message}");
            assert!(!message.contains(written), "{message}");
        }
    }

    #[test]
    fn several_upstreams_and_several_lists_can_be_configured() {
        let text = "listen = 127.0.0.1:5353\nlisten = [::1]:5353\n\
                    upstream = tls 1.1.1.1 cloudflare-dns.com\n\
                    upstream = https 9.9.9.9 dns.quad9.net\n\
                    blocklist = /a.txt\nblocklist = /b.txt\n";
        let config = Config::parse(text).unwrap();
        assert_eq!(config.listen().len(), 2);
        assert_eq!(config.upstreams().len(), 2);
        assert_eq!(config.blocklists().len(), 2);
    }
}
