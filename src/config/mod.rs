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
pub const BLOCK_TTL_MAX: Duration = Duration::from_secs(9);

const DEFAULT_BLOCK_TTL: Duration = Duration::from_secs(2);
const DEFAULT_CACHE_CAPACITY: usize = 20_000;
const DEFAULT_STALE_MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);
const DEFAULT_JOURNAL_RETENTION_DAYS: u32 = 10;
/// The local offset from UTC, which decides where journal files split by date and when the
/// nightly cleanup runs. What breaks if you change it: this is a fixed offset with no
/// daylight saving handling.
const DEFAULT_UTC_OFFSET_HOURS: i32 = 8;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("line {line} has no equals sign: {text}")]
    MissingEquals { line: usize, text: String },
    #[error("line {line} has an unrecognized key `{key}`")]
    UnknownKey { line: usize, key: String },
    #[error("line {line} has an invalid value for `{key}`: {value}")]
    BadValue {
        line: usize,
        key: String,
        value: String,
    },
    #[error(
        "blocked-response TTL is {got:?}, above the {max:?} limit — a larger value makes allowing a domain appear not to work"
    )]
    BlockTtlTooLong { got: Duration, max: Duration },
    #[error("at least one upstream resolver must be configured")]
    NoUpstream,
    #[error("at least one listen address must be configured")]
    NoListen,
    #[error("could not read configuration file {path}: {source}")]
    Io {
        path: PathBuf,
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
    utc_offset_hours: i32,
    internal_domains: Vec<String>,
}

impl Config {
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

    /// The local offset from UTC, in hours.
    pub fn utc_offset_hours(&self) -> i32 {
        self.utc_offset_hours
    }

    /// Domains permitted to resolve to home network addresses. **Empty by default** — any
    /// domain not listed here has its answer discarded whole if it resolves inward (DNS
    /// rebinding defence).
    ///
    /// What breaks if you change it: this list switches the rebinding defence off for those
    /// domains, so only put names that genuinely belong to your network in it.
    pub fn internal_domains(&self) -> &[String] {
        &self.internal_domains
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
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
        let mut utc_offset_hours = DEFAULT_UTC_OFFSET_HOURS;
        let mut internal_domains = Vec::new();

        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let content = strip_comment(raw);
            if content.is_empty() {
                continue;
            }

            let (key, value) =
                content
                    .split_once('=')
                    .ok_or_else(|| ConfigError::MissingEquals {
                        line,
                        text: content.to_string(),
                    })?;
            let key = key.trim();
            let value = unquote(value.trim());

            let bad = || ConfigError::BadValue {
                line,
                key: key.to_string(),
                value: value.to_string(),
            };

            match key {
                "listen" => listen.push(value.parse().map_err(|_| bad())?),
                "upstream" => upstreams.push(Upstream::parse(value).ok_or_else(bad)?),
                "blocklist" => blocklists.push(PathBuf::from(value)),
                "allowlist" => allowlist = Some(PathBuf::from(value)),
                "user_blocklist" => user_blocklist = Some(PathBuf::from(value)),
                "block_ttl_secs" => {
                    block_ttl = Duration::from_secs(value.parse().map_err(|_| bad())?);
                }
                "journal_dir" => journal_dir = PathBuf::from(value),
                "journal_retention_days" => {
                    journal_retention_days = value.parse().map_err(|_| bad())?;
                }
                "cache_capacity" => cache_capacity = value.parse().map_err(|_| bad())?,
                "stale_max_age_secs" => {
                    stale_max_age = Duration::from_secs(value.parse().map_err(|_| bad())?);
                }
                "utc_offset_hours" => utc_offset_hours = value.parse().map_err(|_| bad())?,
                "internal_domain" => {
                    if value.is_empty() {
                        return Err(bad());
                    }
                    internal_domains.push(value.to_string());
                }
                _ => {
                    return Err(ConfigError::UnknownKey {
                        line,
                        key: key.to_string(),
                    });
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
            utc_offset_hours,
            internal_domains,
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
