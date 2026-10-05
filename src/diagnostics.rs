//! `phylode diagnostics`: a report written to be pasted into a public bug report.
//!
//! It carries versions, states and counts — never a domain someone looked up, a network
//! address other than loopback, a configured name, or a path under a home folder. The
//! journal holds the browsing history of everyone on the network and `phylode status`
//! prints the full configuration; neither belongs in a public issue, so this is what the bug
//! report form asks for instead.
//!
//! What breaks if you change it: anything added here is published by whoever pastes it.
//! A new line must be a count, a state or a version, or go through `redact`.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use crate::config::{Config, ConfigError, UpstreamProtocol};
use crate::journal::EventKind;

/// How many of the most recent service events are listed, by time and kind only.
const RECENT_EVENTS: usize = 15;
/// How many lines of the service log are included, after redaction.
const LOG_LINES: usize = 20;

/// Everything read from this Mac. Gathering is the caller's job so that rendering, and the
/// redaction in it, can be tested without a real installation.
pub struct Facts<'a> {
    pub version: &'a str,
    pub macos: &'a str,
    pub arch: &'a str,
    /// The configuration, or why it could not be read. The list and event lines are only
    /// printed when it could.
    pub config: Result<&'a Config, &'a ConfigError>,
    /// Whether the service answered a health-check query just now.
    pub answering: bool,
    /// Domains loaded from the blocklists, or `None` if they could not be loaded.
    pub blocklist_domains: Option<usize>,
    /// Age in whole days of each blocklist file, `None` for a missing file.
    pub blocklist_ages: Vec<Option<u64>>,
    pub allowlist_entries: Option<usize>,
    pub user_blocklist_entries: Option<usize>,
    /// Service events from the last week, oldest first: (local time, kind code).
    pub events: Vec<(String, String)>,
    /// The end of the service log, or why it could not be read.
    pub log: Result<String, String>,
}

pub fn render(facts: &Facts) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Phylode {}", facts.version);
    let _ = writeln!(out, "macOS {} ({})", facts.macos, facts.arch);
    let _ = writeln!(
        out,
        "Service answering: {}",
        if facts.answering { "yes" } else { "no" }
    );

    match &facts.config {
        Ok(config) => {
            render_config(&mut out, config);
            render_lists(&mut out, facts);
            render_events(&mut out, &facts.events);
        }
        Err(error) => {
            // `ConfigError` never repeats what the file says, so it can be printed as it is.
            let _ = writeln!(out, "Configuration: could not be read: {error}");
        }
    }

    let _ = writeln!(
        out,
        "\nService log, last {LOG_LINES} lines (addresses and home folders removed):"
    );
    match &facts.log {
        Ok(text) => {
            let lines: Vec<&str> = text.lines().collect();
            for line in &lines[lines.len().saturating_sub(LOG_LINES)..] {
                let _ = writeln!(out, "  {}", redact(line));
            }
        }
        Err(reason) => {
            let _ = writeln!(out, "  (not included: {reason})");
        }
    }
    out
}

fn render_config(out: &mut String, config: &Config) {
    let listen: Vec<String> = config
        .listen()
        .iter()
        .map(|addr| redact(&addr.to_string()))
        .collect();
    let _ = writeln!(out, "Listening on: {}", listen.join(", "));
    let protocols: Vec<&str> = config
        .upstreams()
        .iter()
        .map(|upstream| match upstream.protocol() {
            UpstreamProtocol::Tls => "DNS over TLS",
            UpstreamProtocol::Https => "DNS over HTTPS",
        })
        .collect();
    let _ = writeln!(
        out,
        "Upstreams: {} ({})",
        protocols.len(),
        protocols.join(", ")
    );
    let _ = writeln!(
        out,
        "Blocked answer TTL: {}s; cache limit {}; journal kept {} days",
        config.block_ttl().as_secs(),
        config.cache_capacity(),
        config.journal_retention_days()
    );
    let _ = writeln!(
        out,
        "Internal domains exempt from rebinding defense: {}",
        config.internal_domains().len()
    );
}

fn render_lists(out: &mut String, facts: &Facts) {
    match facts.blocklist_domains {
        Some(count) => {
            let _ = writeln!(out, "Blocklist: {count} domains loaded");
        }
        None => out.push_str("Blocklist: could not be loaded\n"),
    }
    for (index, age) in facts.blocklist_ages.iter().enumerate() {
        let age = match age {
            Some(days) => format!("updated {days} day(s) ago"),
            None => "missing".to_string(),
        };
        let _ = writeln!(out, "  list {}: {age}", index + 1);
    }
    let _ = writeln!(
        out,
        "Allowlist entries: {}",
        count_or_unreadable(facts.allowlist_entries)
    );
    let _ = writeln!(
        out,
        "Own blocklist entries: {}",
        count_or_unreadable(facts.user_blocklist_entries)
    );
}

fn render_events(out: &mut String, events: &[(String, String)]) {
    let _ = writeln!(out, "\nService events, last 7 days:");
    if events.is_empty() {
        out.push_str("  none recorded\n");
        return;
    }
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for (_, kind) in events {
        match counts.iter_mut().find(|(seen, _)| seen == kind) {
            Some((_, count)) => *count += 1,
            None => counts.push((kind, 1)),
        }
    }
    for (kind, count) in counts {
        let _ = writeln!(out, "  {kind}: {count}");
    }
    let _ = writeln!(out, "Most recent {RECENT_EVENTS}:");
    for (time, kind) in &events[events.len().saturating_sub(RECENT_EVENTS)..] {
        let label = match EventKind::from_wire(kind) {
            Some(known) => known.label(),
            None => kind.as_str(),
        };
        let _ = writeln!(out, "  {time} {label}");
    }
}

fn count_or_unreadable(count: Option<usize>) -> String {
    count.map_or_else(|| "could not be read".to_string(), |n| n.to_string())
}

/// Replaces every IP address other than loopback and unspecified with `<address>`, and
/// every `/Users/<name>` with `~`.
///
/// What breaks if you change it: the service log prints the addresses it binds and probes,
/// and error messages carry file paths; both identify a network or an account.
fn redact(line: &str) -> String {
    let line = strip_home_folders(line);
    let mut out = String::with_capacity(line.len());
    let mut token = String::new();
    for c in line.chars() {
        if c.is_ascii_hexdigit() || c == '.' || c == ':' {
            token.push(c);
        } else {
            out.push_str(&redact_token(&token));
            token.clear();
            out.push(c);
        }
    }
    out.push_str(&redact_token(&token));
    out
}

/// One run of hex digits, dots and colons: an address, an address with a port, or
/// something else that is left alone. Punctuation the run picked up from the sentence around
/// it (`from:192.0.2.5`, `…192.0.2.5.`) is set aside first.
///
/// What breaks if you change it: try the whole run before trimming, or `::ffff:192.0.2.5`
/// loses its leading colons and no longer reads as an address.
fn redact_token(token: &str) -> String {
    let end = token.trim_end_matches(['.', ':']).len();
    let start = token[..end].find(|c| c != '.' && c != ':').unwrap_or(end);
    for (from, to) in [(0, token.len()), (0, end), (start, end)] {
        if let Some(replaced) = redact_address(&token[from..to]) {
            return format!("{}{replaced}{}", &token[..from], &token[to..]);
        }
    }
    token.to_string()
}

/// The replacement for `token` when it is exactly an address worth hiding (with or without an
/// IPv4 port), or `None`.
fn redact_address(token: &str) -> Option<String> {
    let (address, port) = match token.parse::<IpAddr>() {
        Ok(ip) => (Some(ip), ""),
        Err(_) => match token.rsplit_once(':') {
            Some((host, port)) if port.parse::<u16>().is_ok() => (
                host.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
                &token[host.len()..],
            ),
            _ => (None, ""),
        },
    };
    match address {
        Some(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(format!("<address>{port}")),
        _ => None,
    }
}

fn strip_home_folders(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(start) = rest.find("/Users/") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "/Users/".len()..];
        let end = after
            .find(|c: char| c == '/' || c.is_whitespace())
            .unwrap_or(after.len());
        out.push('~');
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Should change: LAN, public and IPv6 addresses, with or without a port, are removed.
    /// Should not change: loopback, the wildcard, times, counts and version numbers stay.
    #[test]
    fn addresses_are_removed_but_loopback_times_and_counts_stay() {
        assert_eq!(
            redact("Self health check running; test queries go to 192.168.1.20:53"),
            "Self health check running; test queries go to <address>:53"
        );
        assert_eq!(
            redact("bound [fd00::1]:53 and 203.0.113.9"),
            "bound [<address>]:53 and <address>"
        );
        assert_eq!(
            redact("listening on 127.0.0.1:53 and [::1]:53 and 0.0.0.0:53"),
            "listening on 127.0.0.1:53 and [::1]:53 and 0.0.0.0:53"
        );
        assert_eq!(
            redact("2026-09-14 20:24:36 Blocklist loaded: 1060000 domains, v0.1.0"),
            "2026-09-14 20:24:36 Blocklist loaded: 1060000 domains, v0.1.0"
        );
    }

    /// Should change: an address touching the punctuation of the sentence around it is still
    /// removed, and that punctuation stays.
    /// Should not change: loopback stays even with punctuation, and plain hex words stay.
    #[test]
    fn addresses_next_to_punctuation_are_removed_too() {
        for (line, expected) in [
            ("no answer from 192.0.2.5.", "no answer from <address>."),
            (
                "sent to 192.0.2.5: timed out",
                "sent to <address>: timed out",
            ),
            ("from:192.0.2.5 again", "from:<address> again"),
            ("peer 2001:db8::7.", "peer <address>."),
            ("mapped ::ffff:192.0.2.5.", "mapped <address>."),
            ("[fe80::1%en0]", "[<address>%en0]"),
            ("on 127.0.0.1. Fine", "on 127.0.0.1. Fine"),
            ("cafe: beef.", "cafe: beef."),
        ] {
            assert_eq!(redact(line), expected, "{line}");
        }
    }

    /// Should change: a configuration that fails to parse is described by line and key, never
    /// by the text on that line — in the configuration section and in the service log, where
    /// the service wrote the same error when it failed to start.
    /// Should not change: the reason (which line, which key) is still there.
    #[test]
    fn a_broken_configuration_is_described_without_its_values() {
        for (text, expected) in [
            (
                "upstream = tls 198.51.100.7 private-doh.example.net extra\n",
                "line 1 has a value `upstream` cannot use",
            ),
            (
                "nas.example.lan\n",
                "line 1 is not in the form `key = value`",
            ),
            (
                "office_nas = nas.example.lan\n",
                "line 1 is not a setting Phylode knows",
            ),
        ] {
            let error = Config::parse(text).unwrap_err();
            let report = render(&Facts {
                config: Err(&error),
                log: Ok(format!(
                    "Could not use the configuration file /usr/local/etc/phylode/phylode.conf: \
                     {error}\n"
                )),
                ..facts_without_config()
            });
            for secret in [
                "private-doh",
                "198.51.100.7",
                "nas.example.lan",
                "office_nas",
            ] {
                assert!(!report.contains(secret), "{secret} leaked:\n{report}");
            }
            assert!(report.contains(expected), "missing {expected:?}:\n{report}");
        }
    }

    fn facts_without_config() -> Facts<'static> {
        Facts {
            version: "0.1.0",
            macos: "26.1",
            arch: "aarch64",
            config: Err(&ConfigError::NoListen),
            answering: false,
            blocklist_domains: None,
            blocklist_ages: Vec::new(),
            allowlist_entries: None,
            user_blocklist_entries: None,
            events: Vec::new(),
            log: Err("not read".to_string()),
        }
    }

    #[test]
    fn home_folders_are_replaced_with_a_tilde() {
        assert_eq!(
            redact("could not read /Users/someone/lists/block.txt: denied"),
            "could not read ~/lists/block.txt: denied"
        );
        assert_eq!(redact("/Users/someone"), "~");
    }

    /// Should change: nothing that identifies the network appears — configured names,
    /// internal domains, upstream addresses, list paths.
    /// Should not change: the counts and states a maintainer needs are all there.
    #[test]
    fn the_report_carries_counts_and_states_but_nothing_configured_by_name() {
        let config = Config::parse(
            "listen = 192.168.1.20:53\n\
             upstream = tls 198.51.100.7 private-doh.example.net\n\
             blocklist = /Users/someone/lists/a.txt\n\
             internal_domain = nas.example.lan\n",
        )
        .unwrap();
        let facts = Facts {
            version: "0.1.0",
            macos: "26.1",
            arch: "aarch64",
            config: Ok(&config),
            answering: true,
            blocklist_domains: Some(1_060_000),
            blocklist_ages: vec![Some(0), None],
            allowlist_entries: Some(3),
            user_blocklist_entries: None,
            events: vec![
                ("2026-09-14 20:00:00".to_string(), "started".to_string()),
                (
                    "2026-09-14 20:00:01".to_string(),
                    "rate-limited".to_string(),
                ),
            ],
            log: Ok("Self health check running; test queries go to 192.168.1.20:53\n".to_string()),
        };
        let report = render(&facts);

        for secret in [
            "192.168.1.20",
            "198.51.100.7",
            "private-doh.example.net",
            "nas.example.lan",
            "someone",
        ] {
            assert!(!report.contains(secret), "{secret} leaked:\n{report}");
        }
        for expected in [
            "Phylode 0.1.0",
            "macOS 26.1 (aarch64)",
            "Service answering: yes",
            "Upstreams: 1 (DNS over TLS)",
            "Internal domains exempt from rebinding defense: 1",
            "Blocklist: 1060000 domains loaded",
            "list 2: missing",
            "Own blocklist entries: could not be read",
            "rate-limited: 1",
            "Listening on: <address>:53",
        ] {
            assert!(report.contains(expected), "missing {expected:?}:\n{report}");
        }
    }
}
