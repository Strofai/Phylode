//! Local zones: names that only mean something inside the network are answered locally with
//! "no such domain" and never sent upstream.
//!
//! Sending them would leak every device's hostname (Apple devices append the router's search
//! domain to a bare name before asking) and every private-address reverse lookup to
//! Cloudflare or Quad9, violating product principle 3. Upstream resolvers can only answer
//! "does not exist" for these anyway, so answering locally makes nothing less resolvable.
//!
//! What breaks if you change it: this list may contain only names **guaranteed not to exist
//! on the public internet** (RFC-reserved, or undelegated in the root zone). Add a domain
//! that really exists and the whole network loses access to it, with no error pointing
//! here.

/// Names guaranteed not to exist on the public internet, together with everything beneath
/// them.
///
/// Sources: RFC 6303 (private-address reverse lookups), RFC 7793 (100.64/10), RFC 6761 (localhost, invalid, test),
/// RFC 6762 (local; and home, lan, corp from appendix G), RFC 8375 (home.arpa), RFC 7686
/// (onion), RFC 9476 (alt), RFC 9462 (resolver.arpa), and
/// `internal`, which ICANN reserved for private networks.
const LOCAL_ZONES: &[&str] = &[
    "local",
    "localhost",
    "invalid",
    "test",
    "home.arpa",
    "internal",
    "home",
    "lan",
    "corp",
    "onion",
    "alt",
    // Asked by devices looking for an encrypted resolver to switch to (DDR). RFC 9462 §6.1:
    // a forwarder should not pass these on, or the device is offered the upstream's.
    "resolver.arpa",
    // IPv4 reverse: 10/8, 127/8, 169.254/16, 192.168/16, 0/8, test networks, broadcast
    "10.in-addr.arpa",
    "127.in-addr.arpa",
    "254.169.in-addr.arpa",
    "168.192.in-addr.arpa",
    "0.in-addr.arpa",
    "2.0.192.in-addr.arpa",
    "100.51.198.in-addr.arpa",
    "113.0.203.in-addr.arpa",
    "255.255.255.255.in-addr.arpa",
    // IPv6 reverse: fc00::/7 (c.f, d.f), fe80::/10 (8.e.f through b.e.f), ::1 and ::
    "c.f.ip6.arpa",
    "d.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
];

/// Whether this name only means something inside the network.
///
/// Reverse lookups for 172.16/12 and 100.64/10 do not fall on label boundaries, so they are
/// checked separately.
/// Whether this is a bare host name with no domain, such as `nas` or `wpad`: a device asking
/// for a machine on its own network before (or instead of) adding a search domain. No such
/// host exists on the public internet; the root zone's own names are top-level domains,
/// which are not looked up as hosts. The caller decides which lookups this applies to.
///
/// What breaks if you change it: matching more than one label stops whole domains resolving.
pub fn is_bare_name(name: &str) -> bool {
    let name = name.trim().trim_end_matches('.');
    !name.is_empty() && !name.contains('.')
}

pub fn is_local(name: &str) -> bool {
    super::any_suffix(name, |rest| {
        LOCAL_ZONES.contains(&rest)
            || in_second_octet_range(rest, "172", 16..=31)
            || in_second_octet_range(rest, "100", 64..=127)
    })
}

/// Matches `<second>.<first>.in-addr.arpa` where the second octet falls in the range.
fn in_second_octet_range(name: &str, first: &str, range: std::ops::RangeInclusive<u8>) -> bool {
    let Some(rest) = name.strip_suffix(".in-addr.arpa") else {
        return false;
    };
    let Some((second, head)) = rest.split_once('.') else {
        return false;
    };
    head == first
        && second
            .parse::<u8>()
            .is_ok_and(|octet| range.contains(&octet))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Should change: local hostnames and private-address reverse lookups are answered
    /// locally.
    #[test]
    fn every_internal_name_is_recognized() {
        for name in [
            "printer.local",
            "macbook.router.home",
            "nas.home.arpa",
            "router.lan",
            "localhost",
            "1.0.168.192.in-addr.arpa",
            "5.0.0.10.in-addr.arpa",
            "1.1.20.172.in-addr.arpa",
            "9.9.64.100.in-addr.arpa",
            "1.0.0.127.in-addr.arpa",
            "4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            "HOME.ARPA.",
            "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
            "wallet.alt",
            "_dns.resolver.arpa",
        ] {
            assert!(
                is_local(name),
                "{name} should be answered locally, not sent upstream"
            );
        }
    }

    #[test]
    fn a_bare_name_has_no_dot() {
        for name in ["nas", "wpad", "printer.", "NAS"] {
            assert!(is_bare_name(name), "{name}");
        }
        for name in ["", ".", "nas.lan", "example.com"] {
            assert!(!is_bare_name(name), "{name}");
        }
    }

    /// Should not change: public names and public-address reverse lookups still go upstream.
    #[test]
    fn public_names_are_unaffected() {
        for name in [
            "www.apple.com",
            "example.com",
            "localhost.example.com",
            "home.example.com",
            "onion.example.com",
            "alt.example.com",
            "8.8.8.8.in-addr.arpa",
            "1.1.15.172.in-addr.arpa",
            "1.1.32.172.in-addr.arpa",
            "1.1.63.100.in-addr.arpa",
            "1.1.1.1.in-addr.arpa",
            "arpa",
            "in-addr.arpa",
            "",
        ] {
            assert!(
                !is_local(name),
                "{name} is public and must be resolved normally"
            );
        }
    }
}
