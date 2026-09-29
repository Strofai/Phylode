//! DNS rebinding defence: when an upstream answer points at an address inside the home
//! network, the whole answer is discarded.
//!
//! The attack works like this: a malicious domain first returns its own public address so
//! the browser loads the page, then the next lookup returns `192.168.x.x`. The browser still
//! considers it the same site, so that page can now target the router, NAS or printer at
//! home.
//!
//! What breaks if you change it: this layer looks only at **addresses**, never at whether a
//! domain is good or bad. Domains that legitimately resolve inward must be listed as
//! exceptions or they stop working entirely.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether this set of answers may be handed to the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rebinding {
    /// No address points inward; answer as usual.
    Clean,
    /// At least one address points into the home network; discard the whole answer.
    Blocked,
}

/// The rebinding guard. Holds the domains exempted from the inward-address rule.
///
/// What breaks if you change it: exception matching follows subdomains just like the
/// allowlist — listing `home.arpa` also exempts `nas.home.arpa`.
#[derive(Clone, Debug, Default)]
pub struct RebindGuard {
    internal_domains: HashSet<String>,
}

impl RebindGuard {
    /// Builds a guard with no exceptions: no domain may resolve to an internal address.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a guard from the internal domains listed in the configuration. Names are
    /// normalized to lowercase with no trailing dot.
    pub fn with_internal_domains<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            internal_domains: domains
                .into_iter()
                .map(|d| normalize(d.as_ref()))
                .filter(|d| !d.is_empty())
                .collect(),
        }
    }

    /// Whether this domain returning these addresses may be handed to the device.
    ///
    /// `addresses` holds only A/AAAA addresses; other record types do not come through here,
    /// because a rebinding attack needs an address something can connect to.
    pub fn inspect(&self, name: &str, addresses: &[IpAddr]) -> Rebinding {
        if addresses.iter().any(is_internal) && !self.is_internal_domain(name) {
            return Rebinding::Blocked;
        }
        Rebinding::Clean
    }

    /// Whether this name is on the exception list. The domain itself or any of its parents
    /// matching counts.
    pub fn is_internal_domain(&self, name: &str) -> bool {
        !self.internal_domains.is_empty()
            && super::any_suffix(name, |rest| self.internal_domains.contains(rest))
    }
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether this address counts as "inside the home network or this machine".
///
/// What breaks if you change it: missing a range leaves that range usable for attacking the
/// LAN; blocking an extra public range stops legitimate sites from loading. The standard
/// ranges do not change, but think carefully before adding a custom one.
fn is_internal(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_internal_v4(v4),
        // IPv6 addresses with an embedded IPv4 address must be unwrapped, or they bypass
        // this check entirely: IPv4-mapped (`::ffff:192.168.1.1`) and the well-known NAT64
        // prefix (`64:ff9b::192.168.1.1`, RFC 6052).
        IpAddr::V6(v6) => match v6.to_ipv4_mapped().or_else(|| nat64_embedded(v6)) {
            Some(v4) => is_internal_v4(&v4),
            None => is_internal_v6(v6),
        },
    }
}

/// In `64:ff9b::/96` the final 32 bits are the IPv4 address (RFC 6052 §2.1).
fn nat64_embedded(address: &Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = address.segments();
    (segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0]).then(|| {
        let [.., a, b, c, d] = address.octets();
        Ipv4Addr::new(a, b, c, d)
    })
}

fn is_internal_v4(address: &Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    address.is_private()            // 10/8, 172.16/12, 192.168/16
        || address.is_loopback()    // 127/8
        || address.is_link_local()  // 169.254/16
        || address.is_unspecified() // 0.0.0.0, which is also what we return for a block
        || address.is_broadcast()   // 255.255.255.255
        || address.is_multicast()   // 224/4
        || a == 0                   // 0/8, "this network"
        || (a == 100 && (64..128).contains(&b))     // 100.64/10 carrier-grade NAT
        || (a == 192 && b == 0 && c == 0)           // 192.0.0/24 IETF protocol assignments
        || (a == 198 && (18..20).contains(&b)) // 198.18/15 benchmarking
}

fn is_internal_v6(address: &Ipv6Addr) -> bool {
    let first = address.segments()[0];
    address.is_loopback()       // ::1
        || address.is_unspecified() // ::, which is also what we return for a blocked AAAA
        || address.is_multicast()
        || (first & 0xfe00) == 0xfc00  // fc00::/7 unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test addresses must parse")
    }

    #[test]
    fn all_three_private_ranges_count_as_internal() {
        for text in ["10.0.0.1", "172.16.5.5", "192.168.0.1", "192.168.1.254"] {
            assert!(is_internal(&ip(text)), "{text} should count as internal");
        }
    }

    #[test]
    fn the_other_reserved_ranges_count_as_internal_too() {
        for text in [
            "127.0.0.1",       // this machine
            "169.254.1.1",     // self-assigned when DHCP fails
            "0.0.0.0",         // what we return for a block
            "255.255.255.255", // broadcast
            "224.0.0.251",     // mDNS multicast
            "100.64.0.1",      // carrier-grade NAT
            "192.0.0.1",       // IETF protocol assignments
            "198.18.0.1",      // benchmarking
        ] {
            assert!(is_internal(&ip(text)), "{text} should count as internal");
        }
    }

    #[test]
    fn genuinely_public_addresses_are_not_internal() {
        for text in [
            "1.1.1.1",
            "9.9.9.9",
            "17.253.144.10", // Apple
            "100.63.255.255",
            "100.128.0.1", // just outside 100.64/10 at each end
            "192.0.1.1",
            "198.20.0.1",
            "172.15.0.1",
            "172.32.0.1", // just outside 172.16/12 at each end
        ] {
            assert!(
                !is_internal(&ip(text)),
                "{text} is public and must not be blocked"
            );
        }
    }

    #[test]
    fn the_internal_ipv6_ranges() {
        for text in ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1"] {
            assert!(is_internal(&ip(text)), "{text} should count as internal");
        }
        for text in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(
                !is_internal(&ip(text)),
                "{text} is public and must not be blocked"
            );
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_bypass_the_check() {
        // The easiest one to miss: `::ffff:192.168.1.1` really means 192.168.1.1.
        assert!(is_internal(&ip("::ffff:192.168.1.1")));
        assert!(!is_internal(&ip("::ffff:1.1.1.1")));
        // Same for the NAT64 prefix; a public address behind NAT64 is still public.
        assert!(is_internal(&ip("64:ff9b::192.168.1.1")));
        assert!(is_internal(&ip("64:ff9b::10.0.0.5")));
        assert!(!is_internal(&ip("64:ff9b::1.1.1.1")));
    }

    #[test]
    fn an_answer_pointing_inward_is_discarded() {
        let guard = RebindGuard::new();
        assert_eq!(
            guard.inspect("evil.example.com", &[ip("192.168.0.1")]),
            Rebinding::Blocked
        );
    }

    #[test]
    fn one_internal_address_discards_the_whole_batch() {
        // An attacker mixes in a public address, betting that only individual records get
        // filtered.
        let guard = RebindGuard::new();
        assert_eq!(
            guard.inspect("evil.example.com", &[ip("1.1.1.1"), ip("192.168.0.1")]),
            Rebinding::Blocked
        );
    }

    #[test]
    fn an_all_public_answer_passes_through() {
        let guard = RebindGuard::new();
        assert_eq!(
            guard.inspect("www.example.com", &[ip("93.184.216.34")]),
            Rebinding::Clean
        );
        assert_eq!(guard.inspect("www.example.com", &[]), Rebinding::Clean);
    }

    #[test]
    fn exempt_domains_may_return_internal_addresses() {
        let guard = RebindGuard::with_internal_domains(["home.arpa"]);
        assert_eq!(
            guard.inspect("nas.home.arpa", &[ip("192.168.0.9")]),
            Rebinding::Clean
        );
        assert_eq!(
            guard.inspect("home.arpa", &[ip("192.168.0.9")]),
            Rebinding::Clean
        );
        // An exception covers only its own tree, nobody else's.
        assert_eq!(
            guard.inspect("evil.example.com", &[ip("192.168.0.9")]),
            Rebinding::Blocked
        );
        // A similar-looking name that is not a subdomain does not count (`nothome.arpa` is
        // not beneath `home.arpa`).
        assert_eq!(
            guard.inspect("nothome.arpa", &[ip("192.168.0.9")]),
            Rebinding::Blocked
        );
    }

    #[test]
    fn exempt_domains_are_normalized_for_case_and_trailing_dot() {
        let guard = RebindGuard::with_internal_domains(["Home.Arpa."]);
        assert_eq!(
            guard.inspect("NAS.HOME.ARPA", &[ip("10.0.0.5")]),
            Rebinding::Clean
        );
    }

    #[test]
    fn a_blank_exception_entry_does_not_exempt_every_domain() {
        // If an empty string made it into the set, walking up the parents would hit it on
        // the final iteration, so **every** domain would be exempt — the whole defence
        // would fail silently.
        let guard = RebindGuard::with_internal_domains(["", "  ", "home.arpa"]);
        assert_eq!(
            guard.inspect("home.arpa", &[ip("10.0.0.5")]),
            Rebinding::Clean
        );
        assert_eq!(
            guard.inspect("evil.example.com", &[ip("10.0.0.5")]),
            Rebinding::Blocked
        );
    }
}
