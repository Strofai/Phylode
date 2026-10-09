//! Which devices get answers: those on the networks the gatekeeper serves. Anything else gets
//! no response at all.
//!
//! The service listens on every interface so any device on the network can use it. This is
//! what keeps that from also serving whoever can reach the Mac from outside — an open resolver
//! is ammunition for reflection attacks. A private source address only counts when this Mac is
//! on that network itself (Apple's definition of the local network, TN3179): anyone on the
//! internet can write a private address into a packet, but they cannot guess which private
//! network a home uses on IPv6, and a VPN is not the local network.
//!
//! What breaks if you change it: answering outsiders with REFUSED or an error would still
//! amplify; saying nothing is the only answer that gives an attacker nothing back. Serving a
//! private range without checking this Mac is on it lets forged packets use up the upstream
//! capacity the whole network shares.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use super::{Admit, AttachedNetworks};
use crate::config::IpNetwork;

/// The ranges a home, office, studio or school network uses for its own devices: RFC 1918,
/// IPv4 link-local, the shared address space some routers hand out (RFC 6598), IPv6 unique
/// local (RFC 4193) and IPv6 link-local. A source in one of them is served only when this Mac
/// is on that network. Public networks are served only through `serve_network`.
const LOCAL_RANGES: [(IpAddr, u8); 7] = [
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
];

/// How many different outside sources get an event of their own. Forged source addresses
/// could otherwise grow the set, and the journal, without bound.
const MAX_NOTED: usize = 64;

/// The networks served, plus which outside sources have already been recorded.
#[derive(Debug)]
pub struct ServedNetworks {
    local_ranges: Vec<IpNetwork>,
    configured: Vec<IpNetwork>,
    attached: AttachedNetworks,
    noted: Mutex<HashSet<IpAddr>>,
}

impl ServedNetworks {
    /// Serves loopback, `configured`, and whatever part of the local ranges `attached` says
    /// this Mac is on — all of them while macOS has not said, so a Mac that cannot ask still
    /// serves its network.
    pub fn new(configured: &[IpNetwork], attached: AttachedNetworks) -> Self {
        Self {
            local_ranges: LOCAL_RANGES
                .iter()
                .filter_map(|&(address, prefix)| IpNetwork::new(address, prefix))
                .collect(),
            configured: configured.to_vec(),
            attached,
            noted: Mutex::new(HashSet::new()),
        }
    }

    /// Whether `client` gets an answer. `first` is set the first time a given outside source
    /// is turned away, so only that one is journalled.
    ///
    /// An IPv4 client reaching an IPv6 socket arrives as `::ffff:a.b.c.d` and is judged by its
    /// IPv4 address.
    pub fn admit(&self, client: IpAddr) -> Admit {
        let client = match client {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(client, IpAddr::V4),
            v4 => v4,
        };
        if client.is_loopback()
            || self.configured.iter().any(|net| net.contains(client))
            || (self.local_ranges.iter().any(|net| net.contains(client))
                && (!self.attached.known() || self.attached.contains(client)))
        {
            return Admit::Yes;
        }
        let first = match self.noted.lock() {
            Ok(mut noted) => noted.len() < MAX_NOTED && noted.insert(client),
            Err(_) => false,
        };
        Admit::No { first }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn turned_away(served: &ServedNetworks, client: &str) -> bool {
        matches!(served.admit(ip(client)), Admit::No { .. })
    }

    /// A Mac on a typical home network: one IPv4 network, a unique local and a link-local IPv6
    /// network, and a public IPv6 network from the provider.
    fn at_home() -> AttachedNetworks {
        AttachedNetworks::fixed(&[
            "192.168.1.0/24",
            "fd12:3456:789a:1::/64",
            "fe80::/64",
            "2001:db8:1:2::/64",
        ])
    }

    /// Should change: nothing outside loopback and this Mac's own private networks is served.
    /// Should not change: loopback and devices on this Mac's networks are served, over IPv4,
    /// IPv6 and IPv4-mapped IPv6.
    #[test]
    fn loopback_and_this_macs_own_private_networks_are_served() {
        let served = ServedNetworks::new(&[], at_home());
        for client in [
            "127.0.0.1",
            "::1",
            "192.168.1.20",
            "fd12:3456:789a:1::20",
            "fe80::1",
            "::ffff:192.168.1.20",
        ] {
            assert_eq!(served.admit(ip(client)), Admit::Yes, "{client}");
        }
        for client in [
            "203.0.113.9",
            "8.8.8.8",
            "2001:db8::1",
            "::ffff:203.0.113.9",
        ] {
            assert!(turned_away(&served, client), "{client} is public");
        }
    }

    /// Should change: a private address on a network this Mac is not on gets nothing — that is
    /// what a packet forged from the internet carries.
    /// Should not change: the same Mac still serves its own network.
    #[test]
    fn a_private_source_on_a_network_this_mac_is_not_on_is_turned_away() {
        let served = ServedNetworks::new(&[], at_home());
        for client in ["fd99:1:2::7", "10.1.2.3", "192.168.7.7", "172.16.0.9"] {
            assert!(turned_away(&served, client), "{client}");
        }
        assert_eq!(served.admit(ip("192.168.1.20")), Admit::Yes);
    }

    /// Should change: being on a public network does not serve it; only `serve_network` does.
    #[test]
    fn this_macs_public_network_is_served_only_when_configured() {
        let served = ServedNetworks::new(&[], at_home());
        assert!(turned_away(&served, "2001:db8:1:2::99"));

        let configured: IpNetwork = "2001:db8:1:2::/64".parse().unwrap();
        let served = ServedNetworks::new(&[configured], at_home());
        assert_eq!(served.admit(ip("2001:db8:1:2::99")), Admit::Yes);
    }

    /// Should change: a configured network is served even though it is public.
    /// Should not change: this Mac's own network and loopback are still served, and other
    /// public addresses still are not.
    #[test]
    fn configured_networks_are_served_on_top_of_this_macs_own() {
        let school: IpNetwork = "198.51.100.0/24".parse().unwrap();
        let served = ServedNetworks::new(&[school], at_home());
        assert_eq!(served.admit(ip("198.51.100.77")), Admit::Yes);
        assert_eq!(served.admit(ip("127.0.0.1")), Admit::Yes);
        assert_eq!(served.admit(ip("192.168.1.20")), Admit::Yes);
        assert!(turned_away(&served, "203.0.113.9"));
    }

    /// Should change: the shared address space is served where a router hands it to this Mac's
    /// own network; a peer elsewhere in that space, as on a VPN, is not.
    /// Should not change: a `serve_network` covering it is served either way.
    #[test]
    fn shared_address_space_is_served_only_on_this_macs_own_network() {
        let peer = "100.101.102.103";
        let behind_router = AttachedNetworks::fixed(&["100.70.0.0/24"]);
        let served = ServedNetworks::new(&[], behind_router);
        assert_eq!(served.admit(ip("100.70.0.9")), Admit::Yes);
        assert!(turned_away(&served, peer));

        let served = ServedNetworks::new(&[], at_home());
        assert!(turned_away(&served, peer));

        let tailnet: IpNetwork = "100.64.0.0/10".parse().unwrap();
        let served = ServedNetworks::new(&[tailnet], at_home());
        assert_eq!(served.admit(ip(peer)), Admit::Yes);
    }

    /// Should change: networks this Mac moves onto are served as soon as they are read, and
    /// the one it left no longer is.
    #[test]
    fn served_networks_follow_the_networks_this_mac_is_on() {
        let attached = AttachedNetworks::fixed(&[]);
        let served = ServedNetworks::new(&[], attached.clone());
        assert!(turned_away(&served, "192.168.1.20"));
        attached.replace_for_test(&["192.168.1.0/24"]);
        assert_eq!(served.admit(ip("192.168.1.20")), Admit::Yes);
        attached.replace_for_test(&["10.0.0.0/24"]);
        assert!(turned_away(&served, "192.168.1.20"));
    }

    /// Should change: until macOS says which networks this Mac is on, every local range is
    /// served, so the network stays online.
    /// Should not change: public addresses still get nothing.
    #[test]
    fn every_local_range_is_served_while_this_macs_networks_are_unknown() {
        let served = ServedNetworks::new(&[], AttachedNetworks::default());
        for client in ["192.168.7.7", "10.1.2.3", "fd99:1:2::7", "100.101.102.103"] {
            assert_eq!(served.admit(ip(client)), Admit::Yes, "{client}");
        }
        assert!(turned_away(&served, "203.0.113.9"));
    }

    #[test]
    fn each_outside_source_is_noted_once_and_the_set_stays_bounded() {
        let served = ServedNetworks::new(&[], at_home());
        assert_eq!(served.admit(ip("203.0.113.9")), Admit::No { first: true });
        assert_eq!(served.admit(ip("203.0.113.9")), Admit::No { first: false });
        for last in 0..=255u8 {
            let _ = served.admit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, last)));
        }
        assert_eq!(
            served.admit(ip("192.0.2.1")),
            Admit::No { first: false },
            "past the cap nothing more is noted"
        );
    }

    #[test]
    fn a_network_matches_by_prefix_and_rejects_impossible_prefixes() {
        let net: IpNetwork = "192.0.2.7/24".parse().unwrap();
        assert!(net.contains(ip("192.0.2.200")));
        assert!(!net.contains(ip("192.0.3.1")));
        assert!(!net.contains(ip("2001:db8::1")));
        let everything: IpNetwork = "0.0.0.0/0".parse().unwrap();
        assert!(everything.contains(ip("203.0.113.9")));
        let v6: IpNetwork = "2001:db8:1:2::/64".parse().unwrap();
        assert!(v6.contains(ip("2001:db8:1:2::99")));
        assert!(!v6.contains(ip("2001:db8:1:3::1")));
        for bad in ["192.0.2.0/33", "2001:db8::/129", "192.0.2.0", "nas/24"] {
            assert!(bad.parse::<IpNetwork>().is_err(), "{bad}");
        }
    }
}
