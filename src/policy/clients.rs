//! Which devices get answers: those on the networks the gatekeeper serves. Anything else gets
//! no response at all.
//!
//! The service listens on every interface so any device on the network can use it. This is
//! what keeps that from also serving whoever can reach the Mac from outside — an open resolver
//! is ammunition for reflection attacks.
//!
//! What breaks if you change it: answering outsiders with REFUSED or an error would still
//! amplify; saying nothing is the only answer that gives an attacker nothing back.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::Admit;
use crate::config::IpNetwork;

/// The private ranges a home, office, studio or school network normally uses: RFC 1918, IPv4
/// link-local, IPv6 unique local (RFC 4193) and IPv6 link-local. Loopback is always served on
/// top of whatever is configured.
const PRIVATE_RANGES: [(IpAddr, u8); 6] = [
    (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
    (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
    (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
    (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
    (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
];

/// The shared address space (RFC 6598). Providers use it between their customers, and overlay
/// VPNs such as Tailscale give it to every peer, so unlike the ranges above it is not
/// assumed to be this network; some home routers hand it out, though.
const SHARED_SPACE: (Ipv4Addr, u8) = (Ipv4Addr::new(100, 64, 0, 0), 10);

/// A public IPv4 address used only to ask the system which source address it would pick.
/// Connecting a UDP socket sends no packet.
const ROUTE_PROBE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// Whether this Mac's own IPv4 address — the one it reaches the internet from — is in the
/// shared address space, meaning the network it sits on hands that space out. Clones share
/// the answer.
///
/// This follows Apple's definition of the local network (TN3179): a network on the Mac's own
/// interface, not one reached through a VPN, whose interface does not carry the default route.
/// What breaks if you change it: serve the space unconditionally and peers on a VPN, or other
/// customers of a provider, can use this Mac's resolver and fill its journal.
#[derive(Clone, Debug, Default)]
pub struct SharedAddressSpace(Arc<AtomicBool>);

impl SharedAddressSpace {
    /// Re-reads this Mac's own address. Cheap and sends nothing, so it can run every minute.
    pub fn refresh(&self) {
        let own = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .and_then(|socket| socket.connect((ROUTE_PROBE, 53)).map(|()| socket))
            .and_then(|socket| socket.local_addr());
        let in_space = own.is_ok_and(|own| shared_space().contains(own.ip()));
        self.0.store(in_space, Ordering::Relaxed);
    }

    fn in_use(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Test only: a fixed answer instead of reading this Mac's address.
    #[cfg(test)]
    pub fn fixed(in_use: bool) -> Self {
        Self(Arc::new(AtomicBool::new(in_use)))
    }
}

fn shared_space() -> IpNetwork {
    let (address, prefix) = SHARED_SPACE;
    IpNetwork::new(IpAddr::V4(address), prefix).expect("RFC 6598 is a valid network")
}

/// How many different outside sources get an event of their own. Forged source addresses
/// could otherwise grow the set, and the journal, without bound.
const MAX_NOTED: usize = 64;

/// The networks served, plus which outside sources have already been recorded.
#[derive(Debug)]
pub struct ServedNetworks {
    networks: Vec<IpNetwork>,
    shared: SharedAddressSpace,
    noted: Mutex<HashSet<IpAddr>>,
}

impl ServedNetworks {
    /// Serves the private ranges plus `configured`, and the shared address space while
    /// `shared` says this Mac is on it.
    pub fn new(configured: &[IpNetwork], shared: SharedAddressSpace) -> Self {
        let networks = PRIVATE_RANGES
            .iter()
            .filter_map(|&(address, prefix)| IpNetwork::new(address, prefix))
            .chain(configured.iter().copied())
            .collect();
        Self {
            networks,
            shared,
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
            || self.networks.iter().any(|net| net.contains(client))
            || (self.shared.in_use() && shared_space().contains(client))
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

    /// Should change: public addresses get no answer by default.
    /// Should not change: loopback and the private ranges networks actually use are served,
    /// over IPv4, IPv6 and IPv4-mapped IPv6.
    #[test]
    fn by_default_only_private_ranges_and_loopback_are_served() {
        let served = ServedNetworks::new(&[], SharedAddressSpace::fixed(false));
        for client in [
            "127.0.0.1",
            "::1",
            "10.1.2.3",
            "172.16.0.9",
            "172.31.255.1",
            "192.168.1.20",
            "169.254.3.4",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:192.168.1.20",
        ] {
            assert_eq!(served.admit(ip(client)), Admit::Yes, "{client}");
        }
        for client in [
            "203.0.113.9",
            "172.32.0.1",
            "8.8.8.8",
            "2001:db8::1",
            "::ffff:203.0.113.9",
        ] {
            assert!(
                matches!(served.admit(ip(client)), Admit::No { .. }),
                "{client} is outside every private range"
            );
        }
    }

    /// Should change: a configured network is served even though it is public.
    /// Should not change: the private ranges and loopback are still served, and other public
    /// addresses still are not.
    #[test]
    fn configured_networks_are_served_on_top_of_the_private_ranges() {
        let school: IpNetwork = "198.51.100.0/24".parse().unwrap();
        let served = ServedNetworks::new(&[school], SharedAddressSpace::fixed(false));
        assert_eq!(served.admit(ip("198.51.100.77")), Admit::Yes);
        assert_eq!(served.admit(ip("127.0.0.1")), Admit::Yes);
        assert_eq!(served.admit(ip("192.168.1.20")), Admit::Yes);
        assert!(matches!(served.admit(ip("203.0.113.9")), Admit::No { .. }));
    }

    /// Should change: the shared address space is served only while this Mac has an address
    /// in it, as on a router that hands it out; a VPN peer there is not served by default.
    /// Should not change: a `serve_network` covering it is served either way.
    #[test]
    fn shared_address_space_is_served_only_where_this_mac_uses_it() {
        let peer = ip("100.101.102.103");
        let served = ServedNetworks::new(&[], SharedAddressSpace::fixed(false));
        assert!(matches!(served.admit(peer), Admit::No { .. }));

        let served = ServedNetworks::new(&[], SharedAddressSpace::fixed(true));
        assert_eq!(served.admit(peer), Admit::Yes);

        let tailnet: IpNetwork = "100.64.0.0/10".parse().unwrap();
        let served = ServedNetworks::new(&[tailnet], SharedAddressSpace::fixed(false));
        assert_eq!(served.admit(peer), Admit::Yes);
    }

    #[test]
    fn each_outside_source_is_noted_once_and_the_set_stays_bounded() {
        let served = ServedNetworks::new(&[], SharedAddressSpace::fixed(false));
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
