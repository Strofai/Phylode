//! The networks this Mac is directly on: the address ranges of its wired, Wi-Fi and bridge
//! interfaces, as macOS reports them.
//!
//! This is Apple's definition of the local network (TN3179): a network on one of the Mac's own
//! interfaces, never one reached through a VPN. The interfaces come from
//! `SCNetworkInterfaceCopyAll`, which lists hardware and leaves tunnels out; their ranges from
//! the SystemConfiguration dynamic store, the same state System Settings shows.
//!
//! What breaks if you change it: work it out from the route to the internet instead and a
//! full-tunnel VPN becomes "the local network", so every peer on that VPN counts as a device
//! at home.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, ItemRef, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::runloop::{CFRunLoop, kCFRunLoopDefaultMode};
use core_foundation::string::CFString;
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};
use system_configuration::network_configuration::get_interfaces;

use crate::config::IpNetwork;

/// The dynamic store keys that change when an interface gains or loses an address.
const ADDRESS_KEYS: &str = "State:/Network/Interface/[^/]+/IPv[46]";

/// How often the networks are re-read when macOS cannot notify us of changes.
const POLL_WITHOUT_NOTIFICATIONS: Duration = Duration::from_secs(60);

/// The networks this Mac is on, kept current by [`AttachedNetworks::watch`]. Clones share
/// them, so the copy being refreshed and the copies being read stay in step.
///
/// Unknown until macOS has answered once; see [`AttachedNetworks::known`].
#[derive(Clone, Debug, Default)]
pub struct AttachedNetworks(Arc<RwLock<Option<Vec<IpNetwork>>>>);

impl AttachedNetworks {
    /// Reads the networks now, then again each time macOS reports an address change, on a
    /// thread of its own. Without notifications it falls back to reading every minute.
    ///
    /// Returns whether macOS notifications are in use; `false` means the fallback.
    pub fn watch(&self) -> std::io::Result<bool> {
        let (ready, notified) = std::sync::mpsc::channel();
        let attached = self.clone();
        std::thread::Builder::new()
            .name("phylode-networks".to_string())
            .spawn(move || attached.run(&ready))?;
        Ok(notified.recv().unwrap_or(false))
    }

    fn run(self, ready: &std::sync::mpsc::Sender<bool>) {
        let context = SCDynamicStoreCallBackContext {
            callout: |store, _changed, attached: &mut AttachedNetworks| attached.read_from(&store),
            info: self.clone(),
        };
        let watched = SCDynamicStoreBuilder::new("phylode")
            .callback_context(context)
            .build()
            .filter(|store| {
                let patterns = CFArray::from_CFTypes(&[CFString::from_static_string(ADDRESS_KEYS)]);
                store.set_notification_keys(&CFArray::<CFString>::from_CFTypes(&[]), &patterns)
            })
            .and_then(|store| store.create_run_loop_source().map(|source| (store, source)));
        let Some((store, source)) = watched else {
            let _ = ready.send(false);
            loop {
                if let Some(store) = SCDynamicStoreBuilder::new("phylode").build() {
                    self.read_from(&store);
                }
                std::thread::sleep(POLL_WITHOUT_NOTIFICATIONS);
            }
        };
        self.read_from(&store);
        let _ = ready.send(true);
        #[allow(
            unsafe_code,
            reason = "the run loop mode is a CoreFoundation constant, readable only through unsafe"
        )]
        // SAFETY: reads an immutable constant CoreFoundation exports; it is set before any
        // Rust code runs and never written again.
        let mode = unsafe { kCFRunLoopDefaultMode };
        CFRunLoop::get_current().add_source(&source, mode);
        CFRunLoop::run_current();
    }

    /// Whether `ip` is on one of the networks. Never while they are unknown.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.read().is_ok_and(|networks| {
            networks
                .as_ref()
                .is_some_and(|networks| networks.iter().any(|net| net.contains(ip)))
        })
    }

    /// Whether macOS has said which networks this Mac is on. Until it has, a caller deciding
    /// whom to serve must not take "on none of them" as the answer.
    ///
    /// What breaks if you change it: treat unknown as "no networks" and a Mac that cannot
    /// reach SystemConfiguration answers no device at all — the whole network goes offline.
    pub fn known(&self) -> bool {
        self.0.read().is_ok_and(|networks| networks.is_some())
    }

    /// Takes what macOS reports now. A read that gets nothing keeps the last answer.
    fn read_from(&self, store: &SCDynamicStore) {
        let Some(networks) = read(store) else {
            return;
        };
        if let Ok(mut current) = self.0.write() {
            *current = Some(networks);
        }
    }

    /// Test only: these networks instead of reading this Mac's.
    #[cfg(test)]
    pub fn fixed(networks: &[&str]) -> Self {
        let networks = networks.iter().map(|net| net.parse().unwrap()).collect();
        Self(Arc::new(RwLock::new(Some(networks))))
    }

    /// Test only: what a refresh does when this Mac moves to `networks`.
    #[cfg(test)]
    pub fn replace_for_test(&self, networks: &[&str]) {
        *self.0.write().unwrap() = Some(networks.iter().map(|net| net.parse().unwrap()).collect());
    }
}

/// Every range on every hardware interface that has an address right now. `None` when macOS
/// lists no hardware interface at all, which means it could not be asked: every Mac has one.
fn read(store: &SCDynamicStore) -> Option<Vec<IpNetwork>> {
    let interfaces = get_interfaces();
    if interfaces.is_empty() {
        return None;
    }
    let mut networks = Vec::new();
    for interface in &interfaces {
        let Some(name) = interface.bsd_name() else {
            continue;
        };
        let state = |family: &str| {
            store
                .get(CFString::new(&format!(
                    "State:/Network/Interface/{name}/{family}"
                )))
                .and_then(|value| value.downcast_into::<CFDictionary>())
        };
        if let Some(v4) = state("IPv4") {
            let addresses = strings(&v4, "Addresses");
            let masks = strings(&v4, "SubnetMasks");
            networks.extend(
                addresses
                    .iter()
                    .zip(&masks)
                    .filter_map(|(address, mask)| ipv4_network(address, mask)),
            );
        }
        if let Some(v6) = state("IPv6") {
            let addresses = strings(&v6, "Addresses");
            let prefixes = numbers(&v6, "PrefixLength");
            networks.extend(
                addresses
                    .iter()
                    .zip(&prefixes)
                    .filter_map(|(address, &prefix)| ipv6_network(address, prefix)),
            );
        }
    }
    Some(networks)
}

/// The IPv4 network an address and its subnet mask describe. A mask whose bits are not
/// contiguous describes no network.
fn ipv4_network(address: &str, mask: &str) -> Option<IpNetwork> {
    let address: Ipv4Addr = address.parse().ok()?;
    let mask = u32::from(mask.parse::<Ipv4Addr>().ok()?);
    if mask.leading_ones() != mask.count_ones() {
        return None;
    }
    IpNetwork::new(IpAddr::V4(address), u8::try_from(mask.count_ones()).ok()?)
}

/// The IPv6 network an address and its prefix length describe. A `%interface` suffix on a
/// link-local address is ignored.
fn ipv6_network(address: &str, prefix: i64) -> Option<IpNetwork> {
    let address: Ipv6Addr = address.split('%').next()?.parse().ok()?;
    IpNetwork::new(IpAddr::V6(address), u8::try_from(prefix).ok()?)
}

fn strings(dictionary: &CFDictionary, key: &'static str) -> Vec<String> {
    values(dictionary, key)
        .filter_map(|value| value.downcast_into::<CFString>())
        .map(|value| value.to_string())
        .collect()
}

fn numbers(dictionary: &CFDictionary, key: &'static str) -> Vec<i64> {
    values(dictionary, key)
        .filter_map(|value| value.downcast_into::<CFNumber>())
        .filter_map(|value| value.to_i64())
        .collect()
}

/// The elements of the array stored under `key`, or none when there is no array there.
fn values(dictionary: &CFDictionary, key: &'static str) -> impl Iterator<Item = CFType> {
    let array = dictionary
        .find(CFString::from_static_string(key).as_CFTypeRef())
        .map(retained)
        .and_then(|value| value.downcast_into::<CFArray>());
    array
        .map(|array| array.iter().map(retained).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
}

/// A reference of our own to an element of a CoreFoundation dictionary or array, typed as
/// "any CoreFoundation object" so it can only be used after a checked downcast.
#[allow(
    unsafe_code,
    reason = "core-foundation hands out container elements only as raw pointers"
)]
fn retained(element: ItemRef<'_, *const c_void>) -> CFType {
    // SAFETY: an `ItemRef` only comes out of a CoreFoundation container that is still alive,
    // so the pointer is a valid CoreFoundation object; the get rule takes a retain of our own,
    // so the result outlives the container safely.
    unsafe { CFType::wrap_under_get_rule((*element).cast()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// Which of `addresses` the network holds.
    fn holds<'a>(network: Option<IpNetwork>, addresses: &[&'a str]) -> Vec<&'a str> {
        let network = network.expect("a network");
        addresses
            .iter()
            .copied()
            .filter(|address| network.contains(ip(address)))
            .collect()
    }

    #[test]
    fn an_ipv4_address_and_mask_give_its_network() {
        assert_eq!(
            holds(
                ipv4_network("192.168.1.20", "255.255.255.0"),
                &["192.168.1.1", "192.168.1.254", "192.168.2.1"]
            ),
            ["192.168.1.1", "192.168.1.254"]
        );
        assert_eq!(
            holds(
                ipv4_network("10.1.2.3", "255.255.240.0"),
                &["10.1.0.1", "10.1.15.254", "10.1.16.1"]
            ),
            ["10.1.0.1", "10.1.15.254"]
        );
        assert_eq!(ipv4_network("192.168.1.20", "255.0.255.0"), None);
        assert_eq!(ipv4_network("not an address", "255.255.255.0"), None);
    }

    #[test]
    fn an_ipv6_address_and_prefix_give_its_network() {
        assert_eq!(
            holds(
                ipv6_network("fd12:3456:789a:1::20", 64),
                &["fd12:3456:789a:1::99", "fd12:3456:789a:2::1"]
            ),
            ["fd12:3456:789a:1::99"]
        );
        assert_eq!(
            holds(ipv6_network("fe80::1%en0", 64), &["fe80::abcd", "fe81::1"]),
            ["fe80::abcd"]
        );
        assert_eq!(ipv6_network("fd12::1", 200), None);
        assert_eq!(ipv6_network("fd12::1", -1), None);
    }

    /// Should change: watching works the way the service uses it — macOS notifications are
    /// set up, the networks are known, and this Mac's own wired or Wi-Fi address falls inside
    /// them.
    /// Fails inside a sandbox that blocks SystemConfiguration, which is what it is meant to
    /// catch: there the service would fall back to every private range.
    #[test]
    fn watching_reads_this_macs_own_network_from_macos() {
        let attached = AttachedNetworks::default();
        assert_eq!(
            attached.watch().ok(),
            Some(true),
            "notifications not set up"
        );
        assert!(
            attached.known(),
            "macOS did not say which networks this Mac is on"
        );
        let own = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .and_then(|socket| {
                socket
                    .connect((Ipv4Addr::new(192, 0, 2, 1), 53))
                    .map(|()| socket)
            })
            .and_then(|socket| socket.local_addr());
        if let Ok(own) = own {
            assert!(attached.contains(own.ip()), "{own} not in {attached:?}");
        }
    }
}
