//! `on` and `off`: points every network service on this Mac at the gatekeeper, and back to the
//! DNS servers it had before.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use super::port::ensure_phylode_holds_port;
use super::{
    ANSWER_WAIT, CONFIG_PATH, InstallError, answers_within, remove_if_present, require_root, run,
    write_file,
};
use crate::config::Config;

const NETWORKSETUP: &str = "/usr/sbin/networksetup";

/// What `on` changed, and where the rest of the network can reach the service.
pub struct SwitchedOn {
    /// This Mac's network services, now resolving through the gatekeeper.
    pub services: Vec<String>,
    /// See [`network_address`].
    pub network_address: Option<IpAddr>,
}

/// Points every network service on this Mac at the gatekeeper, after checking it answers and
/// holds its port alone — pointing DNS at a service that is not answering would leave the Mac
/// unable to resolve anything, and at a port another program holds would hand that program
/// every lookup.
///
/// Each service's DNS servers from before are saved, so `off` can put them back. A service
/// that cannot be changed does not stop the others; the error afterwards names it.
pub fn on() -> Result<SwitchedOn, InstallError> {
    require_root()?;
    let config = Config::load(Path::new(CONFIG_PATH)).map_err(|error| InstallError::Config {
        detail: error.to_string(),
    })?;
    if !answers_within(&config, ANSWER_WAIT) {
        return Err(InstallError::NotAnswering);
    }
    ensure_phylode_holds_port(&config)?;
    let saved_path = Path::new(DNS_BEFORE_ON_PATH);
    let mut saved = read_saved_dns(saved_path);
    let mut services = Vec::new();
    let mut failed = Vec::new();
    for service in network_services()? {
        let switched = run(NETWORKSETUP, &["-getdnsservers", &service]).and_then(|servers| {
            // Switched on twice, the first `on` already saved what was there before.
            if !points_at_gatekeeper(&servers) {
                saved.insert(service.clone(), dns_servers(&servers));
            }
            run(NETWORKSETUP, &["-setdnsservers", &service, "127.0.0.1"])
        });
        match switched {
            Ok(_) => services.push(service),
            Err(error) => failed.push(format!("{service} ({error})")),
        }
    }
    write_saved_dns(saved_path, &saved)?;
    if !failed.is_empty() {
        return Err(InstallError::SomeServices {
            changed: services.join(", "),
            failed: failed.join("; "),
        });
    }
    Ok(SwitchedOn {
        services,
        network_address: network_address(&config),
    })
}

/// The address other devices on the network use to reach this Mac: the one it sends from
/// towards its first upstream. `None` when there is no route (offline).
///
/// Connecting a UDP socket only picks a route; nothing is sent.
pub fn network_address(config: &Config) -> Option<IpAddr> {
    let upstream = config.upstreams().first()?.ip();
    let local: SocketAddr = match upstream {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = std::net::UdpSocket::bind(local).ok()?;
    socket.connect((upstream, 53)).ok()?;
    Some(socket.local_addr().ok()?.ip()).filter(|ip| !ip.is_unspecified())
}

/// Returns every network service that points at the gatekeeper to the DNS servers it had
/// before `on` (automatic when none were saved). Returns the services changed; services
/// configured with other resolvers are left alone.
///
/// What breaks if you change it: stop at the first service that fails and the ones after it
/// keep pointing at a service that `uninstall` is about to remove — those resolve nothing.
pub fn off() -> Result<Vec<String>, InstallError> {
    require_root()?;
    let saved_path = Path::new(DNS_BEFORE_ON_PATH);
    let saved = read_saved_dns(saved_path);
    let mut restored = Vec::new();
    let mut failed = Vec::new();
    for service in network_services()? {
        let result = run(NETWORKSETUP, &["-getdnsservers", &service]).and_then(|servers| {
            if !points_at_gatekeeper(&servers) {
                return Ok(false);
            }
            let before = saved.get(&service).map_or("empty", String::as_str);
            let mut args = vec!["-setdnsservers", service.as_str()];
            args.extend(before.split(' '));
            run(NETWORKSETUP, &args).map(|_| true)
        });
        match result {
            Ok(true) => restored.push(service),
            Ok(false) => {}
            Err(error) => failed.push(format!("{service} ({error})")),
        }
    }
    if !failed.is_empty() {
        return Err(InstallError::SomeServices {
            changed: restored.join(", "),
            failed: failed.join("; "),
        });
    }
    remove_if_present(saved_path)?;
    Ok(restored)
}

/// Whether any of this Mac's network services points at the gatekeeper. `false` when that
/// cannot be read.
///
/// Used after a failed install: an update that stopped the old service but could not start
/// the new one leaves such a Mac resolving nothing, and `phylode off` is the way back.
pub fn this_mac_uses_it() -> bool {
    network_services().is_ok_and(|services| {
        services.iter().any(|service| {
            run(NETWORKSETUP, &["-getdnsservers", service])
                .is_ok_and(|servers| points_at_gatekeeper(&servers))
        })
    })
}

/// Where `on` keeps each network service's DNS servers from before, one `service<TAB>servers`
/// line each, `empty` meaning automatic.
const DNS_BEFORE_ON_PATH: &str = "/usr/local/etc/phylode/dns-before-on.tsv";

/// The servers `networksetup -getdnsservers` listed, space-separated, or `empty` for none
/// (it prints a sentence rather than an empty list).
///
/// What breaks if you change it: only addresses may come out of here, since they go back to
/// `networksetup` as arguments.
fn dns_servers(output: &str) -> String {
    let servers: Vec<&str> = output
        .split_whitespace()
        .filter(|word| word.parse::<IpAddr>().is_ok())
        .collect();
    if servers.is_empty() {
        "empty".to_string()
    } else {
        servers.join(" ")
    }
}

/// The saved servers by service. A missing or unreadable file, or a line that is not a
/// service and addresses, counts as nothing saved: that service goes back to automatic.
fn read_saved_dns(path: &Path) -> std::collections::BTreeMap<String, String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (service, servers) = line.split_once('\t')?;
            (dns_servers(servers) == servers).then(|| (service.to_string(), servers.to_string()))
        })
        .collect()
}

fn write_saved_dns(
    path: &Path,
    saved: &std::collections::BTreeMap<String, String>,
) -> Result<(), InstallError> {
    let text: String = saved
        .iter()
        .map(|(service, servers)| format!("{service}\t{servers}\n"))
        .collect();
    write_file(path, &text, 0o644, 0, 0)
}

/// The names of this Mac's network services.
fn network_services() -> Result<Vec<String>, InstallError> {
    Ok(parse_network_services(&run(
        NETWORKSETUP,
        &["-listallnetworkservices"],
    )?))
}

/// Parses `networksetup -listallnetworkservices`: the first line is a notice, a leading `*`
/// marks a disabled service, and names may contain spaces — even at either end, so they are
/// kept exactly as listed or `networksetup` cannot find them again.
fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .map(|line| line.strip_prefix('*').unwrap_or(line).to_string())
        .filter(|name| !name.trim().is_empty())
        .collect()
}

/// Whether `networksetup -getdnsservers` output lists exactly the gatekeeper.
fn points_at_gatekeeper(servers: &str) -> bool {
    servers.trim() == "127.0.0.1"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Should change: what `networksetup -getdnsservers` printed becomes addresses, or
    /// `empty` for its "none set" sentence; a saved file round-trips.
    /// Should not change: anything that is not an address is never kept, so a tampered file
    /// cannot slip other arguments to `networksetup`.
    #[test]
    fn dns_servers_from_before_are_saved_and_read_back() {
        assert_eq!(
            dns_servers("192.0.2.53\n2001:db8::53\n"),
            "192.0.2.53 2001:db8::53"
        );
        assert_eq!(
            dns_servers("There aren't any DNS Servers set on Wi-Fi.\n"),
            "empty"
        );

        let path = std::env::temp_dir().join(format!("phylode-dns-{}", std::process::id()));
        let mut saved = std::collections::BTreeMap::new();
        saved.insert("Wi-Fi".to_string(), "192.0.2.53 198.51.100.53".to_string());
        saved.insert(" USB LAN ".to_string(), "empty".to_string());
        let text: String = saved
            .iter()
            .map(|(service, servers)| format!("{service}\t{servers}\n"))
            .collect();
        std::fs::write(&path, format!("{text}Ethernet\t-setairportpower on\n")).unwrap();
        assert_eq!(read_saved_dns(&path), saved);
        let _ = std::fs::remove_file(&path);
        assert!(read_saved_dns(&path).is_empty());
    }

    /// Should change: a service name keeps spaces at either end, or `networksetup` cannot find
    /// it again.
    /// Should not change: the notice line is skipped and a disabled service loses its `*`.
    #[test]
    fn network_service_names_are_kept_exactly() {
        let output = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\n USB LAN \n\n";
        assert_eq!(
            parse_network_services(output),
            ["Wi-Fi", "Thunderbolt Bridge", " USB LAN "]
        );
    }

    #[test]
    fn network_services_skip_the_notice_and_keep_spaces_and_disabled_ones() {
        let output = "An asterisk (*) denotes that a network service is disabled.\n\
                      Wi-Fi\n\
                      USB 10/100/1000 LAN\n\
                      *Thunderbolt Bridge\n";
        assert_eq!(
            parse_network_services(output),
            ["Wi-Fi", "USB 10/100/1000 LAN", "Thunderbolt Bridge"]
        );
    }

    #[test]
    fn only_a_service_pointing_solely_at_the_gatekeeper_counts_as_ours() {
        assert!(points_at_gatekeeper("127.0.0.1\n"));
        assert!(!points_at_gatekeeper(
            "There aren't any DNS Servers set on Wi-Fi.\n"
        ));
        assert!(!points_at_gatekeeper("127.0.0.1\n1.1.1.1\n"));
    }
}
