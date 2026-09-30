//! Sets Phylode up as a boot service on this Mac and removes it again, and points the Mac's
//! DNS at it: `phylode install`, `on`, `off` and `uninstall`, each run with sudo.
//!
//! What breaks if you change it: the two plists, the daily list updater and the default
//! configuration are compiled in from `deploy/`, and the paths they contain must match the
//! constants below. `tests/deploy_contract.rs` checks the files agree with each other.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{PermissionsExt, chown};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::config::Config;
use crate::dns::self_probe;
use crate::health::PROBE_NAME;

/// Where `install` writes the configuration, and where every command reads it by default.
pub const CONFIG_PATH: &str = "/usr/local/etc/phylode.conf";

const SERVICE_USER: &str = "_phylode";
const GATEKEEPER_LABEL: &str = "com.Phylode.gatekeeper";
const UPDATE_LABEL: &str = "com.Phylode.blocklist-update";
const GATEKEEPER_PLIST_PATH: &str = "/Library/LaunchDaemons/com.Phylode.gatekeeper.plist";
const UPDATE_PLIST_PATH: &str = "/Library/LaunchDaemons/com.Phylode.blocklist-update.plist";
const UPDATE_SCRIPT_PATH: &str = "/usr/local/libexec/phylode-update-lists";
const BINARY_PATH: &str = "/usr/local/bin/phylode";
const ETC_DIR: &str = "/usr/local/etc/phylode";
const LISTS_DIR: &str = "/usr/local/etc/phylode/lists";
const LOG_DIR: &str = "/var/log/phylode";

const GATEKEEPER_PLIST: &str = include_str!("../../deploy/com.Phylode.gatekeeper.plist");
const UPDATE_PLIST: &str = include_str!("../../deploy/com.Phylode.blocklist-update.plist");
const UPDATE_SCRIPT: &str = include_str!("../../deploy/update-blocklists.sh");
const DEFAULT_CONFIG: &str = include_str!("../../deploy/phylode.conf");

/// How long `install` waits for the first list download before starting the service anyway.
/// Both lists normally arrive in a few seconds; a slow network should not block installing.
const LIST_WAIT: Duration = Duration::from_secs(120);
/// How long `install` and `on` wait for the service to answer.
const ANSWER_WAIT: Duration = Duration::from_secs(15);
/// How long `install` waits for the service to finish loading the lists after it answers.
const LOAD_WAIT: Duration = Duration::from_secs(60);

/// The line the service writes to its log once the blocklist is in memory. `install` watches
/// for it. What breaks if you change it: the service prints this constant, so the two stay in
/// step; a log line written some other way would never be seen.
pub const BLOCKLIST_LOADED: &str = "Blocklist loaded";
/// The service's error log, as set by `StandardErrorPath` in the gatekeeper plist.
pub const SERVICE_LOG: &str = "/var/log/phylode/stderr.log";

const DSCL: &str = "/usr/bin/dscl";
const LAUNCHCTL: &str = "/bin/launchctl";
const NETWORKSETUP: &str = "/usr/sbin/networksetup";

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("this needs administrator rights; run it with sudo")]
    NotRoot,
    #[error("could not run {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`{command}` failed: {stderr}")]
    Failed { command: String, stderr: String },
    #[error("could not write {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("no free system account ID below 500 for {SERVICE_USER}")]
    NoFreeId,
    #[error("could not read the numeric ID of {record} from the directory service")]
    UnknownId { record: String },
    #[error("could not read the configuration {CONFIG_PATH}: {detail}")]
    Config { detail: String },
    #[error(
        "the service is installed but did not answer within {} seconds; see {LOG_DIR}/stderr.log",
        ANSWER_WAIT.as_secs()
    )]
    NotAnswering,
    #[error(
        "{path} can be changed by an account that is not an administrator, which could then \
         replace what install puts there and have it run as root or as the service. Nothing \
         was installed. Make the folder writable only by root or an administrator, then try again"
    )]
    UnprotectedDirectory { path: PathBuf },
}

/// The folders `install` writes into as root, whose contents the boot service or `sudo
/// phylode` later run. Adding a path to the constants above means adding its folder here.
const PROTECTED_DIRS: [&str; 5] = [
    "/usr/local/bin",
    "/usr/local/etc",
    "/usr/local/libexec",
    "/Library/LaunchDaemons",
    "/var/log",
];

/// Installs or updates the service: the `_phylode` account, this binary, the configuration
/// (only if there is none yet), the daily list updater, and the boot service. Waits for the
/// first list download before starting the service, and for the service to answer.
///
/// Leaves the Mac's DNS settings alone; that is `on`.
pub fn install() -> Result<(), InstallError> {
    require_root()?;
    let admin_gid = directory_id("/Groups/admin", "PrimaryGroupID")?;
    for dir in PROTECTED_DIRS {
        require_only_administrators_can_change(Path::new(dir), admin_gid)?;
    }

    step(&format!(
        "Creating the account {SERVICE_USER} (the service runs as this, not root)"
    ));
    ensure_service_user()?;
    let service_uid = directory_id(&format!("/Users/{SERVICE_USER}"), "UniqueID")?;
    let service_gid = directory_id(&format!("/Groups/{SERVICE_USER}"), "PrimaryGroupID")?;

    step(&format!("Installing the program to {BINARY_PATH}"));
    install_binary()?;

    step(&format!("Preparing the journal directory {LOG_DIR}"));
    // Group admin, so `phylode report` needs no sudo; no one else can read it, because the
    // journal is a complete browsing history.
    make_dir(Path::new(LOG_DIR), 0o750, service_uid, admin_gid)?;

    if Path::new(CONFIG_PATH).exists() {
        step(&format!("Keeping the existing configuration {CONFIG_PATH}"));
    } else {
        step(&format!("Writing the default configuration {CONFIG_PATH}"));
        write_file(Path::new(CONFIG_PATH), DEFAULT_CONFIG, 0o644, 0, 0)?;
    }

    step("Preparing the list directories");
    // Writable by the admin group so `phylode allow` and `block` need no sudo (they write a
    // staging file and rename it). Only the daily update job writes the lists themselves.
    make_dir(Path::new(ETC_DIR), 0o775, 0, admin_gid)?;
    make_dir(Path::new(LISTS_DIR), 0o755, service_uid, service_gid)?;

    step("Installing the daily list update and downloading the lists now");
    write_file(Path::new(UPDATE_SCRIPT_PATH), UPDATE_SCRIPT, 0o755, 0, 0)?;
    write_file(Path::new(UPDATE_PLIST_PATH), UPDATE_PLIST, 0o644, 0, 0)?;
    reload(UPDATE_LABEL, UPDATE_PLIST_PATH)?;

    let config = Config::load(Path::new(CONFIG_PATH)).map_err(|error| InstallError::Config {
        detail: error.to_string(),
    })?;
    if wait_for(LIST_WAIT, || config.blocklists().iter().all(|p| p.exists())) {
        println!("    lists downloaded");
    } else {
        println!(
            "    ⚠️ the lists are still downloading; the service starts now and begins blocking \
             as soon as they arrive"
        );
    }

    step("Starting the boot service");
    // Only lines the new process appends count; an earlier run's log is still in the file.
    let log_start = fs::metadata(SERVICE_LOG).map_or(0, |meta| meta.len());
    write_file(
        Path::new(GATEKEEPER_PLIST_PATH),
        GATEKEEPER_PLIST,
        0o644,
        0,
        0,
    )?;
    reload(GATEKEEPER_LABEL, GATEKEEPER_PLIST_PATH)?;

    step("Checking that it answers and has loaded the lists");
    if !answers_within(&config, ANSWER_WAIT) {
        return Err(InstallError::NotAnswering);
    }
    if wait_for(LOAD_WAIT, || logged_since(log_start, BLOCKLIST_LOADED)) {
        println!("    answering and blocking");
    } else {
        println!(
            "    ⚠️ answering, but the lists are not loaded yet; it allows everything until they \
             are — check with: phylode status"
        );
    }
    println!();
    println!("Installed. This Mac is not using it yet; to switch it on:");
    println!("  sudo phylode on");
    Ok(())
}

/// Points every network service on this Mac at the gatekeeper, after checking it answers —
/// pointing DNS at a service that is not answering would leave the Mac unable to resolve
/// anything. Returns the services changed.
pub fn on() -> Result<Vec<String>, InstallError> {
    require_root()?;
    let config = Config::load(Path::new(CONFIG_PATH)).map_err(|error| InstallError::Config {
        detail: error.to_string(),
    })?;
    if !answers_within(&config, ANSWER_WAIT) {
        return Err(InstallError::NotAnswering);
    }
    let mut changed = Vec::new();
    for service in network_services()? {
        run(NETWORKSETUP, &["-setdnsservers", &service, "127.0.0.1"])?;
        changed.push(service);
    }
    Ok(changed)
}

/// Returns every network service that points at the gatekeeper to automatic DNS. Returns the
/// services changed; services configured with other resolvers are left alone.
pub fn off() -> Result<Vec<String>, InstallError> {
    require_root()?;
    let mut restored = Vec::new();
    for service in network_services()? {
        let servers = run(NETWORKSETUP, &["-getdnsservers", &service])?;
        if points_at_gatekeeper(&servers) {
            run(NETWORKSETUP, &["-setdnsservers", &service, "empty"])?;
            restored.push(service);
        }
    }
    Ok(restored)
}

/// Switches DNS back to automatic, stops and removes both launchd jobs, the updater and the
/// program. The configuration, lists, journal and the `_phylode` account are left in place:
/// that is the user's data. Returns the services whose DNS was restored.
pub fn uninstall() -> Result<Vec<String>, InstallError> {
    // DNS goes first: once the service stops, a Mac still pointing at it resolves nothing.
    let restored = off()?;
    bootout(GATEKEEPER_LABEL);
    bootout(UPDATE_LABEL);
    for path in [
        GATEKEEPER_PLIST_PATH,
        UPDATE_PLIST_PATH,
        UPDATE_SCRIPT_PATH,
        BINARY_PATH,
    ] {
        remove_if_present(Path::new(path))?;
    }
    Ok(restored)
}

/// What `uninstall` leaves behind, and the commands to remove it.
pub fn leftovers_message() -> String {
    format!(
        "Your data was deliberately left in place:\n  \
         configuration: {CONFIG_PATH}\n  lists:         {ETC_DIR}/\n  journal:       {LOG_DIR}/\n\
         Delete it yourself once you are sure:\n  \
         sudo rm -rf {ETC_DIR} {CONFIG_PATH} {LOG_DIR}\n\
         The {SERVICE_USER} account is also left behind. To remove it:\n  \
         sudo dscl . -delete /Users/{SERVICE_USER}\n  \
         sudo dscl . -delete /Groups/{SERVICE_USER}"
    )
}

fn step(text: &str) {
    println!("==> {text}");
}

fn require_root() -> Result<(), InstallError> {
    if run("/usr/bin/id", &["-u"])?.trim() == "0" {
        Ok(())
    } else {
        Err(InstallError::NotRoot)
    }
}

/// Fails unless `dir` (or, if it does not exist yet, the nearest folder above it) and every
/// folder above that can only be changed by root or an administrator. Administrators can
/// become root anyway, so only a standard account being able to write there is a risk.
///
/// What breaks if you change it: without this, a standard account that can write to, say,
/// `/usr/local/bin` swaps in its own program and the next `sudo phylode` runs it as root.
fn require_only_administrators_can_change(dir: &Path, admin_gid: u32) -> Result<(), InstallError> {
    use std::os::unix::fs::MetadataExt;

    let existing = dir
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or(Path::new("/"));
    let real = fs::canonicalize(existing).map_err(|source| io_error(existing, source))?;
    for folder in real.ancestors() {
        let meta = fs::metadata(folder).map_err(|source| io_error(folder, source))?;
        let safe = match writers(meta.uid(), meta.gid(), meta.mode(), admin_gid) {
            Writers::RootOrAdministrators => true,
            Writers::Owner(uid) => is_administrator(uid)?,
            Writers::Anyone => false,
        };
        if !safe {
            return Err(InstallError::UnprotectedDirectory {
                path: folder.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Who, besides root, can change a folder with this owner, group and mode.
#[derive(Debug, PartialEq, Eq)]
enum Writers {
    RootOrAdministrators,
    /// Root, administrators, and this owner, who may or may not be an administrator.
    Owner(u32),
    /// Every account, or a group other than wheel and admin.
    Anyone,
}

fn writers(uid: u32, gid: u32, mode: u32, admin_gid: u32) -> Writers {
    let group_writable = mode & 0o020 != 0;
    let world_writable = mode & 0o002 != 0;
    if world_writable || (group_writable && gid != 0 && gid != admin_gid) {
        Writers::Anyone
    } else if uid == 0 {
        Writers::RootOrAdministrators
    } else {
        Writers::Owner(uid)
    }
}

fn is_administrator(uid: u32) -> Result<bool, InstallError> {
    let answer = run(
        "/usr/bin/dsmemberutil",
        &["checkmembership", "-u", &uid.to_string(), "-G", "admin"],
    )?;
    Ok(answer.trim() == "user is a member of the group")
}

/// Runs a program and returns its standard output; a non-zero exit is an error carrying the
/// program's own message.
fn run(program: &str, args: &[&str]) -> Result<String, InstallError> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| InstallError::Spawn {
            program: program.to_string(),
            source,
        })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(InstallError::Failed {
            command: format!("{program} {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn ensure_service_user() -> Result<(), InstallError> {
    let record = format!("/Users/{SERVICE_USER}");
    if run(DSCL, &[".", "-read", &record]).is_ok() {
        println!("    already exists");
        return Ok(());
    }
    let users = run(DSCL, &[".", "-list", "/Users", "UniqueID"])?;
    let groups = run(DSCL, &[".", "-list", "/Groups", "PrimaryGroupID"])?;
    let id = next_system_id(&users, &groups)
        .ok_or(InstallError::NoFreeId)?
        .to_string();
    let group = format!("/Groups/{SERVICE_USER}");
    for args in [
        vec![".", "-create", &record],
        vec![".", "-create", &record, "UserShell", "/usr/bin/false"],
        vec![".", "-create", &record, "RealName", "Phylode Gatekeeper"],
        vec![".", "-create", &record, "UniqueID", &id],
        vec![".", "-create", &record, "PrimaryGroupID", &id],
        vec![".", "-create", &record, "NFSHomeDirectory", "/var/empty"],
        vec![".", "-create", &group, "PrimaryGroupID", &id],
    ] {
        run(DSCL, &args)?;
    }
    println!("    created with ID {id}");
    Ok(())
}

/// One past the highest ID below 500 used by any account or group, so the same number is free
/// for both. `None` when that would reach 500, where ordinary user accounts start.
fn next_system_id(users: &str, groups: &str) -> Option<u32> {
    users
        .lines()
        .chain(groups.lines())
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u32>().ok())
        .filter(|&id| id < 500)
        .max()
        .map(|highest| highest + 1)
        .filter(|&id| id < 500)
}

/// Reads a numeric attribute such as `UniqueID` from a directory service record.
fn directory_id(record: &str, attribute: &str) -> Result<u32, InstallError> {
    run(DSCL, &[".", "-read", record, attribute])?
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| InstallError::UnknownId {
            record: record.to_string(),
        })
}

fn install_binary() -> Result<(), InstallError> {
    let target = Path::new(BINARY_PATH);
    let current = std::env::current_exe().map_err(|source| InstallError::Io {
        path: target.to_path_buf(),
        source,
    })?;
    // Reinstalling from the installed copy would otherwise truncate the file being copied.
    let same_file = fs::canonicalize(&current).ok() == fs::canonicalize(target).ok();
    if !same_file {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        }
        fs::copy(&current, target).map_err(|source| io_error(target, source))?;
    }
    set_owner_and_mode(target, 0o755, 0, 0)
}

fn write_file(
    path: &Path,
    contents: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    fs::write(path, contents).map_err(|source| io_error(path, source))?;
    set_owner_and_mode(path, mode, uid, gid)
}

fn make_dir(path: &Path, mode: u32, uid: u32, gid: u32) -> Result<(), InstallError> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
    set_owner_and_mode(path, mode, uid, gid)
}

fn set_owner_and_mode(path: &Path, mode: u32, uid: u32, gid: u32) -> Result<(), InstallError> {
    chown(path, Some(uid), Some(gid)).map_err(|source| io_error(path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error(path, source))
}

fn remove_if_present(path: &Path) -> Result<(), InstallError> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(io_error(path, error)),
        _ => Ok(()),
    }
}

fn io_error(path: &Path, source: std::io::Error) -> InstallError {
    InstallError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Stops a launchd job and loads it again from its plist.
fn reload(label: &str, plist: &str) -> Result<(), InstallError> {
    bootout(label);
    run(LAUNCHCTL, &["bootstrap", "system", plist]).map(|_| ())
}

/// Stops and unloads a launchd job. A job that is not loaded is already in the wanted state,
/// so that failure is not reported.
fn bootout(label: &str) {
    if run(LAUNCHCTL, &["bootout", &format!("system/{label}")]).is_err() {
        println!("    {label} was not running");
    }
}

/// Polls `ready` once a second until it holds or `limit` passes.
fn wait_for(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if ready() {
            return true;
        }
        if start.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Whether the service log gained a line containing `marker` after byte `start`.
fn logged_since(start: u64, marker: &str) -> bool {
    fs::read(SERVICE_LOG).is_ok_and(|bytes| {
        let start = usize::try_from(start)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        String::from_utf8_lossy(&bytes[start..]).contains(marker)
    })
}

/// Whether the service answers a health-check query on its first listen address, probing
/// once a second until `limit` passes (a zero limit probes once). The health-check name is
/// answered locally, so this works offline.
pub fn answers_within(config: &Config, limit: Duration) -> bool {
    let Some(target) = config.listen().first().map(|addr| reachable(*addr)) else {
        return false;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    wait_for(limit, || {
        runtime
            .block_on(self_probe(target, PROBE_NAME, Duration::from_secs(1)))
            .is_ok()
    })
}

/// A wildcard listen address is not a destination; send to loopback instead. Same rule as
/// `dns::Listener::probe_target`, which works from the bound socket rather than the config.
fn reachable(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

/// The names of this Mac's network services.
fn network_services() -> Result<Vec<String>, InstallError> {
    Ok(parse_network_services(&run(
        NETWORKSETUP,
        &["-listallnetworkservices"],
    )?))
}

/// Parses `networksetup -listallnetworkservices`: the first line is a notice, a leading `*`
/// marks a disabled service, and names may contain spaces.
fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .map(|line| line.strip_prefix('*').unwrap_or(line).trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Whether `networksetup -getdnsservers` output lists exactly the gatekeeper.
fn points_at_gatekeeper(servers: &str) -> bool {
    servers.trim() == "127.0.0.1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_next_id_is_free_for_both_accounts_and_groups() {
        let users = "_www 70\n_phylodeish 250\nroot 0\njohn 501\n";
        let groups = "admin 80\n_something 260\nstaff 20\n";
        assert_eq!(next_system_id(users, groups), Some(261));
    }

    /// Should change: a folder any account, or an unrelated group, can write is refused, and
    /// one owned by an ordinary account needs that account checked.
    /// Should not change: root-owned folders, including admin-group-writable ones such as
    /// the list folder install itself creates, pass without a lookup.
    #[test]
    fn only_root_and_administrators_may_be_able_to_change_an_install_folder() {
        let admin = 80;
        assert_eq!(writers(0, 0, 0o755, admin), Writers::RootOrAdministrators);
        assert_eq!(
            writers(0, admin, 0o775, admin),
            Writers::RootOrAdministrators
        );
        assert_eq!(writers(501, 20, 0o755, admin), Writers::Owner(501));
        assert_eq!(writers(0, 0, 0o777, admin), Writers::Anyone);
        assert_eq!(writers(0, 20, 0o775, admin), Writers::Anyone);
    }

    #[test]
    fn no_id_is_offered_once_the_system_range_is_full() {
        assert_eq!(next_system_id("_last 499\n", ""), None);
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

    #[test]
    fn a_wildcard_listen_address_is_probed_on_loopback() {
        let wildcard: SocketAddr = "0.0.0.0:53".parse().unwrap();
        assert_eq!(reachable(wildcard), "127.0.0.1:53".parse().unwrap());
        let specific: SocketAddr = "192.0.2.10:53".parse().unwrap();
        assert_eq!(reachable(specific), specific);
    }

    #[test]
    fn the_embedded_plists_run_what_install_puts_in_place() {
        // Each file looks fine on its own; if a path disagrees, launchd starts nothing and
        // reports it only in the system log.
        assert!(GATEKEEPER_PLIST.contains(&format!("<string>{BINARY_PATH}</string>")));
        assert!(GATEKEEPER_PLIST.contains(&format!("<string>{CONFIG_PATH}</string>")));
        assert!(GATEKEEPER_PLIST.contains(&format!("<string>{GATEKEEPER_LABEL}</string>")));
        assert!(UPDATE_PLIST.contains(&format!("<string>{UPDATE_SCRIPT_PATH}</string>")));
        assert!(UPDATE_PLIST.contains(&format!("<string>{UPDATE_LABEL}</string>")));
        assert!(UPDATE_SCRIPT.contains(LISTS_DIR));
        assert!(GATEKEEPER_PLIST.contains(&format!("<string>{SERVICE_LOG}</string>")));
        for plist in [GATEKEEPER_PLIST, UPDATE_PLIST] {
            assert!(plist.contains(&format!("<string>{SERVICE_USER}</string>")));
            assert!(plist.contains(&format!("<string>{LOG_DIR}/")));
        }
    }

    #[test]
    fn the_embedded_default_configuration_parses() {
        let dir = std::env::temp_dir().join(format!("phylode-install-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phylode.conf");
        fs::write(&path, DEFAULT_CONFIG).unwrap();
        let config = Config::load(&path).expect("the default configuration must load");
        assert_eq!(config.blocklists().len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }
}
