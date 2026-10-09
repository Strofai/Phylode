//! Sets Phylode up as a boot service on this Mac and removes it again, and points the Mac's
//! DNS at it: `phylode install`, `on`, `off` and `uninstall`, each run with sudo.
//!
//! What breaks if you change it: the two plists, the daily list updater and the default
//! configuration are compiled in from `deploy/`, and the paths they contain must match the
//! constants below. `tests/deploy_contract.rs` checks the files agree with each other.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown, lchown};
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
const NEWSYSLOG_PATH: &str = "/etc/newsyslog.d/phylode.conf";
const BINARY_PATH: &str = "/usr/local/bin/phylode";
const ETC_DIR: &str = "/usr/local/etc/phylode";
const LISTS_DIR: &str = "/usr/local/etc/phylode/lists";
const LOG_DIR: &str = "/var/log/phylode";
/// The logs launchd writes for the two jobs (`StandardOutPath`, `StandardErrorPath`), which
/// newsyslog rotates as root. Created by `install` and handed to the service account.
const SERVICE_LOGS: [&str; 3] = [
    SERVICE_LOG,
    "/var/log/phylode/stdout.log",
    "/var/log/phylode/update.log",
];
/// The default `journal_dir` in `deploy/phylode.conf`; the only folder under [`LOG_DIR`] the
/// service account can write in.
const JOURNAL_DIR: &str = "/var/log/phylode/queries";

const GATEKEEPER_PLIST: &str = include_str!("../../deploy/com.Phylode.gatekeeper.plist");
const UPDATE_PLIST: &str = include_str!("../../deploy/com.Phylode.blocklist-update.plist");
const UPDATE_SCRIPT: &str = include_str!("../../deploy/update-blocklists.sh");
const DEFAULT_CONFIG: &str = include_str!("../../deploy/phylode.conf");
const NEWSYSLOG_CONFIG: &str = include_str!("../../deploy/phylode.newsyslog.conf");

/// How long `install` waits for the first list download before starting the service anyway.
/// Both lists normally arrive in a few seconds; a slow network should not block installing.
const LIST_WAIT: Duration = Duration::from_secs(120);
/// How long `install` and `on` wait for the service to answer.
const ANSWER_WAIT: Duration = Duration::from_secs(15);
/// How long `install` waits for the service to finish loading the lists after it answers.
const LOAD_WAIT: Duration = Duration::from_secs(60);
/// How long `install` and `uninstall` wait for launchd to unload a job. launchd gives a job
/// 20 seconds to exit after SIGTERM (`ExitTimeOut`), so this allows for that.
const BOOTOUT_WAIT: Duration = Duration::from_secs(25);

/// The line the service writes to its log once the blocklist is in memory. `install` watches
/// for it. What breaks if you change it: the service prints this constant, so the two stay in
/// step; a log line written some other way would never be seen.
pub const BLOCKLIST_LOADED: &str = "Blocklist loaded";
/// The service's error log, as set by `StandardErrorPath` in the gatekeeper plist.
pub const SERVICE_LOG: &str = "/var/log/phylode/stderr.log";

const DSCL: &str = "/usr/bin/dscl";
const LAUNCHCTL: &str = "/bin/launchctl";
const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
const LSOF: &str = "/usr/sbin/lsof";
/// launchd's process ID. It holds the sockets it binds for a job as long as the job is loaded.
const LAUNCHD_PID: u32 = 1;

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
    #[error("`{command}` failed: {detail}")]
    Failed { command: String, detail: String },
    #[error("could not access {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "every system account ID from 400 to 499 is taken, so the {SERVICE_USER} account cannot be \
         created; create it by hand with dscl and run install again"
    )]
    NoFreeId,
    #[error("could not read the numeric ID of {record} from the directory service")]
    UnknownId { record: String },
    #[error("the configuration {CONFIG_PATH} cannot be used: {detail}")]
    Config { detail: String },
    #[error(
        "the service is installed but did not answer within {} seconds; see {SERVICE_LOG}",
        ANSWER_WAIT.as_secs()
    )]
    NotAnswering,
    #[error(
        "{path} can be changed by an account that is not an administrator, which could then \
         replace what install puts there and have it run as root or as the service. Nothing \
         was installed. Make the folder writable only by root or an administrator (`ls -lde \
         {path}` shows its owner, mode and any access control entries), then try again"
    )]
    UnprotectedDirectory { path: PathBuf },
    #[error(
        "DNS could not be changed on every network service. Changed: {changed}. Not changed: \
         {failed}. Run the same command again once that is fixed"
    )]
    SomeServices { changed: String, failed: String },
    #[error(
        "launchd still has {label} loaded, so it was left as it was; check it with `sudo launchctl \
         print system/{label}` and run the same command again"
    )]
    StillLoaded { label: String },
    #[error(
        "port {port} is held by {holders}, not only by Phylode, so another program could be \
         answering lookups in its place. Run `sudo phylode off` so this Mac stops sending its \
         lookups there, stop that program, then run `sudo phylode install` again"
    )]
    PortTaken { port: u16, holders: String },
}

/// The folders `install` writes into as root, whose contents the boot service or `sudo
/// phylode` later run. Adding a path to the constants above means adding its folder here.
const PROTECTED_DIRS: [&str; 6] = [
    "/etc/newsyslog.d",
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

    step("Letting other devices reach it through the macOS firewall");
    allow_through_firewall()?;

    step(&format!("Preparing the journal directory {LOG_DIR}"));
    prepare_log_dir(service_uid, admin_gid)?;
    // macOS newsyslog keeps the service logs from growing without end.
    write_file(Path::new(NEWSYSLOG_PATH), NEWSYSLOG_CONFIG, 0o644, 0, 0)?;

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
            "    Warning: the lists are still downloading; the service starts now and begins blocking \
             as soon as they arrive"
        );
    }

    step("Starting the boot service");
    // Only lines the new process appends count; an earlier run's log is still in the file.
    let log_start = fs::metadata(SERVICE_LOG).map_or(0, |meta| meta.len());
    let plist_unchanged = is_loaded(GATEKEEPER_LABEL)
        && fs::read_to_string(GATEKEEPER_PLIST_PATH).is_ok_and(|now| now == GATEKEEPER_PLIST);
    if plist_unchanged {
        // launchd keeps holding port 53 while the program restarts, so the port is never free
        // for another program to take.
        run(
            LAUNCHCTL,
            &["kickstart", "-k", &format!("system/{GATEKEEPER_LABEL}")],
        )?;
    } else {
        write_file(
            Path::new(GATEKEEPER_PLIST_PATH),
            GATEKEEPER_PLIST,
            0o644,
            0,
            0,
        )?;
        reload(GATEKEEPER_LABEL, GATEKEEPER_PLIST_PATH)?;
    }

    step("Checking that it answers and has loaded the lists");
    if !answers_within(&config, ANSWER_WAIT) {
        return Err(InstallError::NotAnswering);
    }
    ensure_phylode_holds_port(&config)?;
    if wait_for(LOAD_WAIT, || logged_since(log_start, BLOCKLIST_LOADED)) {
        println!("    answering and blocking");
    } else {
        println!(
            "    Warning: Phylode is answering, but the lists are not loaded yet; it allows everything until they \
             are — check with: phylode status"
        );
    }
    println!();
    println!("Installed. This Mac is not using it yet; to switch it on:");
    println!("  sudo phylode on");
    Ok(())
}

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

/// Switches DNS back to automatic, stops and removes both launchd jobs, the updater and the
/// program. The configuration, lists, journal and the `_phylode` account are left in place:
/// that is the user's data. Returns the services whose DNS was restored.
pub fn uninstall() -> Result<Vec<String>, InstallError> {
    // DNS goes first: once the service stops, a Mac still pointing at it resolves nothing.
    let restored = off()?;
    // Files go only once both jobs are gone. What breaks if you change it: deleting the plists
    // of a job launchd still has loaded leaves a running service nothing can manage any more.
    for label in [GATEKEEPER_LABEL, UPDATE_LABEL] {
        unload(label)?;
    }
    // Not an error when it was never added (the firewall was set up by hand, say).
    let _ = run(SOCKETFILTERFW, &["--remove", BINARY_PATH]);
    for path in [
        GATEKEEPER_PLIST_PATH,
        UPDATE_PLIST_PATH,
        UPDATE_SCRIPT_PATH,
        NEWSYSLOG_PATH,
        BINARY_PATH,
    ] {
        remove_if_present(Path::new(path))?;
        remove_if_present(&staged_path(Path::new(path)))?;
    }
    // Left behind only by an install that stopped between copying and renaming.
    remove_if_present(&Path::new(BINARY_PATH).with_extension("new"))?;
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

/// Whether this process runs with root's effective user ID. False when that cannot be told.
pub fn running_as_root() -> bool {
    run("/usr/bin/id", &["-u"]).is_ok_and(|uid| uid.trim() == "0")
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
    for folder in folders_to_check(existing)? {
        let folder = folder.as_path();
        let meta = fs::metadata(folder).map_err(|source| io_error(folder, source))?;
        let safe =
            match writers(meta.uid(), meta.gid(), meta.mode(), admin_gid) {
                Writers::RootOrAdministrators => true,
                Writers::Owner(uid) => is_administrator(uid)?,
                Writers::Anyone => false,
            } && !acl_lets_others_write(&run("/bin/ls", &["-lde", &folder.to_string_lossy()])?);
        if !safe {
            return Err(InstallError::UnprotectedDirectory {
                path: folder.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Every folder whose writers decide what ends up at `path`: its ancestors as written and
/// the ancestors of the folder it resolves to, each once.
///
/// What breaks if you change it: checking only the resolved folder misses a symbolic link
/// along the written path — whoever can change the folder holding that link can point it
/// somewhere protected for the check, then back at their own folder afterwards.
fn folders_to_check(path: &Path) -> Result<std::collections::BTreeSet<PathBuf>, InstallError> {
    let real = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    Ok(path
        .ancestors()
        .chain(real.ancestors())
        .map(Path::to_path_buf)
        .collect())
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

/// Accounts an access control entry may grant change rights to without making a folder unsafe.
const ACL_TRUSTED: [&str; 3] = ["user:root", "group:wheel", "group:admin"];

/// Access control rights that change a folder or what is in it, as `ls -le` names them.
const ACL_WRITE_RIGHTS: [&str; 10] = [
    "write",
    "append",
    "add_file",
    "add_subdirectory",
    "delete",
    "delete_child",
    "writeattr",
    "writeextattr",
    "writesecurity",
    "chown",
];

/// Whether an `ls -lde` listing shows an access control entry that lets an account other than
/// root or an administrator change the folder, or the folders install later creates inside it
/// (entries meant only for those are counted too).
/// What breaks if you change it: the owner, group and mode checks alone miss a macOS access
/// control entry granting a standard account the same rights.
fn acl_lets_others_write(listing: &str) -> bool {
    listing.lines().skip(1).any(|entry| {
        let Some((head, rights)) = entry.trim().rsplit_once(' ') else {
            return false;
        };
        let Some(principal) = head.strip_suffix(" allow") else {
            return false;
        };
        let principal = principal.strip_suffix(" inherited").unwrap_or(principal);
        let principal = principal
            .split_once(": ")
            .map_or(principal, |(_, name)| name);
        !ACL_TRUSTED.contains(&principal)
            && rights
                .split(',')
                .any(|right| ACL_WRITE_RIGHTS.contains(&right))
    })
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
        let said = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(InstallError::Failed {
            command: format!("{program} {}", args.join(" ")),
            detail: if said.is_empty() {
                format!("it stopped with {} and printed no reason", output.status)
            } else {
                said
            },
        })
    }
}

///
/// Creating takes seven `dscl` steps, so it is all or nothing: a step that fails removes what
/// the earlier ones made, and a half-made account left by an older version is removed and made
/// again. What breaks if you change it: count a half-made account as existing and every later
/// install stops at reading its ID, with no way forward but `dscl` by hand.
fn ensure_service_user() -> Result<(), InstallError> {
    let record = format!("/Users/{SERVICE_USER}");
    let group = format!("/Groups/{SERVICE_USER}");
    let complete = directory_id(&record, "UniqueID").is_ok()
        && directory_id(&record, "PrimaryGroupID").is_ok()
        && directory_id(&group, "PrimaryGroupID").is_ok();
    if complete {
        println!("    already exists");
        return Ok(());
    }
    remove_service_user(&record, &group);
    let users = run(DSCL, &[".", "-list", "/Users", "UniqueID"])?;
    let groups = run(DSCL, &[".", "-list", "/Groups", "PrimaryGroupID"])?;
    let id = next_system_id(&users, &groups)
        .ok_or(InstallError::NoFreeId)?
        .to_string();
    let created = create_service_user(&record, &group, &id);
    if created.is_err() {
        remove_service_user(&record, &group);
    }
    created?;
    println!("    created with ID {id}");
    Ok(())
}

/// Deletes whatever exists of the service account and its group; either may be missing.
fn remove_service_user(record: &str, group: &str) {
    for path in [record, group] {
        let _ = run(DSCL, &[".", "-delete", path]);
    }
}

fn create_service_user(record: &str, group: &str, id: &str) -> Result<(), InstallError> {
    for args in [
        vec![".", "-create", record],
        vec![".", "-create", record, "UserShell", "/usr/bin/false"],
        vec![".", "-create", record, "RealName", "Phylode Gatekeeper"],
        vec![".", "-create", record, "UniqueID", id],
        vec![".", "-create", record, "PrimaryGroupID", id],
        vec![".", "-create", record, "NFSHomeDirectory", "/var/empty"],
        vec![".", "-create", group, "PrimaryGroupID", id],
    ] {
        run(DSCL, &args)?;
    }
    Ok(())
}

/// The highest ID below 500 that no account or group uses, so the same number is free for
/// both. `None` when every one from 499 down to 400 is taken.
///
/// What breaks if you change it: Apple adds system accounts upward from the low hundreds, and
/// a macOS update deletes any account holding an ID it wants (macOS 15 took 301–304 from Nix's
/// build accounts). Counting down from 499 keeps as far from that as the system range allows.
fn next_system_id(users: &str, groups: &str) -> Option<u32> {
    let taken: std::collections::HashSet<u32> = users
        .lines()
        .chain(groups.lines())
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u32>().ok())
        .collect();
    (400..500).rev().find(|id| !taken.contains(id))
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

/// Puts this binary at [`BINARY_PATH`] by copying it beside the target and renaming it over.
///
/// What breaks if you change it: copying straight onto the installed file rewrites the
/// executable the running service is mapped from, and macOS kills any process started from it
/// before that service exits (the kernel's cached code signature no longer matches). Renaming
/// gives the new binary its own file, so an update never touches the one in use.
fn install_binary() -> Result<(), InstallError> {
    let target = Path::new(BINARY_PATH);
    let current = std::env::current_exe().map_err(|source| io_error(target, source))?;
    // Reinstalling from the installed copy: it is already in place.
    if fs::canonicalize(&current).ok() == fs::canonicalize(target).ok() {
        return set_owner_and_mode(target, 0o755, 0, 0);
    }
    let staged = target.with_extension("new");
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    }
    fs::copy(&current, &staged).map_err(|source| io_error(&staged, source))?;
    set_owner_and_mode(&staged, 0o755, 0, 0)?;
    fs::rename(&staged, target).map_err(|source| io_error(target, source))
}

/// Registers the installed binary with the macOS application firewall as allowed to accept
/// connections, whether or not the firewall is on right now.
///
/// Why: with the firewall on, macOS asks on screen before an unlisted program accepts a
/// connection from another address, and a Mac serving the network usually has nobody at the
/// screen. The entry is removed and added again because the firewall remembers the binary's
/// signature, which changes with every build.
fn allow_through_firewall() -> Result<(), InstallError> {
    let _ = run(SOCKETFILTERFW, &["--remove", BINARY_PATH]);
    run(SOCKETFILTERFW, &["--add", BINARY_PATH])?;
    run(SOCKETFILTERFW, &["--unblockapp", BINARY_PATH])?;
    Ok(())
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
    // Written beside the target and renamed over it, owner and mode already set. What breaks
    // if you change it: rewritten in place, a list update already running reads the new
    // script from where it had got to in the old one (bash reads as it goes), and launchd or
    // a reader can see a half-written file.
    let staged = staged_path(path);
    remove_if_present(&staged)?;
    fs::write(&staged, contents).map_err(|source| io_error(&staged, source))?;
    set_owner_and_mode(&staged, mode, uid, gid)?;
    fs::rename(&staged, path).map_err(|source| io_error(path, source))
}

/// Where a file is written before it replaces `path`: the same folder, so the rename is
/// atomic.
fn staged_path(path: &Path) -> PathBuf {
    let name = path.file_name().map_or_else(
        || "phylode".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    path.with_file_name(format!("{name}.phylode-new"))
}

/// Makes [`LOG_DIR`] root's, then gives the service account only its logs and the journal
/// folder inside it. Group admin, so `phylode report` needs no sudo; no one else can read the
/// contents, because the journal is a complete browsing history.
///
/// What breaks if you change it: newsyslog renames, compresses and chowns the logs as root,
/// and launchd opens them as root. In a folder the service account can write, that account
/// decides what those names point at — a link to a system file would hand it to the account,
/// turning a compromised service into root (Apple's Secure Coding Guide, "Race Conditions and
/// Secure File Operations": watch out for symbolic links in writable directories).
fn prepare_log_dir(service_uid: u32, admin_gid: u32) -> Result<(), InstallError> {
    // Executable for others so the service account can reach its own entries; it is not in
    // the admin group. Nothing in here is readable to them.
    make_dir(Path::new(LOG_DIR), 0o755, 0, admin_gid)?;
    // From here on only root can add, rename or remove entries, so what is checked below is
    // what gets chowned.
    for log in SERVICE_LOGS {
        let path = Path::new(log);
        clear_unless(path, |meta| meta.is_file() && meta.nlink() == 1)?;
        fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        lchown(path, Some(service_uid), Some(admin_gid))
            .map_err(|source| io_error(path, source))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o640))
            .map_err(|source| io_error(path, source))?;
    }
    let journal = Path::new(JOURNAL_DIR);
    clear_unless(journal, fs::Metadata::is_dir)?;
    make_dir(journal, crate::journal::DIR_MODE, service_uid, admin_gid)
}

/// Removes whatever is at `path` unless it is missing or passes `keep`, which sees the entry
/// itself rather than what a link points at. A link is removed, never followed.
fn clear_unless(path: &Path, keep: impl Fn(&fs::Metadata) -> bool) -> Result<(), InstallError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(path, error)),
    };
    if keep(&meta) {
        return Ok(());
    }
    let removed = if meta.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    removed.map_err(|source| io_error(path, source))
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
    unload(label)?;
    run(LAUNCHCTL, &["bootstrap", "system", plist]).map(|_| ())
}

/// Stops a launchd job and waits until launchd has let go of it.
///
/// What breaks if you change it: `bootout` returns while launchd may still be tearing the job
/// down (a list download finishing, say). Loading it again then fails with "Bootstrap failed:
/// 5: Input/output error", and removing its files leaves a job nothing can manage.
fn unload(label: &str) -> Result<(), InstallError> {
    bootout(label);
    if wait_for(BOOTOUT_WAIT, || !is_loaded(label)) {
        Ok(())
    } else {
        Err(InstallError::StillLoaded {
            label: label.to_string(),
        })
    }
}

/// Stops and unloads a launchd job. A job that is not loaded is already in the wanted state,
/// so that failure is not reported.
fn bootout(label: &str) {
    if run(LAUNCHCTL, &["bootout", &format!("system/{label}")]).is_err() {
        println!("    {label} was not running");
    }
}

/// Whether launchd still has this job loaded.
fn is_loaded(label: &str) -> bool {
    run(LAUNCHCTL, &["print", &format!("system/{label}")]).is_ok()
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

/// Checks that launchd and the Phylode job it started are the only programs holding the
/// service's port. A reply on that port proves nothing by itself: while launchd is not holding
/// it, macOS lets any account bind a port below 1024 on every address.
///
/// What breaks if you change it: check only that something answers, and a program another
/// account left listening receives every lookup this Mac and the network make.
fn ensure_phylode_holds_port(config: &Config) -> Result<(), InstallError> {
    let port = config.listen().first().map_or(53, SocketAddr::port);
    let job = run(LAUNCHCTL, &["print", &format!("system/{GATEKEEPER_LABEL}")])
        .ok()
        .and_then(|printed| job_pid(&printed));
    let listing = list_port(port)?;
    others_on_port(&holders(&listing, port), job)
        .map_err(|holders| InstallError::PortTaken { port, holders })
}

/// `lsof` output for every socket on `port`, as process, command and address fields. Empty when
/// nothing holds it.
fn list_port(port: u16) -> Result<String, InstallError> {
    let args = [
        "-nP".to_string(),
        format!("-iUDP:{port}"),
        format!("-iTCP:{port}"),
        "-F".to_string(),
        "pcn".to_string(),
    ];
    let output = Command::new(LSOF)
        .args(&args)
        .output()
        .map_err(|source| InstallError::Spawn {
            program: LSOF.to_string(),
            source,
        })?;
    // lsof also exits unsuccessfully when nothing matches; only then is standard error empty.
    if output.status.success() || output.stderr.is_empty() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(InstallError::Failed {
            command: format!("{LSOF} {}", args.join(" ")),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// The process ID in `launchctl print` output for a running job. `None` while it is not running.
fn job_pid(printed: &str) -> Option<u32> {
    printed
        .lines()
        .find_map(|line| line.strip_prefix("\tpid = "))
        .and_then(|pid| pid.trim().parse().ok())
}

/// Each process in `lsof -F pcn` output with a socket whose own end is `port`: one listening
/// there, or one that accepted a connection there. A connection this Mac made to another
/// machine's port does not count.
fn holders(listing: &str, port: u16) -> Vec<(u32, String)> {
    let own_end = format!(":{port}");
    let mut found: Vec<(u32, String)> = Vec::new();
    let mut process: Option<u32> = None;
    let mut command = String::new();
    for line in listing.lines() {
        match line.split_at_checked(1) {
            Some(("p", pid)) => {
                process = pid.parse().ok();
                command.clear();
            }
            Some(("c", name)) => command = name.to_string(),
            Some(("n", address)) => {
                let local = address.split("->").next().unwrap_or(address);
                if let Some(pid) = process
                    && local.ends_with(&own_end)
                    && !found.iter().any(|(seen, _)| *seen == pid)
                {
                    found.push((pid, command.clone()));
                }
            }
            _ => {}
        }
    }
    found
}

/// `Ok` when `job` is among the holders and everyone else is launchd; otherwise names who
/// else holds the port.
fn others_on_port(holders: &[(u32, String)], job: Option<u32>) -> Result<(), String> {
    let others: Vec<String> = holders
        .iter()
        .filter(|(pid, _)| *pid != LAUNCHD_PID && Some(*pid) != job)
        .map(|(pid, command)| format!("{command} (process {pid})"))
        .collect();
    let ours = job.is_some_and(|job| holders.iter().any(|(pid, _)| *pid == job));
    match (others.is_empty(), ours) {
        (true, true) => Ok(()),
        (true, false) => Err("no program Phylode started".to_string()),
        (false, _) => Err(others.join(", ")),
    }
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

    /// `lsof -nP -iUDP:53 -iTCP:53 -F pcn` as root, on a Mac where launchd and Phylode hold
    /// port 53, mDNSResponder has asked the router something, and another account's program
    /// sits on 127.0.0.1:53.
    const LISTING: &str = "p1\nclaunchd\nf20\nn*:53\nf21\nn*:53\n\
                           p412\ncphylode\nf3\nn*:53\nf4\nn*:53\nf9\nn[::1]:53->[::1]:61022\n\
                           p300\ncmDNSResponder\nf9\nn192.168.0.192:61000->192.168.0.1:53\n\
                           p900\ncimpostor\nf3\nn127.0.0.1:53\n";

    /// Should change: every process with its own end on the port is found, once each.
    /// Should not change: a connection this Mac made to another machine's port 53 is not
    /// holding it, and port 53 does not match 153 or 5353.
    #[test]
    fn the_programs_holding_a_port_are_read_from_lsof() {
        let found: Vec<u32> = holders(LISTING, 53)
            .into_iter()
            .map(|(pid, _)| pid)
            .collect();
        assert_eq!(found, [1, 412, 900]);
        assert_eq!(holders(LISTING, 53)[2].1, "impostor");
        assert!(holders("p7\ncx\nf1\nn*:153\nf2\nn*:5353\n", 53).is_empty());
        assert!(holders("", 53).is_empty());
    }

    #[test]
    fn a_running_jobs_process_id_is_read_from_launchctl() {
        let printed = "system/com.Phylode.gatekeeper = {\n\tactive count = 1\n\tstate = running\n\
                       \tpid = 412\n\tsockets = {\n\t\tpid = 9\n\t}\n}\n";
        assert_eq!(job_pid(printed), Some(412));
        assert_eq!(job_pid("system/x = {\n\tstate = not running\n}\n"), None);
    }

    /// Should change: anyone besides launchd and the job holding the port is named, and so is
    /// a port the job does not hold at all.
    /// Should not change: launchd and the job together are fine.
    #[test]
    fn only_launchd_and_the_job_may_hold_the_port() {
        let ours = [(1, "launchd".to_string()), (412, "phylode".to_string())];
        assert_eq!(others_on_port(&ours, Some(412)), Ok(()));

        let taken = holders(LISTING, 53);
        assert_eq!(
            others_on_port(&taken, Some(412)),
            Err("impostor (process 900)".to_string())
        );

        let squatter = [(900, "impostor".to_string())];
        assert_eq!(
            others_on_port(&squatter, None),
            Err("impostor (process 900)".to_string())
        );
        assert_eq!(
            others_on_port(&[(1, "launchd".to_string())], Some(412)),
            Err("no program Phylode started".to_string())
        );
    }

    /// Should change: what `networksetup -getdnsservers` printed becomes addresses, or
    /// `empty` for its "none set" sentence; a saved file round-trips.
    /// Should not change: anything that is not an address is never kept, so a tampered file
    /// cannot slip other arguments to `networksetup`.
    /// Should change: a file being replaced is swapped for a new one, so whoever already has
    /// the old one open (bash running the updater) keeps reading the old contents whole.
    /// Should not change: the path ends up with the new contents and the requested mode, and
    /// nothing is left beside it.
    #[test]
    fn a_replaced_file_is_swapped_not_rewritten_in_place() {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;

        let dir = std::env::temp_dir().join(format!("phylode-swap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phylode-update-lists");
        std::fs::write(&path, "old script\n").unwrap();
        let mut reader = std::fs::File::open(&path).unwrap();
        let me = std::fs::metadata(&dir).unwrap();

        write_file(&path, "new script\n", 0o755, me.uid(), me.gid()).unwrap();

        let mut seen = String::new();
        reader.read_to_string(&mut seen).unwrap();
        assert_eq!(seen, "old script\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new script\n");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o755);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn the_next_id_is_free_for_both_accounts_and_groups() {
        let users = "_www 70\n_modelmanagerd 301\n_taken 499\nroot 0\njohn 501\n";
        let groups = "admin 80\n_also 498\nstaff 20\n";
        assert_eq!(next_system_id(users, groups), Some(497));
    }

    /// Should change: the folder holding a symbolic link on the written path is checked, not
    /// only the folder the link resolves to.
    /// Should not change: the resolved folder and its ancestors are still checked.
    #[test]
    fn the_folder_holding_a_link_on_the_path_is_checked_too() {
        let base = std::env::temp_dir().join(format!("phylode-link-{}", std::process::id()));
        let holder = base.join("holder");
        let target = base.join("target");
        fs::create_dir_all(&holder).unwrap();
        fs::create_dir_all(&target).unwrap();
        let link = holder.join("bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let folders = folders_to_check(&link).unwrap();
        assert!(folders.contains(&holder), "the folder holding the link");
        let real_target = fs::canonicalize(&target).unwrap();
        assert!(
            folders.contains(&real_target),
            "the folder the link resolves to"
        );
        assert!(folders.contains(real_target.parent().unwrap()));
        assert!(folders.contains(Path::new("/")));
        let _ = fs::remove_dir_all(&base);
    }

    /// Should change: an access control entry granting a standard account or group change
    /// rights is caught, including one inherited or meant only for folders created inside.
    /// Should not change: no entries, deny entries, read-only grants, and grants to root or
    /// the admin group pass. Listings follow the format `ls -lde` prints on macOS.
    #[test]
    fn access_control_entries_that_let_others_write_are_caught() {
        let header = "drwxr-xr-x  3 root  wheel  96 Aug  8 15:25 /usr/local/bin\n";
        let with = |entries: &str| format!("{header}{entries}");

        for unsafe_entries in [
            " 0: group:staff allow add_file,add_subdirectory,delete_child\n",
            " 0: group:everyone deny delete\n 1: user:alex allow write\n",
            " 0: group:staff inherited allow add_file\n",
            " 0: group:everyone allow add_file,directory_inherit,only_inherit\n",
        ] {
            assert!(
                acl_lets_others_write(&with(unsafe_entries)),
                "{unsafe_entries}"
            );
        }
        for safe_entries in [
            "",
            " 0: group:everyone deny delete\n",
            " 0: group:staff allow list,search,readattr,readextattr,readsecurity\n",
            " 0: group:admin allow add_file,add_subdirectory,delete_child\n",
        ] {
            assert!(
                !acl_lets_others_write(&with(safe_entries)),
                "{safe_entries}"
            );
        }
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
        let full: String = (400..500).map(|id| format!("_a{id} {id}\n")).collect();
        assert_eq!(next_system_id(&full, ""), None);
        assert_eq!(next_system_id("", ""), Some(499));
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

    /// Every log launchd opens or newsyslog rotates is one `install` hands to the service
    /// account, and the journal is where the default configuration puts it. A log missing
    /// from the list would be created by launchd in a folder the account cannot write.
    #[test]
    fn install_prepares_every_log_the_jobs_write() {
        let mut named: Vec<&str> = [GATEKEEPER_PLIST, UPDATE_PLIST, NEWSYSLOG_CONFIG]
            .iter()
            .flat_map(|text| text.split(['<', '>', ' ', '\n']))
            .filter(|word| word.starts_with(LOG_DIR) && word.ends_with(".log"))
            .collect();
        named.sort_unstable();
        named.dedup();
        let mut prepared = SERVICE_LOGS.to_vec();
        prepared.sort_unstable();
        assert_eq!(named, prepared);
        assert!(DEFAULT_CONFIG.contains(&format!("journal_dir = {JOURNAL_DIR}\n")));
    }

    /// Should change: a link or a second hard link in a log's place is removed, and what it
    /// pointed at is left alone. Should not change: a plain log and a real folder are kept.
    #[test]
    fn a_planted_entry_is_removed_rather_than_followed() {
        let dir = std::env::temp_dir().join(format!("phylode-logs-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("system-file");
        fs::write(&target, "keep").unwrap();
        let regular = |meta: &fs::Metadata| meta.is_file() && meta.nlink() == 1;

        let link = dir.join("stderr.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        clear_unless(&link, regular).unwrap();
        assert!(fs::symlink_metadata(&link).is_err());

        let hard = dir.join("stdout.log");
        fs::hard_link(&target, &hard).unwrap();
        clear_unless(&hard, regular).unwrap();
        assert!(fs::symlink_metadata(&hard).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");

        let log = dir.join("update.log");
        fs::write(&log, "line\n").unwrap();
        clear_unless(&log, regular).unwrap();
        assert_eq!(fs::read_to_string(&log).unwrap(), "line\n");

        let journal = dir.join("queries");
        fs::create_dir(&journal).unwrap();
        clear_unless(&journal, fs::Metadata::is_dir).unwrap();
        assert!(journal.is_dir());

        fs::remove_dir_all(&dir).unwrap();
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
