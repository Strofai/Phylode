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
use crate::journal;
use crate::report::archive;

mod account;
mod permissions;
mod port;
mod switch;

use account::{directory_id, ensure_service_user};
use permissions::require_only_administrators_can_change;
use port::ensure_phylode_holds_port;

pub use switch::{SwitchedOn, network_address, off, on, this_mac_uses_it};

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

const LAUNCHCTL: &str = "/bin/launchctl";
const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

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
        out_line!("    lists downloaded");
    } else {
        out_line!(
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
        out_line!("    answering and blocking");
    } else {
        out_line!(
            "    Warning: Phylode is answering, but the lists are not loaded yet; it allows everything until they \
             are — check with: phylode status"
        );
    }
    out_line!();
    out_line!("Installed. This Mac is not using it yet; to switch it on:");
    out_line!("  sudo phylode on");
    Ok(())
}

/// Deletes every recorded lookup and every saved weekly summary, then restarts the service so
/// it starts today's file afresh; launchd holds port 53 throughout, so lookups keep being
/// answered. The service's events stay: they hold no lookups. Returns how many files went.
///
/// What breaks if you change it: restart before deleting and the new process writes into
/// today's file just before it is deleted, losing the rest of the day's lookups.
pub fn forget() -> Result<usize, InstallError> {
    require_root()?;
    let config = Config::load(Path::new(CONFIG_PATH)).map_err(|error| InstallError::Config {
        detail: error.to_string(),
    })?;
    let journal_dir = config.journal_dir();
    let lookups = files_in(journal_dir, |name| journal::queries_day(name).is_some())?;
    let summaries = files_in(&journal_dir.join(archive::ARCHIVE_DIR), |name| {
        name.ends_with(".txt")
    })?;
    for path in lookups.iter().chain(&summaries) {
        fs::remove_file(path).map_err(|source| InstallError::Io {
            path: path.clone(),
            source,
        })?;
    }
    if is_loaded(GATEKEEPER_LABEL) {
        run(
            LAUNCHCTL,
            &["kickstart", "-k", &format!("system/{GATEKEEPER_LABEL}")],
        )?;
    }
    Ok(lookups.len() + summaries.len())
}

/// The files directly in `directory` whose names `wanted` accepts. A folder that does not
/// exist holds none.
fn files_in(directory: &Path, wanted: impl Fn(&str) -> bool) -> Result<Vec<PathBuf>, InstallError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(InstallError::Io {
                path: directory.to_path_buf(),
                source,
            });
        }
    };
    Ok(entries
        .flatten()
        .filter(|entry| entry.file_name().to_str().is_some_and(&wanted))
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect())
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
    out_line!("==> {text}");
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
        out_line!("    {label} was not running");
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

#[cfg(test)]
mod tests {
    use super::*;

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
