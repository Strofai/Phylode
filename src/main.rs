//! Phylode's entry point: the service itself, plus the `allow` / `block` / `status` /
//! `report` commands.
//!
//! The startup order is deliberate: bind the listener → start serving immediately → load
//! the blocklist in the background.
//! What breaks if you change it: move list loading ahead of serving and the whole household
//! waits for a list download to finish before it has working name resolution.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use phylode::cache::Cache;
use phylode::cli;
use phylode::config::Config;
use phylode::dns::{self, Listener};
use phylode::gatekeeper::Gatekeeper;
use phylode::health;
use phylode::install;
use phylode::journal::{EventKind, Journal, LocalZone};
use phylode::policy::{Allowlist, Blocklist, RebindGuard};
use phylode::report;
use phylode::upstream::{self, Conductor};

/// How often to check whether the list files changed on disk.
///
/// An allow or block is promised to take effect within 10 seconds, so this must be
/// comfortably below that.
const RELOAD_INTERVAL: Duration = Duration::from_secs(2);

const USAGE: &str = "\
Usage:
  sudo phylode install           install or update the boot service
  sudo phylode on                point this Mac's DNS at it
  sudo phylode off               put this Mac's DNS back to automatic
  sudo phylode uninstall         remove the service (your lists and journal stay)
  phylode allow <domain>         allow a domain
  phylode block <domain>         block a domain
  phylode status                 show the current configuration and list status
  phylode report [days]          weekly summary (7 days by default)
  phylode [--config <file>]      run the gatekeeper in the foreground

allow and block each undo the other, taking effect within seconds.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match Command::parse(&args) {
        Ok(command) => command.run(),
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

enum Command {
    Serve {
        config_path: PathBuf,
    },
    Allow {
        config_path: PathBuf,
        domain: String,
    },
    Block {
        config_path: PathBuf,
        domain: String,
    },
    Status {
        config_path: PathBuf,
    },
    Report {
        config_path: PathBuf,
        days: u32,
    },
    Install,
    On,
    Off,
    Uninstall,
    Help,
}

impl Command {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut rest: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut config_path = PathBuf::from(install::CONFIG_PATH);

        // --config may appear anywhere, so pull it out before looking at the subcommand.
        if let Some(index) = rest.iter().position(|a| *a == "--config") {
            let value = rest
                .get(index + 1)
                .ok_or_else(|| "--config needs a path to a configuration file".to_string())?;
            config_path = PathBuf::from(value);
            rest.drain(index..=index + 1);
        }

        match rest.as_slice() {
            [] => Ok(Self::Serve { config_path }),
            ["--help" | "-h" | "help"] => Ok(Self::Help),
            ["status"] => Ok(Self::Status { config_path }),
            ["install"] => Ok(Self::Install),
            ["on"] => Ok(Self::On),
            ["off"] => Ok(Self::Off),
            ["uninstall"] => Ok(Self::Uninstall),
            ["report"] => Ok(Self::Report {
                config_path,
                days: 7,
            }),
            ["report", days] => Ok(Self::Report {
                config_path,
                days: days
                    .parse()
                    .map_err(|_| format!("days must be a positive integer; got {days}"))?,
            }),
            ["allow", domain] => Ok(Self::Allow {
                config_path,
                domain: (*domain).to_string(),
            }),
            ["block", domain] => Ok(Self::Block {
                config_path,
                domain: (*domain).to_string(),
            }),
            ["allow" | "block"] => Err(format!("Which domain?\n\n{USAGE}")),
            other => Err(format!("Unrecognized arguments {other:?}\n\n{USAGE}")),
        }
    }

    fn run(self) -> ExitCode {
        match self {
            Self::Help => {
                println!("{USAGE}");
                ExitCode::SUCCESS
            }
            Self::Serve { config_path } => serve(&config_path),
            Self::Allow {
                config_path,
                domain,
            } => edit(&config_path, &domain, cli::allow),
            Self::Block {
                config_path,
                domain,
            } => edit(&config_path, &domain, cli::block),
            Self::Status { config_path } => status(&config_path),
            Self::Report { config_path, days } => weekly_report(&config_path, days),
            Self::Install => finish(install::install()),
            Self::On => finish(install::on().map(|services| {
                println!("This Mac now uses Phylode for DNS on:");
                for service in services {
                    println!("  {service}");
                }
                println!("To switch back: sudo phylode off");
            })),
            Self::Off => finish(install::off().map(|services| {
                if services.is_empty() {
                    println!("No network service was using Phylode; nothing changed.");
                } else {
                    println!("DNS is back to automatic on:");
                    for service in services {
                        println!("  {service}");
                    }
                }
            })),
            Self::Uninstall => finish(install::uninstall().map(|restored| {
                for service in restored {
                    println!("DNS back to automatic: {service}");
                }
                println!("Removed.\n\n{}", install::leftovers_message());
            })),
        }
    }
}

/// Prints an install-family error and turns the result into an exit code.
fn finish(result: Result<(), install::InstallError>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Did not finish: {error}");
            ExitCode::FAILURE
        }
    }
}

type EditFn = fn(&str, Option<&Path>, Option<&Path>) -> Result<cli::Outcome, cli::CliError>;

fn edit(config_path: &Path, domain: &str, action: EditFn) -> ExitCode {
    let Some(config) = load_config(config_path) else {
        return ExitCode::from(2);
    };
    match action(domain, config.allowlist(), config.user_blocklist()) {
        Ok(outcome) => {
            println!("{}", outcome.message());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn status(config_path: &Path) -> ExitCode {
    let Some(config) = load_config(config_path) else {
        return ExitCode::from(2);
    };

    println!("Configuration: {}", config_path.display());
    println!("Listening on: {:?}", config.listen());
    println!(
        "Time zone for journal dates: {} (this Mac's setting)",
        local_zone().name()
    );
    println!(
        "Upstreams: {}, all encrypted; never downgrades to plaintext when unreachable",
        plural(config.upstreams().len(), "server", "servers")
    );
    for upstream in config.upstreams() {
        println!(
            "  · {:?} {} (certificate name {})",
            upstream.protocol(),
            upstream.ip(),
            upstream.server_name()
        );
    }
    println!(
        "Blocked answers cached by devices for: {:?}",
        config.block_ttl()
    );
    println!(
        "Query journal: {}, kept {} days",
        config.journal_dir().display(),
        config.journal_retention_days()
    );
    println!(
        "Blocklists: {}",
        plural(config.blocklists().len(), "file", "files")
    );
    for path in config.blocklists() {
        println!(
            "  · {}{}{}",
            path.display(),
            exists_mark(path),
            age_mark(path)
        );
    }
    // Load them the way the service does, so the number matches what the service sees.
    let blocklist = Blocklist::new();
    let optional: Vec<&Path> = config.user_blocklist().into_iter().collect();
    match blocklist.load_all(config.blocklists(), &optional) {
        Ok(_) => println!(
            "  {} domains will be blocked in total",
            blocklist.loaded_len().unwrap_or(0)
        ),
        Err(error) => println!("  ⚠️ {error} — nothing is being blocked right now"),
    }
    match config.user_blocklist() {
        Some(path) => println!(
            "Your own blocklist: {}{}",
            path.display(),
            exists_mark(path)
        ),
        None => println!("Your own blocklist: no user_blocklist set in the configuration"),
    }
    match config.allowlist() {
        Some(path) => {
            let allowlist = Allowlist::new();
            match allowlist.load_from_file(path) {
                Ok(_) => println!(
                    "Your own allowlist: {} ({})",
                    path.display(),
                    plural(allowlist.user_len(), "entry", "entries")
                ),
                Err(error) => println!("Your own allowlist: ⚠️ {error}"),
            }
        }
        None => println!("Your own allowlist: no allowlist set in the configuration"),
    }
    println!(
        "Always allowed (hardcoded, not configurable): {}",
        Allowlist::hard_rules().join(", ")
    );
    match config.internal_domains() {
        [] => println!("Rebinding defence: on, with no exempt domains"),
        domains => println!(
            "Rebinding defence: on; these domains are exempt (may point inward): {}",
            domains.join(", ")
        ),
    }
    ExitCode::SUCCESS
}

fn weekly_report(config_path: &Path, days: u32) -> ExitCode {
    let Some(config) = load_config(config_path) else {
        return ExitCode::from(2);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dates = report::recent_days(now, &local_zone(), days.max(1));
    let summary = report::Summary::gather(config.journal_dir(), &dates);
    println!("{}", summary.render());
    let archive = config.journal_dir().join(report::archive::ARCHIVE_DIR);
    if archive.is_dir() {
        println!(
            "Past weekly summaries are kept in {} (12 weeks)",
            archive.display()
        );
    }
    ExitCode::SUCCESS
}

/// Renders a count with its noun, using the singular form when the count is 1.
///
/// Both forms are passed explicitly rather than derived: English plurals are irregular
/// (entry/entries, not entrys), and guessing produces exactly the kind of wrong output this
/// function exists to prevent.
///
/// What breaks if you change it: these lines are the first thing a user sees. "1 upstreams" is
/// the kind of detail that makes a program look machine-generated.
fn plural(n: usize, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}

fn exists_mark(path: &Path) -> &'static str {
    if path.exists() {
        ""
    } else {
        " (not created yet)"
    }
}

/// How long since a list file was updated. The updater runs daily, so more than 3 days
/// means it is broken and that has to be visible.
fn age_mark(path: &Path) -> String {
    let Some(age) = std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
    else {
        return String::new();
    };
    let days = age.as_secs() / 86_400;
    match days {
        0 => " (updated today)".to_string(),
        1 => " (updated 1 day ago)".to_string(),
        2..=3 => format!(" (updated {days} days ago)"),
        _ => format!(" (⚠️ not updated for {days} days; the daily schedule may be broken)"),
    }
}

/// The Mac's time zone, which journal dates and the weekly summary are expressed in. Falls
/// back to UTC, with a warning, when the system zone cannot be read.
fn local_zone() -> LocalZone {
    LocalZone::system().unwrap_or_else(|error| {
        eprintln!(
            "Warning: could not read this Mac's time zone, so journal dates are in UTC: {error}"
        );
        LocalZone::utc()
    })
}

fn load_config(path: &Path) -> Option<Config> {
    match Config::load(path) {
        Ok(config) => Some(config),
        Err(error) => {
            eprintln!("Could not read the configuration file: {error}");
            None
        }
    }
}

fn serve(config_path: &Path) -> ExitCode {
    let Some(config) = load_config(config_path) else {
        return ExitCode::from(2);
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Could not build the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> Result<(), String> {
    let conductor = Arc::new(
        Conductor::new(config.upstreams())
            .map_err(|error| format!("Upstream configuration is invalid: {error}"))?,
    );

    // In a real deployment launchd binds port 53 and hands us the socket, so the service
    // itself needs no privileges. When not started by launchd (development, manual runs)
    // we bind it ourselves.
    let listener = match Listener::from_launchd() {
        Ok(listener) => {
            let (udp, tcp) = listener.counts();
            eprintln!(
                "Adopted launchd's sockets: {udp} UDP, {tcp} TCP (this process is unprivileged)"
            );
            listener
        }
        Err(reason) => {
            eprintln!(
                "Not started by launchd ({reason}); binding {:?} directly",
                config.listen()
            );
            Listener::bind(config.listen())
                .await
                .map_err(|error| format!("Could not bind {:?}: {error}", config.listen()))?
        }
    };

    let blocklist = Blocklist::new();
    let allowlist = Allowlist::new();

    let zone = local_zone();
    let journal = match Journal::start(
        config.journal_dir().to_path_buf(),
        config.journal_retention_days(),
        zone.clone(),
    ) {
        Ok(journal) => Some(journal),
        Err(error) => {
            eprintln!(
                "Warning: the query journal could not be opened; this run will not be journalled: {error}"
            );
            None
        }
    };

    eprintln!(
        "Phylode serving on {:?}; {} (all encrypted, no downgrade), cache limit {}",
        config.listen(),
        plural(conductor.len(), "upstream", "upstreams"),
        config.cache_capacity()
    );
    eprintln!(
        "Journalling to {}, kept {} days",
        config.journal_dir().display(),
        config.journal_retention_days()
    );

    if let Some(journal) = journal.as_ref() {
        journal.event(EventKind::Started, "Phylode started serving");
    }
    spawn_reloader(
        blocklist.clone(),
        allowlist.clone(),
        config.clone(),
        journal.clone(),
    );

    if journal.is_some() {
        spawn_archiver(config.clone(), zone);
    }
    spawn_shutdown(journal.clone());

    let upstream_journal = journal.clone();
    upstream::spawn_reprobe(Arc::clone(&conductor), move |down| {
        let (kind, detail) = if down {
            (
                EventKind::UpstreamsDown,
                "every upstream is unreachable; only the cache is holding",
            )
        } else {
            (
                EventKind::UpstreamsRecovered,
                "at least one upstream recovered",
            )
        };
        eprintln!("{detail}");
        if let Some(journal) = upstream_journal.as_ref() {
            journal.event(kind, detail);
        }
    });

    // The self health check must be wired up before serving starts, and the address has to
    // be read before the listener is handed over. launchd's KeepAlive only checks whether
    // the process exists; it does nothing when the process is stuck but still alive.
    match listener.probe_target() {
        Some(target) => {
            eprintln!("Self health check running; test queries go to {target}");
            health::spawn(target, journal.clone());
        }
        None => eprintln!(
            "Warning: no UDP listener, so this run has no self health check — \
             a hang that does not exit will go unnoticed"
        ),
    }

    let cache = Arc::new(Cache::new(config.cache_capacity(), config.stale_max_age()));
    let own_addresses = listener.local_ips();
    let gatekeeper = Arc::new(
        Gatekeeper::new(
            allowlist,
            blocklist,
            cache,
            conductor,
            journal,
            config.block_ttl(),
            RebindGuard::with_internal_domains(config.internal_domains()),
        )
        .serving_on(own_addresses),
    );
    dns::serve(listener, gatekeeper)
        .await
        .map_err(|error| format!("Service stopped: {error}"))
}

/// How long to wait for the journal to flush after a stop signal. launchd waits 20 seconds
/// by default before killing the process (`ExitTimeOut` in `man launchd.plist`), so this
/// must be comfortably shorter.
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Background task: on a stop signal (the SIGTERM launchd sends when stopping the service or
/// shutting down, or Ctrl-C in a terminal), record a "service stopped" event, wait for the
/// journal to reach disk, then exit cleanly.
///
/// What breaks if you change it: without handling these signals the process is killed
/// outright and neither the last batch of records nor the stop event survives. The boot
/// service sets KeepAlive, so launchd still restarts it after a clean exit as configured.
fn spawn_shutdown(journal: Option<Journal>) {
    tokio::spawn(async move {
        let Some(reason) = wait_for_stop_signal().await else {
            return;
        };
        eprintln!("Received {reason}; flushing the journal before exiting");
        if let Some(journal) = journal {
            journal.event(EventKind::Stopped, format!("received {reason}"));
            let flushed =
                tokio::task::spawn_blocking(move || journal.flush_blocking(SHUTDOWN_FLUSH_TIMEOUT))
                    .await
                    .unwrap_or(false);
            if !flushed {
                eprintln!(
                    "Warning: the journal did not finish writing within {} seconds; the last few \
                     records may be lost",
                    SHUTDOWN_FLUSH_TIMEOUT.as_secs()
                );
            }
        }
        std::process::exit(0);
    });
}

/// Waits for SIGTERM or Ctrl-C and reports which arrived. If the signal handler cannot be
/// installed, prints a warning and returns `None` (the process still terminates the default
/// way).
async fn wait_for_stop_signal() -> Option<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(error) => {
            eprintln!(
                "Warning: could not install the stop signal handler; the last few records may be \
                 lost on shutdown: {error}"
            );
            return None;
        }
    };
    tokio::select! {
        _ = terminate.recv() => Some("a stop signal"),
        _ = tokio::signal::ctrl_c() => Some("an interrupt (Ctrl-C)"),
    }
}

/// How often to check whether last week has been archived. Archiving is needed once, after
/// a Monday, so an hour of latency is irrelevant.
const ARCHIVE_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Background task: at startup and hourly thereafter, archive last week's summary (weekly
/// summaries are kept for 12 weeks).
///
/// What breaks if you change it: archiving has to happen inside the detailed journal's
/// 10-day window, so a service stopped for more than 3 days misses that week entirely.
fn spawn_archiver(config: Config, zone: LocalZone) {
    tokio::spawn(async move {
        loop {
            let dir = config.journal_dir().to_path_buf();
            let zone = zone.clone();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let result =
                tokio::task::spawn_blocking(move || report::archive::archive_due(&dir, now, &zone))
                    .await;
            match result {
                Ok(Ok(Some(path))) => {
                    eprintln!("Archived last week's summary: {}", path.display());
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    eprintln!("Warning: could not archive last week's summary: {error}");
                }
                Err(error) => eprintln!("Warning: the archiving task was interrupted: {error}"),
            }
            tokio::time::sleep(ARCHIVE_CHECK_INTERVAL).await;
        }
    });
}

/// Background task: load once, then periodically check whether the files changed and reload
/// when they have.
///
/// What breaks if you change it: the first load deliberately does not block startup. When
/// loading fails every query is allowed through, but the reason has to be printed where
/// someone can see it.
fn spawn_reloader(
    blocklist: Blocklist,
    allowlist: Allowlist,
    config: Config,
    journal: Option<Journal>,
) {
    tokio::spawn(async move {
        let mut last_signature = String::new();
        loop {
            let signature = signature_of(&config);
            if signature != last_signature {
                last_signature = signature;
                reload_once(&blocklist, &allowlist, &config, journal.as_ref()).await;
            }
            tokio::time::sleep(RELOAD_INTERVAL).await;
        }
    });
}

async fn reload_once(
    blocklist: &Blocklist,
    allowlist: &Allowlist,
    config: &Config,
    journal: Option<&Journal>,
) {
    let blocklist = blocklist.clone();
    let allowlist = allowlist.clone();
    let required: Vec<PathBuf> = config.blocklists().to_vec();
    let optional: Vec<PathBuf> = config
        .user_blocklist()
        .map(PathBuf::from)
        .into_iter()
        .collect();
    let allow_path = config.allowlist().map(PathBuf::from);
    let journal = journal.cloned();

    let _ = tokio::task::spawn_blocking(move || {
        match blocklist.load_all(&required, &optional) {
            Ok(count) => {
                eprintln!("Blocklist loaded: {}", plural(count, "domain", "domains"));
                if let Some(journal) = journal.as_ref() {
                    journal.event(
                        EventKind::BlocklistLoaded,
                        plural(count, "domain", "domains"),
                    );
                }
            }
            Err(error) => {
                eprintln!("Blocklist failed to load; allowing everything for now: {error}");
                if let Some(journal) = journal.as_ref() {
                    journal.event(EventKind::BlocklistFailed, error.to_string());
                }
            }
        }
        if let Some(path) = allow_path {
            match allowlist.load_from_file(&path) {
                Ok(count) => eprintln!(
                    "Allowlist loaded: {} (plus {} hardcoded Apple rules)",
                    plural(count, "entry", "entries"),
                    Allowlist::hard_rules().len()
                ),
                Err(error) => {
                    eprintln!(
                        "Warning: the allowlist could not be read; only the hardcoded Apple rules \
                         apply: {error}"
                    );
                    if let Some(journal) = journal.as_ref() {
                        journal.event(EventKind::AllowlistFailed, error.to_string());
                    }
                }
            }
        }
    })
    .await;
}

/// Fingerprints each file by inode, nanosecond modification time and size; a change means
/// reload.
///
/// What breaks if you change it: `phylode allow` writes to a staging file and renames it,
/// which changes the inode every time. Drop the inode and compare only whole seconds and
/// size, and allowing two domains of equal length within the same second silently loses the
/// second one.
fn signature_of(config: &Config) -> String {
    use std::os::unix::fs::MetadataExt;

    let paths = config
        .blocklists()
        .iter()
        .map(PathBuf::from)
        .chain(config.user_blocklist().map(PathBuf::from))
        .chain(config.allowlist().map(PathBuf::from));

    let mut parts = Vec::new();
    for path in paths {
        let mark = std::fs::metadata(&path)
            .ok()
            .map(|meta| {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                format!("{}:{modified}:{}", meta.ino(), meta.len())
            })
            .unwrap_or_else(|| "missing".to_string());
        parts.push(format!("{}={mark}", path.display()));
    }
    parts.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Should change: a count of 1 uses the singular form.
    /// Should not change: any other count uses the plural given, including irregular ones.
    #[test]
    fn counts_of_one_read_as_singular() {
        assert_eq!(plural(1, "upstream", "upstreams"), "1 upstream");
        assert_eq!(plural(0, "upstream", "upstreams"), "0 upstreams");
        assert_eq!(plural(2, "upstream", "upstreams"), "2 upstreams");
        assert_eq!(
            plural(3, "entry", "entries"),
            "3 entries",
            "irregular plurals must come from the caller, not from appending an s"
        );
    }

    /// Should change: replacing an allowlist of identical size by rename within the same
    /// second still changes the fingerprint (this is exactly how `phylode allow` writes).
    /// Should not change: an untouched file keeps its fingerprint.
    #[test]
    fn a_same_second_same_size_replacement_is_still_detected() {
        let dir = std::env::temp_dir().join(format!("phylode-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let allow = dir.join("allow.txt");
        std::fs::write(&allow, "aaaa.com\n").unwrap();
        let config = Config::parse(&format!(
            "listen = 127.0.0.1:5353\nupstream = tls 1.1.1.1 cloudflare-dns.com\nallowlist = {}\n",
            allow.display()
        ))
        .unwrap();

        let before = signature_of(&config);
        assert_eq!(before, signature_of(&config));

        let staged = dir.join("allow.txt.tmp");
        std::fs::write(&staged, "bbbb.com\n").unwrap();
        std::fs::rename(&staged, &allow).unwrap();
        assert_ne!(before, signature_of(&config));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
