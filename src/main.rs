//! Phylode's entry point: the service itself, plus the `allow` / `block` / `status` /
//! `report` commands.
//!
//! The startup order is deliberate: bind the listener → start serving immediately → load
//! the blocklist in the background.
//! What breaks if you change it: move list loading ahead of serving and the whole network
//! waits for a list download to finish before it has working name resolution.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use phylode::cache::Cache;
use phylode::cli;
use phylode::config::Config;
use phylode::diagnostics;
use phylode::dns::{self, Listener};
use phylode::gatekeeper::Gatekeeper;
use phylode::health;
use phylode::install;
use phylode::journal::{self, EventKind, Journal, LocalZone};
use phylode::policy::{Allowlist, Blocklist, RebindGuard, ServedNetworks};
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
  phylode diagnostics            a report to paste into a bug report; holds no domains,
                                 addresses or names
  phylode [--config <file>]      run Phylode in the foreground

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
    Diagnostics {
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
            ["diagnostics"] => Ok(Self::Diagnostics { config_path }),
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
                    .ok()
                    .filter(|&days: &u32| days > 0)
                    .ok_or_else(|| format!("days must be a positive integer; got {days}"))?,
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
            other => Err(format!(
                "Unknown command: phylode {}\n\n{USAGE}",
                other.join(" ")
            )),
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
            Self::Diagnostics { config_path } => diagnostics(&config_path),
            Self::Report { config_path, days } => weekly_report(&config_path, days),
            Self::Install => finish(install::install()),
            Self::On => finish(install::on().map(|switched| {
                println!("This Mac now uses Phylode for DNS on:");
                for service in switched.services {
                    println!("  {service}");
                }
                println!("To switch back: sudo phylode off");
                println!();
                println!("{}", network_hint(switched.network_address));
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

/// How the rest of the network starts using this Mac.
fn network_hint(address: Option<std::net::IpAddr>) -> String {
    match address {
        Some(address) => format!(
            "Other devices on this network can use it too: set {address} as the DNS server in \
             your router's DHCP settings, or on each device. Keep this Mac's address fixed (a \
             DHCP reservation on the router), or devices lose it when it changes."
        ),
        None => "This Mac has no network connection right now, so there is no address to give \
                 other devices yet; run phylode status once it is connected."
            .to_string(),
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
    let extra: Vec<String> = config
        .served_networks()
        .iter()
        .map(ToString::to_string)
        .collect();
    println!(
        "Answers: this Mac and devices on private network ranges{}",
        if extra.is_empty() {
            String::new()
        } else {
            format!(", plus {}", extra.join(", "))
        }
    );
    match install::network_address(&config) {
        Some(address) => println!("Other devices reach it at: {address}"),
        None => println!("Other devices reach it at: unknown (this Mac is offline)"),
    }
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
        Err(error) => match blocklist.loaded_len() {
            Some(loaded) => println!(
                "  Warning: {error}. The service keeps any list it loaded before; if it \
                 restarted now it would start with only the lists that read ({})",
                plural(loaded, "domain", "domains")
            ),
            None => println!(
                "  Warning: {error}. The service keeps any list it loaded before, but would \
                 start with none if it restarted now"
            ),
        },
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
                Err(error) => println!("Your own allowlist: not loaded ({error})"),
            }
        }
        None => println!("Your own allowlist: no allowlist set in the configuration"),
    }
    println!(
        "Always allowed (hardcoded, not configurable): {}",
        Allowlist::hard_rules().join(", ")
    );
    match config.internal_domains() {
        [] => println!("Rebinding defense: on, with no exempt domains"),
        domains => println!(
            "Rebinding defense: on; these domains are exempt (may point inward): {}",
            domains.join(", ")
        ),
    }
    ExitCode::SUCCESS
}

fn weekly_report(config_path: &Path, days: u32) -> ExitCode {
    let Some(config) = load_config(config_path) else {
        return ExitCode::from(2);
    };
    // The journal holds nothing older than its retention, so a longer span only adds empty days.
    let kept = config.journal_retention_days();
    if days > kept {
        println!("The journal keeps {kept} days, so this covers the last {kept}.\n");
    }
    let dates = report::recent_days(journal::unix_now(), &local_zone(), days.min(kept.max(1)));
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
    match age_in_days(path) {
        None => String::new(),
        Some(0) => " (updated today)".to_string(),
        Some(1) => " (updated 1 day ago)".to_string(),
        Some(days @ 2..=3) => format!(" (updated {days} days ago)"),
        Some(days) => {
            format!(" (warning: not updated for {days} days; the daily schedule may be broken)")
        }
    }
}

/// Whole days since a file was last modified; `None` when it does not exist.
fn age_in_days(path: &Path) -> Option<u64> {
    let age = std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()?
        .elapsed()
        .ok()?;
    Some(age.as_secs() / 86_400)
}

/// Gathers what `diagnostics::render` prints. Every read is allowed to fail — a broken
/// installation is exactly when this gets run — and a failure becomes a line, not an exit.
fn diagnostics(config_path: &Path) -> ExitCode {
    let config = Config::load(config_path);
    let macos = std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut facts = diagnostics::Facts {
        version: env!("CARGO_PKG_VERSION"),
        macos: &macos,
        arch: std::env::consts::ARCH,
        config: config.as_ref(),
        answering: false,
        blocklist_domains: None,
        blocklist_ages: Vec::new(),
        allowlist_entries: None,
        user_blocklist_entries: None,
        events: Vec::new(),
        log: std::fs::read_to_string(install::SERVICE_LOG)
            .map_err(|error| format!("could not read {}: {error}", install::SERVICE_LOG)),
    };

    if let Ok(config) = config.as_ref() {
        facts.answering = install::answers_within(config, Duration::ZERO);
        let blocklist = Blocklist::new();
        let optional: Vec<&Path> = config.user_blocklist().into_iter().collect();
        facts.blocklist_domains = blocklist.load_all(config.blocklists(), &optional).ok();
        facts.blocklist_ages = config.blocklists().iter().map(|p| age_in_days(p)).collect();
        let count = |path: Option<&Path>| path.map_or(Some(0), |p| cli::entry_count(p).ok());
        facts.allowlist_entries = count(config.allowlist());
        facts.user_blocklist_entries = count(config.user_blocklist());

        for day in report::recent_days(journal::unix_now(), &local_zone(), 7) {
            let Ok(text) =
                std::fs::read_to_string(journal::events_file(config.journal_dir(), &day))
            else {
                continue;
            };
            facts.events.extend(text.lines().filter_map(|line| {
                let mut fields = line.split('\t');
                Some((fields.next()?.to_string(), fields.next()?.to_string()))
            }));
        }
    }

    print!("{}", diagnostics::render(&facts));
    ExitCode::SUCCESS
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
            eprintln!(
                "Could not use the configuration file {}: {error}",
                path.display()
            );
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
        .serving_on(own_addresses)
        .answering(ServedNetworks::new(config.served_networks())),
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
            let now = journal::unix_now();
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
/// only the list whose files changed.
///
/// What breaks if you change it: the first load deliberately does not block startup. When
/// loading fails every query is allowed through, but the reason has to be printed where
/// someone can see it. The two lists are fingerprinted separately because `phylode allow`
/// only touches the small allowlist; reloading the million-entry blocklist for it would
/// cost seconds of CPU and a second copy of the list in memory each time.
fn spawn_reloader(
    blocklist: Blocklist,
    allowlist: Allowlist,
    config: Config,
    journal: Option<Journal>,
) {
    tokio::spawn(async move {
        let mut lists_seen = None;
        let mut allow_seen = None;
        loop {
            let lists = fingerprint(
                config
                    .blocklists()
                    .iter()
                    .map(PathBuf::as_path)
                    .chain(config.user_blocklist()),
            );
            if lists_seen.as_ref() != Some(&lists) {
                lists_seen = Some(lists);
                reload_blocklist(&blocklist, &config, journal.as_ref()).await;
            }
            if let Some(path) = config.allowlist() {
                let allow = fingerprint([path]);
                if allow_seen.as_ref() != Some(&allow) {
                    allow_seen = Some(allow);
                    reload_allowlist(&allowlist, path, journal.as_ref()).await;
                }
            }
            tokio::time::sleep(RELOAD_INTERVAL).await;
        }
    });
}

async fn reload_blocklist(blocklist: &Blocklist, config: &Config, journal: Option<&Journal>) {
    let blocklist = blocklist.clone();
    let required: Vec<PathBuf> = config.blocklists().to_vec();
    let optional: Vec<PathBuf> = config
        .user_blocklist()
        .map(PathBuf::from)
        .into_iter()
        .collect();
    let journal = journal.cloned();

    let _ = tokio::task::spawn_blocking(move || match blocklist.load_all(&required, &optional) {
        Ok(count) => {
            eprintln!(
                "{}: {}",
                install::BLOCKLIST_LOADED,
                plural(count, "domain", "domains")
            );
            if let Some(journal) = journal.as_ref() {
                journal.event(
                    EventKind::BlocklistLoaded,
                    plural(count, "domain", "domains"),
                );
            }
        }
        // A failed load leaves any list loaded before in place, or at startup uses the files
        // that did read, so whether the network is unprotected depends on whether anything is
        // loaded now; the journal has to tell them apart or the weekly summary reports a gap
        // that did not happen.
        Err(error) => match blocklist.loaded_len() {
            Some(loaded) => {
                eprintln!(
                    "Not every blocklist could be used: {error}. Still blocking with the lists \
                     already loaded ({}).",
                    plural(loaded, "domain", "domains")
                );
                if let Some(journal) = journal.as_ref() {
                    journal.event(EventKind::BlocklistKept, error.to_string());
                }
            }
            None => {
                eprintln!("Blocklist failed to load; allowing everything for now: {error}");
                if let Some(journal) = journal.as_ref() {
                    journal.event(EventKind::BlocklistFailed, error.to_string());
                }
            }
        },
    })
    .await;
}

async fn reload_allowlist(allowlist: &Allowlist, path: &Path, journal: Option<&Journal>) {
    let allowlist = allowlist.clone();
    let path = path.to_path_buf();
    let journal = journal.cloned();

    let _ = tokio::task::spawn_blocking(move || match allowlist.load_from_file(&path) {
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
fn fingerprint<'a>(paths: impl IntoIterator<Item = &'a Path>) -> String {
    use std::os::unix::fs::MetadataExt;

    let mut parts = Vec::new();
    for path in paths {
        let mark = std::fs::metadata(path)
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
        let before = fingerprint([allow.as_path()]);
        assert_eq!(before, fingerprint([allow.as_path()]));

        let staged = dir.join("allow.txt.tmp");
        std::fs::write(&staged, "bbbb.com\n").unwrap();
        std::fs::rename(&staged, &allow).unwrap();
        assert_ne!(before, fingerprint([allow.as_path()]));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
