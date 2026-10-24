//! Runs the gatekeeper in the foreground, as launchd starts it.
//!
//! The startup order is deliberate: bind the listener → start serving immediately → load
//! the blocklist in the background.
//! What breaks if you change it: move list loading ahead of serving and the whole network
//! waits for a list download to finish before it has working name resolution.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use phylode::cache::Cache;
use phylode::config::Config;
use phylode::dns::{self, Listener};
use phylode::gatekeeper::Gatekeeper;
use phylode::health;
use phylode::install;
use phylode::journal::{self, EventKind, Journal, LocalZone};
use phylode::log_line;
use phylode::policy::{
    Allowlist, AttachedNetworks, Blocklist, RebindGuard, ServedNetworks, held_entries, held_path,
};
use phylode::report;
use phylode::upstream::{self, Conductor};

use crate::{load_config, local_zone, plural};

/// How often to check whether the list files changed on disk.
///
/// An allow or block is promised to take effect within 10 seconds, so this must be
/// comfortably below that.
const RELOAD_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) fn serve(config_path: &Path) -> ExitCode {
    // The service writes into folders the service account owns. As root it would follow a
    // link that account planted there and write wherever it points (Apple's Secure Coding
    // Guide, "Elevating Privileges Safely": run with the least privilege the work needs).
    // launchd always starts it as _phylode.
    if install::running_as_root() {
        log_line!(
            "Phylode does not run as root. `sudo phylode on` starts it as the _phylode account; \
             to try it out, run it from your own account with a configuration that listens on a \
             port above 1023."
        );
        return ExitCode::from(2);
    }
    let Some(config) = load_config(config_path) else {
        return ExitCode::from(2);
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            log_line!("Could not build the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            log_line!("{message}");
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
            log_line!(
                "Adopted launchd's sockets: {udp} UDP, {tcp} TCP (this process is unprivileged)"
            );
            listener
        }
        Err(reason) => {
            log_line!(
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
        config.journal(),
    ) {
        Ok(journal) => Some(journal),
        Err(error) => {
            log_line!(
                "Warning: the query journal could not be opened; this run will not be journalled: {error}"
            );
            None
        }
    };

    log_line!(
        "Phylode serving on {:?}; {} (all encrypted, no downgrade), cache limit {}",
        config.listen(),
        plural(conductor.len(), "upstream", "upstreams"),
        config.cache_capacity()
    );
    log_line!(
        "Journalling to {}, kept {} days",
        config.journal_dir().display(),
        config.journal_retention_days()
    );

    if let Some(journal) = journal.as_ref() {
        journal.event(
            EventKind::Started,
            journal::started_detail(config.journal()),
        );
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
        log_line!("{detail}");
        if let Some(journal) = upstream_journal.as_ref() {
            journal.event(kind, detail);
        }
    });

    // The self health check must be wired up before serving starts, and the address has to
    // be read before the listener is handed over. launchd's KeepAlive only checks whether
    // the process exists; it does nothing when the process is stuck but still alive.
    match listener.probe_target() {
        Some(target) => {
            log_line!("Self health check running; test queries go to {target}");
            health::spawn(target, journal.clone());
        }
        None => log_line!(
            "Warning: no UDP listener, so this run has no self health check — \
             a hang that does not exit will go unnoticed"
        ),
    }

    let cache = Arc::new(Cache::new(config.cache_capacity(), config.stale_max_age()));
    let own_addresses = listener.local_ips();
    let attached = AttachedNetworks::default();
    match attached.watch() {
        Ok(true) => log_line!("Following this Mac's networks as macOS reports changes"),
        Ok(false) => log_line!(
            "Warning: macOS does not report network changes to Phylode; this Mac's networks \
             are re-read every minute instead"
        ),
        Err(error) => log_line!("Warning: could not start following this Mac's networks: {error}"),
    }
    if !attached.known() {
        log_line!(
            "Warning: macOS has not said which networks this Mac is on; answering every private \
             range until it does"
        );
    }
    let rebind_guard = RebindGuard::with_internal_domains(config.internal_domains())
        .counting_as_inside(config.served_networks())
        .reading_nat64(config.nat64_prefixes())
        .attached_to(attached.clone());
    let gatekeeper = Arc::new(
        Gatekeeper::new(
            allowlist,
            blocklist,
            cache,
            conductor,
            journal,
            config.block_ttl(),
            rebind_guard,
        )
        .serving_on(own_addresses)
        .answering(ServedNetworks::new(config.served_networks(), attached)),
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
        log_line!("Received {reason}; flushing the journal before exiting");
        if let Some(journal) = journal {
            journal.event(EventKind::Stopped, format!("received {reason}"));
            let flushed =
                tokio::task::spawn_blocking(move || journal.flush_blocking(SHUTDOWN_FLUSH_TIMEOUT))
                    .await
                    .unwrap_or(false);
            if !flushed {
                log_line!(
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
            log_line!(
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
                    log_line!("Archived last week's summary: {}", path.display());
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    log_line!("Warning: could not archive last week's summary: {error}");
                }
                Err(error) => log_line!("Warning: the archiving task was interrupted: {error}"),
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
        let mut held_seen = None;
        loop {
            let held_paths: Vec<PathBuf> = config
                .blocklists()
                .iter()
                .map(|list| held_path(list))
                .collect();
            let held = fingerprint(held_paths.iter().map(PathBuf::as_path));
            if held_seen.as_ref() != Some(&held) {
                held_seen = Some(held);
                report_held(&config, journal.as_ref());
            }
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

/// Journals each list whose daily update is being held back, so the weekly summary shows it.
/// Runs at start-up and whenever a held download appears, changes or goes.
fn report_held(config: &Config, journal: Option<&Journal>) {
    for list in config.blocklists() {
        let Some(entries) = held_entries(list) else {
            continue;
        };
        let name = list.file_name().unwrap_or_default().to_string_lossy();
        let detail = format!("{name}: update has {}", plural(entries, "entry", "entries"));
        log_line!("Blocklist update set aside, under half the list in use: {detail}");
        if let Some(journal) = journal {
            journal.event(EventKind::BlocklistHeld, detail);
        }
    }
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
            log_line!(
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
                log_line!(
                    "Not every blocklist could be used: {error}. Still blocking with the lists \
                     already loaded ({}).",
                    plural(loaded, "domain", "domains")
                );
                if let Some(journal) = journal.as_ref() {
                    journal.event(EventKind::BlocklistKept, error.to_string());
                }
            }
            None => {
                log_line!("Blocklist failed to load; allowing everything for now: {error}");
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
        Ok(count) => log_line!(
            "Allowlist loaded: {} (plus {} hardcoded Apple rules)",
            plural(count, "entry", "entries"),
            Allowlist::hard_rules().len()
        ),
        Err(error) => {
            // A failed read leaves the entries already loaded in place; at start-up there are
            // none yet.
            log_line!(
                "Warning: the allowlist could not be read, so the entries loaded before stay in \
                 effect (none if the service just started) alongside the hardcoded Apple rules: \
                 {error}"
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
