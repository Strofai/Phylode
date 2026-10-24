//! Phylode's entry point: reads the command line and runs the command it names, from
//! `install` to `report`. Running the service itself is [`service`].

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use phylode::cli;
use phylode::config::Config;
use phylode::diagnostics;
use phylode::install;
use phylode::journal::{self, LocalZone, OlderDetail};
use phylode::policy::{Allowlist, Blocklist, held_entries, held_path};
use phylode::report;
use phylode::{log_line, out, out_line};

mod service;

const USAGE: &str = "\
Usage:
  sudo phylode install           install or update the boot service
  sudo phylode on                point this Mac's DNS at it
  sudo phylode off               put this Mac's DNS back as it was before on
  sudo phylode uninstall         remove the service (your lists and journal stay)
  sudo phylode forget            delete the lookup journal and saved weekly summaries now
  phylode allow <domain>         allow a domain
  phylode block <domain>         block a domain
  phylode status                 show the current configuration and list status
  phylode report [days]          weekly summary (7 days by default)
  phylode diagnostics            a report to paste into a bug report; holds no domains,
                                 addresses or names
  phylode --version              show which version is installed
  phylode [--config <file>]      run Phylode in the foreground

allow and block each undo the other, taking effect within seconds.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match Command::parse(&args) {
        Ok(command) => command.run(),
        Err(message) => {
            log_line!("{message}");
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
    Forget,
    Help,
    Version,
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
            ["--version" | "-V" | "version"] => Ok(Self::Version),
            ["status"] => Ok(Self::Status { config_path }),
            ["diagnostics"] => Ok(Self::Diagnostics { config_path }),
            ["install"] => Ok(Self::Install),
            ["on"] => Ok(Self::On),
            ["off"] => Ok(Self::Off),
            ["uninstall"] => Ok(Self::Uninstall),
            ["forget"] => Ok(Self::Forget),
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
                out_line!("{USAGE}");
                ExitCode::SUCCESS
            }
            Self::Version => {
                out_line!("Phylode {}", env!("CARGO_PKG_VERSION"));
                ExitCode::SUCCESS
            }
            Self::Serve { config_path } => service::serve(&config_path),
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
            Self::Install => {
                let result = install::install();
                let failed = result.is_err();
                let code = finish(result);
                if failed && install::this_mac_uses_it() {
                    log_line!(
                        "This Mac still uses Phylode for DNS, and it may not be running now. To \
                         get DNS back until install succeeds: sudo phylode off"
                    );
                }
                code
            }
            Self::On => finish(install::on().map(|switched| {
                out_line!("This Mac now uses Phylode for DNS on:");
                for service in switched.services {
                    out_line!("  {service}");
                }
                out_line!("To switch back: sudo phylode off");
                out_line!();
                out_line!("{}", network_hint(switched.network_address));
            })),
            Self::Off => finish(install::off().map(|services| {
                if services.is_empty() {
                    out_line!("No network service was using Phylode; nothing changed.");
                } else {
                    out_line!("DNS is back to how it was before phylode on, on:");
                    for service in services {
                        out_line!("  {service}");
                    }
                }
            })),
            Self::Uninstall => finish(install::uninstall().map(|restored| {
                for service in restored {
                    out_line!("DNS back as it was: {service}");
                }
                out_line!("Removed.\n\n{}", install::leftovers_message());
            })),
            Self::Forget => finish(install::forget().map(|removed| {
                out_line!(
                    "Deleted {}: every recorded lookup and saved weekly summary. Lookups from now \
                     on are kept as the journal setting says.",
                    plural(removed, "file", "files")
                );
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
            log_line!("Did not finish: {error}");
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
            out_line!("{}", outcome.message());
            ExitCode::SUCCESS
        }
        Err(error) => {
            log_line!("{error}");
            ExitCode::from(2)
        }
    }
}

fn status(config_path: &Path) -> ExitCode {
    let Some(config) = load_config(config_path) else {
        return ExitCode::from(2);
    };

    out_line!("Configuration: {}", config_path.display());
    let extra: Vec<String> = config
        .served_networks()
        .iter()
        .map(ToString::to_string)
        .collect();
    out_line!(
        "Answers: this Mac and devices on private network ranges{}",
        if extra.is_empty() {
            String::new()
        } else {
            format!(", plus {}", extra.join(", "))
        }
    );
    match install::network_address(&config) {
        Some(address) => out_line!("Other devices reach it at: {address}"),
        None => out_line!("Other devices reach it at: unknown (this Mac is offline)"),
    }
    out_line!(
        "Time zone for journal dates: {} (this Mac's setting)",
        local_zone().name()
    );
    out_line!(
        "Upstreams: {}, all encrypted; never downgrades to plaintext when unreachable",
        plural(config.upstreams().len(), "server", "servers")
    );
    for upstream in config.upstreams() {
        out_line!(
            "  · {:?} {} (certificate name {})",
            upstream.protocol(),
            upstream.ip(),
            upstream.server_name()
        );
    }
    out_line!(
        "Protection: {} ({}, updated daily)",
        config.protection().name(),
        config.protection().lists()
    );
    out_line!(
        "Blocked answers cached by devices for: {:?}",
        config.block_ttl()
    );
    out_line!(
        "Query journal: {}, kept {} days, journal = {}",
        config.journal_dir().display(),
        config.journal_retention_days(),
        config.journal().name()
    );
    match journal::older_detail(config.journal_dir(), config.journal()) {
        OlderDetail::None => {}
        OlderDetail::NotApplied(running) => out_line!(
            "  The running service still keeps {}; journal = {} applies once it restarts: \
             sudo phylode install",
            running.name(),
            config.journal().name()
        ),
        OlderDetail::Until(day) => out_line!(
            "  Lookups up to {day} keep more than {} does. They are deleted after {}, and weekly \
             summaries saved by then after 12 weeks; to delete both now: sudo phylode forget",
            config.journal().name(),
            days_after(&day, config.journal_retention_days())
        ),
    }
    out_line!(
        "Blocklists: {}",
        plural(config.blocklists().len(), "file", "files")
    );
    for path in config.blocklists() {
        out_line!(
            "  · {}{}{}{}",
            path.display(),
            exists_mark(path),
            age_mark(path),
            unusable_mark(path)
        );
        if let Some(entries) = held_entries(path) {
            out_line!(
                "    Warning: the last update had only {}, under half of this list, so it was set \
                 aside and this list is still in use. If the list really did shrink, use the \
                 update with: sudo mv {} {}",
                plural(entries, "entry", "entries"),
                held_path(path).display(),
                path.display()
            );
        }
    }
    // Load them the way the service does, so the number matches what the service sees.
    let blocklist = Blocklist::new();
    let optional: Vec<&Path> = config.user_blocklist().into_iter().collect();
    match blocklist.load_all(config.blocklists(), &optional) {
        Ok(_) => out_line!(
            "  {} will be blocked in total",
            plural(blocklist.loaded_len().unwrap_or(0), "domain", "domains")
        ),
        Err(error) => match blocklist.loaded_len() {
            Some(loaded) => out_line!(
                "  Warning: {error}. The service keeps any list it loaded before; if it \
                 restarted now it would start with only the lists that read ({})",
                plural(loaded, "domain", "domains")
            ),
            None => out_line!(
                "  Warning: {error}. The service keeps any list it loaded before, but would \
                 start with none if it restarted now"
            ),
        },
    }
    match config.user_blocklist() {
        Some(path) => out_line!(
            "Your own blocklist: {}{}{}",
            path.display(),
            exists_mark(path),
            unusable_mark(path)
        ),
        None => out_line!("Your own blocklist: no user_blocklist set in the configuration"),
    }
    match config.allowlist() {
        Some(path) => {
            let allowlist = Allowlist::new();
            match allowlist.load_from_file(path) {
                Ok(_) => out_line!(
                    "Your own allowlist: {} ({})",
                    path.display(),
                    plural(allowlist.user_len(), "entry", "entries")
                ),
                Err(error) => out_line!("Your own allowlist: not loaded ({error})"),
            }
        }
        None => out_line!("Your own allowlist: no allowlist set in the configuration"),
    }
    out_line!(
        "Always allowed (hardcoded, not configurable): {}",
        Allowlist::hard_rules().join(", ")
    );
    match config.internal_domains() {
        [] => out_line!("Rebinding defense: on, with no exempt domains"),
        domains => out_line!(
            "Rebinding defense: on; these domains are exempt (may point inward): {}",
            domains.join(", ")
        ),
    }
    if !config.nat64_prefixes().is_empty() {
        let prefixes: Vec<String> = config
            .nat64_prefixes()
            .iter()
            .map(ToString::to_string)
            .collect();
        out_line!(
            "NAT64 prefixes the rebinding defense also reads: 64:ff9b::/96, {}",
            prefixes.join(", ")
        );
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
        out_line!("The journal keeps {kept} days, so this covers the last {kept}.\n");
    }
    let dates = report::recent_days(journal::unix_now(), &local_zone(), days.min(kept.max(1)));
    let summary = report::Summary::gather(config.journal_dir(), &dates);
    out_line!("{}", summary.render());
    let archive = config.journal_dir().join(report::archive::ARCHIVE_DIR);
    if archive.is_dir() {
        out_line!(
            "Past weekly summaries are kept in {} (12 weeks)",
            archive.display()
        );
    }
    ExitCode::SUCCESS
}

/// The date `days` after `day` (both `YYYY-MM-DD`): the last day a journal file for `day` is
/// kept when the retention is `days`.
fn days_after(day: &str, days: u32) -> String {
    day.parse::<jiff::civil::Date>()
        .ok()
        .and_then(|date| {
            date.checked_add(jiff::Span::new().days(i64::from(days)))
                .ok()
        })
        .map_or_else(
            || format!("{days} days after {day}"),
            |date| date.to_string(),
        )
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

/// Entries in a list file that can never match, which loading drops without a word.
fn unusable_mark(path: &Path) -> String {
    match std::fs::read_to_string(path)
        .map(|text| phylode::policy::blocklist::unusable_entries(&text))
    {
        Ok(0) | Err(_) => String::new(),
        Ok(count) => format!(
            " (warning: {} can never match — wildcards, adblock rules and Unicode not written as \
             xn-- are not supported)",
            plural(count, "entry", "entries")
        ),
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
            .map(|text| journal::printable(&text))
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
            let text = journal::printable(&text);
            facts.events.extend(text.lines().filter_map(|line| {
                let mut fields = line.split('\t');
                Some((fields.next()?.to_string(), fields.next()?.to_string()))
            }));
        }
    }

    out!("{}", diagnostics::render(&facts));
    ExitCode::SUCCESS
}

/// The Mac's time zone, which journal dates and the weekly summary are expressed in. Falls
/// back to UTC, with a warning, when the system zone cannot be read.
fn local_zone() -> LocalZone {
    LocalZone::system().unwrap_or_else(|error| {
        log_line!(
            "Warning: could not read this Mac's time zone, so journal dates are in UTC: {error}"
        );
        LocalZone::utc()
    })
}

fn load_config(path: &Path) -> Option<Config> {
    match Config::load(path) {
        Ok(config) => Some(config),
        Err(error) => {
            log_line!(
                "Could not use the configuration file {}: {error}",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Should change: `--version`, `-V` and `version` ask for the version.
    /// Should not change: an unknown word is still refused, with the usage.
    #[test]
    fn the_version_can_be_asked_for() {
        for word in ["--version", "-V", "version"] {
            let args = vec![word.to_string()];
            assert!(
                matches!(Command::parse(&args), Ok(Command::Version)),
                "{word}"
            );
        }
        let args = vec!["versions".to_string()];
        assert!(Command::parse(&args).is_err());
    }

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
}
