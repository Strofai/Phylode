//! Weekly summary: turns the query journal and service events into the handful of lines
//! the owner reads each week.
//!
//! The seven items and their order are part of the product: changing them changes what
//! the owner is told each week.
//!
//! What breaks if you change it: **items 6 and 7 must never be omitted just because they
//! are usually empty.** They answer "was there a window with no protection?" and "were any
//! records dropped?" — both failures are worse when they happen silently.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fs::File;
use std::hash::Hash;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::journal::{self, EventKind, LocalZone};

pub mod archive;

/// Burst detection multiplier: how many times the median a single device's query count
/// must exceed before it is called out.
///
/// The value is 4 because a HomeKit hub (an Apple TV or HomePod) legitimately queries far
/// more than a phone or laptop. A lower threshold would flag the hub every single day.
/// ⚠️ **This multiplier has not been validated against real multi-device data yet.**
/// Retune it with a real distribution once a whole network is behind the gatekeeper.
const BURST_MULTIPLIER: u64 = 4;

/// Threshold for "keeps asking for the same unfamiliar domain": one device asking for one
/// domain more than this many times.
/// ⚠️ Likewise unvalidated against real data; retune once a whole network is connected.
const REPEAT_THRESHOLD: u64 = 500;

/// How many entries the top-N lists show.
const TOP_N: usize = 10;

/// The most different names (devices, domains, device and domain pairs) one table counts.
/// A household week stays far below it; a flood of made-up names would otherwise grow the
/// tables until the service, which archives each week, runs out of memory. Ours: Apple,
/// Anthropic and Cloudflare publish no figure for this.
const MAX_TRACKED: usize = 100_000;

/// Translates an event code into the sentence the owner reads. Unrecognized codes (kinds
/// retired since an old journal file was written) are printed verbatim — better than the
/// line vanishing, because at least the timestamp shows something happened.
fn event_label(kind: &str) -> &str {
    match EventKind::from_wire(kind) {
        Some(known) => known.label(),
        None => kind,
    }
}

/// How much detail the summary prints.
#[derive(Clone, Copy)]
enum Detail {
    Full,
    Archive,
}

/// A summary over a span of days.
#[derive(Debug, Default)]
pub struct Summary {
    pub days: Vec<String>,
    pub total_queries: u64,
    pub blocked: u64,
    pub blocked_by_client: HashMap<String, u64>,
    pub top_blocked: Vec<(String, u64)>,
    pub queries_by_client: HashMap<String, u64>,
    pub repeat_offenders: Vec<(String, String, u64)>,
    pub fail_open_queries: u64,
    pub failed_queries: u64,
    /// Times the in-flight upstream limit was full, so the query was neither sent nor
    /// served from cache. Should normally be 0.
    pub overloaded_queries: u64,
    /// Times an answer pointed into the local network and the whole response was dropped
    /// (DNS rebinding defence).
    pub rebind_blocked: u64,
    /// Times an upstream signature failed to validate and the answer was refused, plus the
    /// domains involved.
    pub dnssec_bogus: u64,
    pub dnssec_bogus_by_domain: HashMap<String, u64>,
    /// Times an upstream answered but answered with a failure. The upstream is fine —
    /// usually the domain's own authoritative servers are broken.
    pub servfail_queries: u64,
    /// Which domains those answers came from.
    pub rebind_by_domain: HashMap<String, u64>,
    /// Queries answered only because the user allowed the domain with `phylode allow`, by
    /// domain. Apple's hard rules are not counted.
    pub user_allowed_by_domain: HashMap<String, u64>,
    pub events: Vec<(String, String, String)>,
    pub unreadable_files: Vec<String>,
    /// Whether a table reached [`MAX_TRACKED`] names, so later names went uncounted in it.
    /// The totals still count every line.
    pub truncated: bool,
    /// Whether the journal held lookups whose domain the `journal` setting left out.
    pub hidden_domains: bool,
    /// Whether the journal held lookups whose device the `journal` setting left out.
    pub hidden_devices: bool,
}

impl Summary {
    /// Reads the given days out of `directory` and folds them into a summary.
    ///
    /// An unreadable file does not fail the whole operation, but it is recorded in
    /// `unreadable_files` — "some days could not be read" is itself something the owner
    /// needs told.
    pub fn gather(directory: &Path, days: &[String]) -> Self {
        let mut summary = Self {
            days: days.to_vec(),
            ..Default::default()
        };
        let mut blocked_counts: HashMap<String, u64> = HashMap::new();
        let mut per_client_domain: HashMap<(String, String), u64> = HashMap::new();

        for day in days {
            let queries = for_each_line(&journal::queries_file(directory, day), |line| {
                summary.absorb_query(line, &mut blocked_counts, &mut per_client_domain);
            });
            if queries.is_err() {
                summary.unreadable_files.push(format!("{day}.tsv"));
            }
            let events = for_each_line(&journal::events_file(directory, day), |line| {
                summary.absorb_event(line);
            });
            if events.is_err() {
                summary.unreadable_files.push(format!("events-{day}.tsv"));
            }
        }

        summary.top_blocked = top_n(blocked_counts, TOP_N);
        summary.repeat_offenders = per_client_domain
            .into_iter()
            .filter(|(_, count)| *count >= REPEAT_THRESHOLD)
            .map(|((client, domain), count)| (client, domain, count))
            .collect();
        summary
            .repeat_offenders
            .sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        summary
    }

    fn absorb_query(
        &mut self,
        line: &str,
        blocked_counts: &mut HashMap<String, u64>,
        per_client_domain: &mut HashMap<(String, String), u64>,
    ) {
        let fields: Vec<&str> = line.split('\t').collect();
        // Malformed lines are skipped. We write the journal ourselves, but the disk may still
        // corrupt it.
        let [_time, client, name, _record_type, disposition, rest @ ..] = fields.as_slice() else {
            return;
        };
        // What the `journal` setting left out is not counted as a device or domain of its own.
        let device_known = *client != journal::HIDDEN_DEVICE;
        let domain_known = *name != journal::HIDDEN;
        self.hidden_devices |= !device_known;
        self.hidden_domains |= !domain_known;
        let truncated = &mut self.truncated;
        if domain_known && *disposition == "allowed" && rest.first() == Some(&journal::USER_ALLOWED)
        {
            tally(&mut self.user_allowed_by_domain, *name, truncated);
        }

        self.total_queries += 1;
        if device_known {
            tally(&mut self.queries_by_client, *client, truncated);
        }
        if device_known && domain_known {
            tally(
                per_client_domain,
                &((*client).to_string(), (*name).to_string()),
                truncated,
            );
        }

        match *disposition {
            "blocked" => {
                self.blocked += 1;
                if device_known {
                    tally(&mut self.blocked_by_client, *client, truncated);
                }
                if domain_known {
                    tally(blocked_counts, *name, truncated);
                }
            }
            "fail-open" => self.fail_open_queries += 1,
            "failed" => self.failed_queries += 1,
            "overloaded" => self.overloaded_queries += 1,
            "servfail" => self.servfail_queries += 1,
            "dnssec-bogus" => {
                self.dnssec_bogus += 1;
                tally(&mut self.dnssec_bogus_by_domain, *name, truncated);
            }
            "rebind" => {
                self.rebind_blocked += 1;
                tally(&mut self.rebind_by_domain, *name, truncated);
            }
            _ => {}
        }
    }

    fn absorb_event(&mut self, line: &str) {
        let fields: Vec<&str> = line.split('\t').collect();
        let [time, kind, detail, ..] = fields.as_slice() else {
            return;
        };
        if self.events.len() >= MAX_TRACKED {
            self.truncated = true;
            return;
        }
        self.events.push((
            (*time).to_string(),
            (*kind).to_string(),
            (*detail).to_string(),
        ));
    }

    /// Devices whose query count is markedly higher than the others.
    pub fn bursty_clients(&self) -> Vec<(String, u64)> {
        if self.queries_by_client.len() < 2 {
            return Vec::new();
        }
        let mut counts: Vec<u64> = self.queries_by_client.values().copied().collect();
        counts.sort_unstable();
        let median = counts[counts.len() / 2].max(1);

        let mut bursty: Vec<(String, u64)> = self
            .queries_by_client
            .iter()
            .filter(|(_, count)| **count >= median.saturating_mul(BURST_MULTIPLIER))
            .map(|(client, count)| (client.clone(), *count))
            .collect();
        bursty.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        bursty
    }

    /// Whether there was a window with no protection.
    ///
    /// The decision lives in [`EventKind::means_unprotected`]; this function deliberately
    /// does not keep a second list — with two lists, adding an event kind updates only one
    /// of them, and the one left behind fails silently.
    pub fn unprotected_events(&self) -> Vec<&(String, String, String)> {
        self.events
            .iter()
            .filter(|(_, kind, _)| {
                EventKind::from_wire(kind).is_some_and(EventKind::means_unprotected)
            })
            .collect()
    }

    /// Whether any records were dropped.
    pub fn dropped_events(&self) -> Vec<&(String, String, String)> {
        self.events
            .iter()
            .filter(|(_, kind, _)| kind == EventKind::RecordsDropped.as_str())
            .collect()
    }

    /// How many times the service started. More than once means it restarted.
    pub fn restart_count(&self) -> usize {
        self.events
            .iter()
            .filter(|(_, kind, _)| kind == EventKind::Started.as_str())
            .count()
    }

    /// Renders the lines the owner reads — the full version, generated on demand.
    pub fn render(&self) -> String {
        self.render_with(Detail::Full)
    }

    /// The version archived for 12 weeks. For privacy, the archive holds only statistics, blocked domains and the gatekeeper's own health —
    /// **never ordinarily allowed domains**. So "keeps asking for one domain" keeps the
    /// count but not the name; the name lives only in the 10-day detailed journal.
    pub fn render_archive(&self) -> String {
        self.render_with(Detail::Archive)
    }

    fn render_with(&self, detail: Detail) -> String {
        let mut out = String::new();
        let range = match (self.days.first(), self.days.last()) {
            (Some(first), Some(last)) if first != last => format!("{first} to {last}"),
            (Some(only), _) => only.clone(),
            _ => "(no dates given)".to_string(),
        };
        out.push_str(&format!("Phylode, week of {range}\n\n"));

        if self.total_queries == 0 {
            out.push_str("No queries were recorded in this period.\n");
            out.push_str(
                "Either the service is not running, or this machine's resolver has not been \
                 pointed at it yet.\n\n",
            );
        }

        out.push_str(&format!(
            "1. Blocked {} queries ({} total)\n",
            self.blocked, self.total_queries
        ));
        // When the "also blocked N" line below is present, we must not claim "nothing was
        // blocked" — the two sentences would contradict each other.
        if self.blocked == 0 && self.total_queries > 0 && self.rebind_blocked == 0 {
            out.push_str("   Nothing was blocked this week.\n");
        }
        for (client, count) in sorted_desc(&self.blocked_by_client) {
            out.push_str(&format!("   · {client}: {count}\n"));
        }
        if self.hidden_devices && self.blocked > 0 {
            out.push_str(
                "   (the journal setting keeps devices out of the journal, so none are listed)\n",
            );
        }
        // This category differs from a blocklist hit: the list blocks ads and known-bad
        // domains, whereas this is "someone is using a domain name to target devices in
        // your house". It gets its own sentence.
        if self.rebind_blocked > 0 {
            out.push_str(&format!(
                "   Warning: also dropped {} answers pointing at devices inside your network — \
                 that is how a domain name gets used to attack devices on your network\n",
                self.rebind_blocked
            ));
            for (domain, count) in sorted_desc(&self.rebind_by_domain).into_iter().take(TOP_N) {
                out.push_str(&format!("      · {domain}: {count}\n"));
            }
            out.push_str(
                "      If one of these is yours, such as a remote-access name for a device at \
                 home, add `internal_domain = <name>` to the configuration file\n",
            );
        }

        // Not counted as "blocked": no list matched. The domains are named so that a site the
        // household needs, signed wrongly by its owner, can be allowed.
        if self.dnssec_bogus > 0 {
            out.push_str(&format!(
                "   · {} answers failed signature validation and were refused; \
                 `phylode allow <domain>` lets a domain you trust through\n",
                self.dnssec_bogus
            ));
            for (domain, count) in sorted_desc(&self.dnssec_bogus_by_domain)
                .into_iter()
                .take(TOP_N)
            {
                out.push_str(&format!("      · {domain}: {count}\n"));
            }
        }

        out.push_str("\n2. Signs of devices phoning home\n");
        let bursty = self.bursty_clients();
        let unseen = match (self.hidden_devices, self.hidden_domains) {
            (true, true) => Some("devices and domains"),
            (true, false) => Some("devices"),
            (false, true) => Some("domains"),
            (false, false) => None,
        };
        match unseen {
            Some(what) if bursty.is_empty() && self.repeat_offenders.is_empty() => {
                out.push_str(&format!(
                    "   Cannot tell: the journal setting keeps {what} out of the journal.\n"
                ));
            }
            Some(what) => out.push_str(&format!(
                "   Only partly checked: the journal setting keeps {what} out of the journal.\n"
            )),
            None if bursty.is_empty() && self.repeat_offenders.is_empty() => {
                out.push_str("   None.\n");
            }
            None => {}
        }
        for (client, count) in bursty {
            out.push_str(&format!(
                "   · {client} made {count} queries this week, markedly more than the others\n"
            ));
        }
        for (client, domain, count) in self.repeat_offenders.iter().take(TOP_N) {
            match detail {
                Detail::Full => {
                    out.push_str(&format!(
                        "   · {client} keeps asking for {domain} ({count} times)\n"
                    ));
                }
                Detail::Archive => out.push_str(&format!(
                    "   · {client} keeps asking for one domain ({count} times; the name is kept \
                     only in the 10-day detailed journal)\n"
                )),
            }
        }

        out.push_str("\n3. Phylode's own health\n");
        let restarts = self.restart_count();
        if restarts > 1 {
            out.push_str(&format!(
                "   · Started {restarts} times — more than one restart is worth a look\n"
            ));
        } else if restarts == 1 {
            out.push_str("   · Started once, no unexpected restarts\n");
        }
        if self.failed_queries > 0 {
            out.push_str(&format!(
                "   · {} queries failed because every upstream was unreachable\n",
                self.failed_queries
            ));
        }
        if self.servfail_queries > 0 {
            out.push_str(&format!(
                "   · {} queries got a failure from upstream — neither Phylode nor the \
                 upstream is broken; usually those domains' own name servers are\n",
                self.servfail_queries
            ));
        }
        if self.overloaded_queries > 0 {
            out.push_str(&format!(
                "   · {} queries failed because too many were in flight at once — this should \
                 not normally happen, and means some device is flooding queries\n",
                self.overloaded_queries
            ));
        }
        let routine = [EventKind::Started, EventKind::BlocklistLoaded];
        let notable: Vec<&(String, String, String)> = self
            .events
            .iter()
            .filter(|(_, kind, _)| !routine.iter().any(|k| k.as_str() == kind))
            .collect();
        let notable_count = notable.len();
        for (time, kind, detail) in notable {
            out.push_str(&format!("   · {time} {} — {detail}\n", event_label(kind)));
        }
        if restarts <= 1
            && self.failed_queries == 0
            && self.overloaded_queries == 0
            && self.servfail_queries == 0
            && notable_count == 0
        {
            out.push_str("   · Everything else normal\n");
        }

        out.push_str("\n4. Domains you allowed this week\n");
        if self.user_allowed_by_domain.is_empty() {
            if self.hidden_domains {
                out.push_str(
                    "   Cannot tell: the journal setting keeps domains out of the journal.\n",
                );
            } else {
                out.push_str("   None were used (allow one with phylode allow).\n");
            }
        }
        match detail {
            Detail::Full => {
                for (domain, count) in sorted_desc(&self.user_allowed_by_domain)
                    .into_iter()
                    .take(TOP_N)
                {
                    out.push_str(&format!("   · {domain}: {count}\n"));
                }
            }
            Detail::Archive if !self.user_allowed_by_domain.is_empty() => {
                out.push_str(&format!(
                    "   · Allowed domains used: {} (the names are kept only in the \
                     10-day detailed journal)\n",
                    self.user_allowed_by_domain.len()
                ));
            }
            Detail::Archive => {}
        }

        out.push_str(&format!("\n5. Top {TOP_N} most-blocked domains\n"));
        if self.top_blocked.is_empty() {
            if self.hidden_domains && self.blocked > 0 {
                out.push_str(
                    "   Cannot tell: the journal setting keeps domains out of the journal.\n",
                );
            } else {
                out.push_str("   None.\n");
            }
        }
        for (domain, count) in &self.top_blocked {
            out.push_str(&format!("   · {domain}: {count}\n"));
        }

        out.push_str("\n6. Was there a window with no protection?\n");
        let unprotected = self.unprotected_events();
        // The service writes an event every time it starts; a span with no records at all
        // means the journal could not be opened or the service was not running. Saying
        // "protection was continuous" there would be a silent failure.
        let no_records = self.events.is_empty() && self.total_queries == 0;
        if no_records {
            out.push_str(
                "   Warning: cannot tell — there is not a single record for this period (the service \
                 was not running, or the journal directory is not writable).\n",
            );
        } else if unprotected.is_empty() && self.fail_open_queries == 0 {
            out.push_str("   No — protection was continuous.\n");
        } else {
            if self.fail_open_queries > 0 {
                out.push_str(&format!(
                    "   Warning: {} queries were allowed through while the blocklist was unavailable — \
                     nothing was being blocked during that window\n",
                    self.fail_open_queries
                ));
            }
            for (time, kind, detail) in unprotected {
                out.push_str(&format!(
                    "   Warning: {time} {} — {detail}\n",
                    event_label(kind)
                ));
            }
        }

        out.push_str("\n7. Were any records dropped?\n");
        let dropped = self.dropped_events();
        if no_records {
            out.push_str("   Warning: cannot tell — there are no journal files for this period.\n");
        } else if dropped.is_empty() && self.unreadable_files.is_empty() && !self.truncated {
            out.push_str("   No — the journal for this period is complete.\n");
        } else {
            for (time, _, detail) in dropped {
                out.push_str(&format!("   Warning: {time} records dropped: {detail}\n"));
            }
            for file in &self.unreadable_files {
                out.push_str(&format!("   Warning: could not read journal file {file}\n"));
            }
            if self.truncated {
                out.push_str(&format!(
                    "   Warning: the journal named more than {MAX_TRACKED} different devices or \
                     domains, so the lists above leave some out; the totals count every query\n"
                ));
            }
        }

        out
    }
}

/// Date strings for the last `days` days counting back from today, oldest first.
pub fn recent_days(now_unix: i64, zone: &LocalZone, days: u32) -> Vec<String> {
    (0..days)
        .rev()
        .map(|back| zone.days_before(now_unix, i64::from(back)).to_string())
        .collect()
}

/// Hands each line of the file at `path` to `absorb`, control characters replaced, reading a
/// line at a time. A missing file has no lines; any other read failure is returned.
///
/// What breaks if you change it: reading the whole file first holds a day's journal (up to
/// 200 MB) twice over in the service that archives each week.
fn for_each_line(path: &Path, mut absorb: impl FnMut(&str)) -> std::io::Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for line in BufReader::new(file).lines() {
        absorb(&journal::printable(&line?));
    }
    Ok(())
}

/// Adds one to `key`'s count. A key not yet counted is only added while the table holds fewer
/// than [`MAX_TRACKED`]; past that, `truncated` is set.
fn tally<K>(map: &mut HashMap<K::Owned, u64>, key: &K, truncated: &mut bool)
where
    K: ToOwned + Eq + Hash + ?Sized,
    K::Owned: Eq + Hash + Borrow<K>,
{
    if let Some(count) = map.get_mut(key) {
        *count += 1;
    } else if map.len() < MAX_TRACKED {
        map.insert(key.to_owned(), 1);
    } else {
        *truncated = true;
    }
}

fn sorted_desc(map: &HashMap<String, u64>) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    items
}

fn top_n(map: HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = map.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    items.truncate(n);
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERIES: &str = "\
2026-09-14 10:00:00\t127.0.0.1\tads.example.com\tA\tblocked\tblocklist
2026-09-14 10:00:01\t127.0.0.1\tads.example.com\tA\tblocked\tblocklist
2026-09-14 10:00:02\t127.0.0.1\tapple.com\tA\tallowed\t-
2026-09-14 10:00:03\t192.168.0.9\ttracker.example.net\tA\tblocked\tblocklist
2026-09-14 10:00:04\t192.168.0.9\tshop.example.com\tA\tfail-open\tblocklist unavailable, allowing
2026-09-14 10:00:05\t127.0.0.1\trebind.example.org\tA\trebind\tanswer points into the local network
";

    const EVENTS: &str = "\
2026-09-14 09:59:00\tstarted\tPhylode started
2026-09-14 10:00:04\tblocklist-failed\tcould not read the blocklist
2026-09-14 10:05:00\trecords-dropped\tdropped 12 records
";

    fn write_fixture(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("phylode-report-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("2026-09-14.tsv"), QUERIES).unwrap();
        std::fs::write(dir.join("events-2026-09-14.tsv"), EVENTS).unwrap();
        dir
    }

    fn one_day() -> Vec<String> {
        vec!["2026-09-14".to_string()]
    }

    #[test]
    fn counts_blocks_and_which_devices_made_them() {
        let dir = write_fixture("counts");
        let s = Summary::gather(&dir, &one_day());
        assert_eq!(s.total_queries, 6);
        assert_eq!(s.blocked, 3);
        assert_eq!(s.blocked_by_client.get("127.0.0.1"), Some(&2));
        assert_eq!(s.blocked_by_client.get("192.168.0.9"), Some(&1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: domains the user allowed are listed with their counts in the full
    /// summary, and only counted in the archive.
    /// Should not change: Apple's hard rules and ordinary allows are not listed.
    #[test]
    fn item_four_lists_the_domains_the_user_allowed() {
        let dir =
            std::env::temp_dir().join(format!("phylode-report-{}-allowed", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("2026-09-14.tsv"),
            "2026-09-14 10:00:00\t192.168.0.9\tshop.example.com\tA\tallowed\tallowlist\n\
             2026-09-14 10:00:01\t192.168.0.9\tshop.example.com\tAAAA\tallowed\tallowlist\n\
             2026-09-14 10:00:02\t192.168.0.9\tcaptive.apple.com\tA\tallowed\tApple service, always allowed\n\
             2026-09-14 10:00:03\t192.168.0.9\tnews.example.org\tA\tallowed\t-\n",
        )
        .unwrap();
        let s = Summary::gather(&dir, &one_day());
        let _ = std::fs::remove_dir_all(&dir);

        let full = s.render();
        let item = &full[full.find("4. Domains").unwrap()..full.find("5. Top").unwrap()];
        assert!(item.contains("· shop.example.com: 2"), "{item}");
        assert!(!item.contains("captive.apple.com"), "{item}");
        assert!(!item.contains("news.example.org"), "{item}");

        let archive = s.render_archive();
        let item = &archive[archive.find("4. Domains").unwrap()..archive.find("5. Top").unwrap()];
        assert!(item.contains("Allowed domains used: 1 "), "{item}");
        assert!(!item.contains("shop.example.com"), "{item}");
    }

    #[test]
    fn most_blocked_domain_sorts_first() {
        let dir = write_fixture("top");
        let s = Summary::gather(&dir, &one_day());
        assert_eq!(s.top_blocked[0], ("ads.example.com".to_string(), 2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allows_during_blocklist_outage_are_counted_separately() {
        // Item 6 has to be able to say "there was no protection during this window", so
        // these must not be mixed in with ordinary allows.
        let dir = write_fixture("failopen");
        let s = Summary::gather(&dir, &one_day());
        assert_eq!(s.fail_open_queries, 1);
        assert_eq!(s.unprotected_events().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: an update that could not be used while the previous list kept blocking
    /// is listed under Phylode's own health, not as a window with no protection.
    /// Should not change: having no list at all still counts as a window with no protection
    /// (the control, from the shared fixture).
    #[test]
    fn a_refused_update_with_the_previous_list_kept_is_not_a_gap() {
        let dir = std::env::temp_dir().join(format!("phylode-report-{}-kept", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("2026-09-14.tsv"),
            QUERIES.replace("fail-open", "allowed"),
        )
        .unwrap();
        std::fs::write(
            dir.join("events-2026-09-14.tsv"),
            "2026-09-14 09:59:00\tstarted\tPhylode started\n\
             2026-09-14 10:00:04\tblocklist-kept\tblocklist list.txt is larger than 64 MB\n",
        )
        .unwrap();
        let s = Summary::gather(&dir, &one_day());
        assert!(s.unprotected_events().is_empty());
        let text = s.render();
        let item_three = &text[text.find("3. ").unwrap()..text.find("4. ").unwrap()];
        assert!(
            item_three.contains("blocking continued with the lists already loaded"),
            "{item_three}"
        );
        assert!(text.contains("No — protection was continuous."), "{text}");
        let _ = std::fs::remove_dir_all(&dir);

        let control = write_fixture("kept-control");
        assert_eq!(
            Summary::gather(&control, &one_day())
                .unprotected_events()
                .len(),
            1
        );
        let _ = std::fs::remove_dir_all(&control);
    }

    #[test]
    fn answers_dropped_for_pointing_inward_are_counted_separately() {
        // This is not the same thing as a blocklist hit; merged together, an attack on the
        // local network becomes invisible.
        let dir = write_fixture("rebind");
        let s = Summary::gather(&dir, &one_day());
        assert_eq!(s.rebind_blocked, 1);
        assert_eq!(s.rebind_by_domain.get("rebind.example.org"), Some(&1));
        assert_eq!(s.blocked, 3, "it must not count towards blocklist hits");

        let text = s.render();
        assert!(
            text.contains("pointing at devices inside your network"),
            "the weekly summary must say this; actual output:\n{text}"
        );
        assert!(text.contains("rebind.example.org"));
        assert!(
            !text.contains("Nothing was blocked this week"),
            "with 0 blocklist hits but a blocked attack, this line contradicts the next one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: bogus-signature counts and domains are visible, and upstream
    /// failures get their own line.
    /// Should not change: neither is described as "blocked", nor merged into "every
    /// upstream unreachable".
    #[test]
    fn bogus_signatures_and_upstream_failures_are_reported_separately() {
        let s = Summary {
            dnssec_bogus: 2,
            dnssec_bogus_by_domain: HashMap::from([("dnssec-failed.org".to_string(), 2)]),
            servfail_queries: 1,
            ..Summary::default()
        };
        let text = s.render();
        assert!(
            text.contains("2 answers failed signature validation"),
            "{text}"
        );
        assert!(text.contains("dnssec-failed.org: 2"), "{text}");
        assert!(text.contains("`phylode allow <domain>`"), "{text}");
        assert!(
            text.contains("1 queries got a failure from upstream"),
            "{text}"
        );
        assert!(!text.contains("every upstream was unreachable"), "{text}");
    }

    /// Should change: overload count gets its own line.
    /// Should not change: it is not merged into "every upstream unreachable".
    #[test]
    fn overloaded_queries_are_reported_on_their_own() {
        let s = Summary {
            overloaded_queries: 3,
            ..Summary::default()
        };
        let text = s.render();
        assert!(
            text.contains("3 queries failed because too many were in flight"),
            "{text}"
        );
        assert!(!text.contains("every upstream was unreachable"), "{text}");
        assert!(!text.contains("Everything else normal"), "{text}");
    }

    /// Should change: escape sequences planted in the journal files reach the summary as `_`.
    /// Should not change: the event and the device are still reported.
    #[test]
    fn control_characters_in_the_journal_are_not_printed() {
        let dir = std::env::temp_dir().join(format!("phylode-report-{}-esc", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("2026-09-14.tsv"),
            "2026-09-14 10:00:00\t10.0.0.\x1b[2J5\tads.example.com\tA\tblocked\tlist\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("events-2026-09-14.tsv"),
            "2026-09-14 10:00:00\tblocklist-failed\tgone\x1b]0;owned\x07\n",
        )
        .unwrap();
        let text = Summary::gather(&dir, &one_day()).render();
        assert!(
            !text.chars().any(|c| c == '\x1b' || c == '\x07'),
            "{text:?}"
        );
        assert!(text.contains("10.0.0._[2J5"), "{text}");
        assert!(text.contains("gone_]0;owned_"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_quiet_week_does_not_mention_rebinding() {
        // The "should not change" column: a normal week must not sprout a warning line.
        let s = Summary::default();
        assert!(
            !s.render()
                .contains("pointing at devices inside your network")
        );
    }

    #[test]
    fn dropped_records_are_visible() {
        let dir = write_fixture("dropped");
        let s = Summary::gather(&dir, &one_day());
        assert_eq!(s.dropped_events().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_period_does_not_render_a_blank_report() {
        // "Nothing has been blocked yet" must be said outright, not left as whitespace.
        let dir = std::env::temp_dir().join(format!("phylode-report-{}-empty", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let text = Summary::gather(&dir, &one_day()).render();
        assert!(text.contains("No queries were recorded"));
        // With no records at all, claiming "protection was continuous" or "the journal is
        // complete" would be a silent failure.
        assert!(!text.contains("protection was continuous"));
        assert!(!text.contains("journal for this period is complete"));
        assert!(text.contains("Warning: cannot tell"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn all_seven_items_appear_in_the_output() {
        let dir = write_fixture("render");
        let text = Summary::gather(&dir, &one_day()).render();
        for marker in ["1. ", "2. ", "3. ", "4. ", "5. ", "6. ", "7. "] {
            assert!(text.contains(marker), "item {marker} is missing");
        }
        assert!(
            text.contains("Warning:"),
            "an unprotected window must carry a warning marker"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_single_device_never_counts_as_a_burst() {
        // v1 serves only the local machine; with one device there is nothing to compare
        // against, so it must not report anything.
        let mut s = Summary::default();
        s.queries_by_client.insert("127.0.0.1".to_string(), 99_999);
        assert!(s.bursty_clients().is_empty());
    }

    #[test]
    fn recent_days_includes_today_and_runs_oldest_first() {
        let days = recent_days(1_789_388_676, &LocalZone::fixed_hours(8), 3);
        assert_eq!(days, ["2026-09-12", "2026-09-13", "2026-09-14"]);
    }

    /// Should change: a journal naming more devices than the tables hold stops adding new
    /// ones, says so in item 7, and still counts every query. Should not change: the ordinary
    /// fixture is reported complete.
    #[test]
    fn a_flood_of_new_names_is_capped_and_reported() {
        let ordinary = Summary::gather(&write_fixture("ordinary"), &one_day());
        assert!(!ordinary.truncated);

        let dir = write_fixture("flood");
        let extra = 5;
        let flood: String = (0..MAX_TRACKED + extra)
            .map(|n| {
                format!(
                    "2026-09-14 11:00:00\t10.{}.{}.{}\tapple.com\tA\tallowed\t-\n",
                    n >> 16,
                    (n >> 8) & 255,
                    n & 255
                )
            })
            .collect();
        std::fs::write(dir.join("2026-09-14.tsv"), flood).unwrap();
        std::fs::write(dir.join("events-2026-09-14.tsv"), "").unwrap();

        let s = Summary::gather(&dir, &one_day());
        assert_eq!(s.total_queries, 100_005);
        assert_eq!(s.queries_by_client.len(), 100_000);
        assert!(s.truncated);
        let text = s.render();
        assert!(text.contains("leave some out; the totals count every query"));
        assert!(!text.contains("journal for this period is complete"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Should change: a journal kept at Domains lists no device (none as 0.0.0.0) and says it
    /// cannot tell which devices phone home; blocked and allowed domains are still counted.
    /// Should not change: an ordinary journal is checked as before.
    #[test]
    fn a_domains_journal_reports_devices_as_unknown() {
        let ordinary = Summary::gather(&write_fixture("seen"), &one_day()).render();
        assert!(!ordinary.contains("Cannot tell: the journal setting"));

        let dir = write_fixture("domains");
        let lines = "\
2026-09-14 10:00:00\t0.0.0.0\tshop.example.com\tA\tallowed\t-
2026-09-14 10:00:01\t0.0.0.0\tok.example.com\tA\tallowed\tallowlist
2026-09-14 10:00:02\t0.0.0.0\tads.example.com\tA\tblocked\tblocklist
";
        std::fs::write(dir.join("2026-09-14.tsv"), lines).unwrap();
        let s = Summary::gather(&dir, &one_day());
        assert_eq!((s.total_queries, s.blocked), (3, 1));
        assert!(s.queries_by_client.is_empty());
        let text = s.render();
        assert!(text.contains("   · ads.example.com: 1"), "{text}");
        assert!(!text.contains("0.0.0.0:"), "{text}");
        assert!(
            text.contains("   Cannot tell: the journal setting keeps devices out of the journal."),
            "{text}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Should change: a journal kept at Zero lists no device and no domain — not even "-" as
    /// the most-blocked domain — and says it cannot tell instead of "none".
    /// Should not change: the totals are still counted.
    #[test]
    fn a_zero_journal_reports_only_totals() {
        let dir = write_fixture("zero");
        let lines = "\
2026-09-14 00:00:00\t0.0.0.0\t-\t-\tallowed\t-
2026-09-14 00:00:00\t0.0.0.0\t-\t-\tallowed\t-
2026-09-14 00:00:00\t0.0.0.0\t-\t-\tblocked\t-
";
        std::fs::write(dir.join("2026-09-14.tsv"), lines).unwrap();
        let s = Summary::gather(&dir, &one_day());
        assert_eq!((s.total_queries, s.blocked), (3, 1));
        assert!(s.top_blocked.is_empty() && s.queries_by_client.is_empty());
        let text = s.render();
        assert!(!text.contains("   · -:"), "{text}");
        assert!(!text.contains("0.0.0.0:"), "{text}");
        assert!(
            text.contains(
                "   Cannot tell: the journal setting keeps devices and domains out of the journal."
            ),
            "{text}"
        );
        assert!(
            text.contains("   Cannot tell: the journal setting keeps domains out of the journal."),
            "{text}"
        );
        assert!(!text.contains("None were used"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
