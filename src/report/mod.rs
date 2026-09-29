//! Weekly summary: turns the query journal and service events into the handful of lines
//! the owner reads each week.
//!
//! The seven items and their order are part of the product: changing them changes what
//! the owner is told each week.
//!
//! What breaks if you change it: **items 6 and 7 must never be omitted just because they
//! are usually empty.** They answer "was there a window with no protection?" and "were any
//! records dropped?" — both failures are worse when they happen silently.

use std::collections::HashMap;
use std::path::Path;

use crate::journal::{Civil, EventKind};

pub mod archive;

/// Burst detection multiplier: how many times the median a single device's query count
/// must exceed before it is called out.
///
/// The value is 4 because a HomeKit hub (an Apple TV or HomePod) legitimately queries far
/// more than a phone or laptop. A lower threshold would flag the hub every single day.
/// ⚠️ **This multiplier has not been validated against real multi-device data yet.**
/// Retune it with a real distribution once the whole household is behind the gatekeeper.
const BURST_MULTIPLIER: u64 = 4;

/// Threshold for "keeps asking for the same unfamiliar domain": one device asking for one
/// domain more than this many times.
/// ⚠️ Likewise unvalidated against real data; retune once the household is connected.
const REPEAT_THRESHOLD: u64 = 500;

/// How many entries the top-N lists show.
const TOP_N: usize = 10;

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
    /// Times an answer pointed into the home network and the whole response was dropped
    /// (DNS rebinding defence).
    pub rebind_blocked: u64,
    /// Times an upstream signature failed to validate and the answer was allowed through
    /// per configuration, plus the domains involved (report-only mode).
    pub dnssec_bogus: u64,
    pub dnssec_bogus_by_domain: HashMap<String, u64>,
    /// Times an upstream answered but answered with a failure. The upstream is fine —
    /// usually the domain's own authoritative servers are broken.
    pub servfail_queries: u64,
    /// Which domains those answers came from.
    pub rebind_by_domain: HashMap<String, u64>,
    pub events: Vec<(String, String, String)>,
    pub unreadable_files: Vec<String>,
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
            match std::fs::read_to_string(directory.join(format!("{day}.tsv"))) {
                Ok(text) => {
                    summary.absorb_queries(&text, &mut blocked_counts, &mut per_client_domain);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => summary.unreadable_files.push(format!("{day}.tsv")),
            }

            match std::fs::read_to_string(directory.join(format!("events-{day}.tsv"))) {
                Ok(text) => summary.absorb_events(&text),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => summary.unreadable_files.push(format!("events-{day}.tsv")),
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

    fn absorb_queries(
        &mut self,
        text: &str,
        blocked_counts: &mut HashMap<String, u64>,
        per_client_domain: &mut HashMap<(String, String), u64>,
    ) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            // Malformed lines are skipped. We write the journal ourselves, but the disk
            // may still corrupt it.
            let [_time, client, name, _record_type, disposition, ..] = fields.as_slice() else {
                continue;
            };

            self.total_queries += 1;
            *self
                .queries_by_client
                .entry((*client).to_string())
                .or_default() += 1;
            *per_client_domain
                .entry(((*client).to_string(), (*name).to_string()))
                .or_default() += 1;

            match *disposition {
                "blocked" => {
                    self.blocked += 1;
                    *self
                        .blocked_by_client
                        .entry((*client).to_string())
                        .or_default() += 1;
                    *blocked_counts.entry((*name).to_string()).or_default() += 1;
                }
                "fail-open" => self.fail_open_queries += 1,
                "failed" => self.failed_queries += 1,
                "overloaded" => self.overloaded_queries += 1,
                "servfail" => self.servfail_queries += 1,
                "dnssec-bogus" => {
                    self.dnssec_bogus += 1;
                    *self
                        .dnssec_bogus_by_domain
                        .entry((*name).to_string())
                        .or_default() += 1;
                }
                "rebind" => {
                    self.rebind_blocked += 1;
                    *self
                        .rebind_by_domain
                        .entry((*name).to_string())
                        .or_default() += 1;
                }
                _ => {}
            }
        }
    }

    fn absorb_events(&mut self, text: &str) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            let [time, kind, detail, ..] = fields.as_slice() else {
                continue;
            };
            self.events.push((
                (*time).to_string(),
                (*kind).to_string(),
                (*detail).to_string(),
            ));
        }
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
        out.push_str(&format!("Gatekeeper, week of {range}\n\n"));

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
        // This category differs from a blocklist hit: the list blocks ads and known-bad
        // domains, whereas this is "someone is using a domain name to target devices in
        // your house". It gets its own sentence.
        if self.rebind_blocked > 0 {
            out.push_str(&format!(
                "   ⚠️ Also dropped {} answers pointing at devices inside your network — \
                 that is how a domain name gets used to attack your home devices\n",
                self.rebind_blocked
            ));
            for (domain, count) in sorted_desc(&self.rebind_by_domain).into_iter().take(TOP_N) {
                out.push_str(&format!("      · {domain}: {count}\n"));
            }
        }

        // DNSSEC is in report-only mode, so this reports "how many and which domains"
        // rather than "blocked". Whether to start enforcing is a decision to make once
        // this number is known.
        if self.dnssec_bogus > 0 {
            out.push_str(&format!(
                "   · {} answers failed signature validation (allowed through per your \
                 configuration, recorded only)\n",
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
        if bursty.is_empty() && self.repeat_offenders.is_empty() {
            out.push_str("   None.\n");
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

        out.push_str("\n3. The gatekeeper's own health\n");
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
                "   · {} queries got a failure from upstream — neither the gatekeeper nor the \
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
        out.push_str("   (allowed with phylode allow; see the current list with phylode status)\n");

        out.push_str(&format!("\n5. Top {TOP_N} most-blocked domains\n"));
        if self.top_blocked.is_empty() {
            out.push_str("   None.\n");
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
                "   ⚠️ Cannot tell — there is not a single record for this period (the service \
                 was not running, or the journal directory is not writable).\n",
            );
        } else if unprotected.is_empty() && self.fail_open_queries == 0 {
            out.push_str("   No — protection was continuous.\n");
        } else {
            if self.fail_open_queries > 0 {
                out.push_str(&format!(
                    "   ⚠️ {} queries were allowed through while the blocklist was unavailable — \
                     nothing was being blocked during that window\n",
                    self.fail_open_queries
                ));
            }
            for (time, kind, detail) in unprotected {
                out.push_str(&format!("   ⚠️ {time} {} — {detail}\n", event_label(kind)));
            }
        }

        out.push_str("\n7. Were any records dropped?\n");
        let dropped = self.dropped_events();
        if no_records {
            out.push_str("   ⚠️ Cannot tell — there are no journal files for this period.\n");
        } else if dropped.is_empty() && self.unreadable_files.is_empty() {
            out.push_str("   No — the journal for this period is complete.\n");
        } else {
            for (time, _, detail) in dropped {
                out.push_str(&format!("   ⚠️ {time} records dropped: {detail}\n"));
            }
            for file in &self.unreadable_files {
                out.push_str(&format!("   ⚠️ Could not read journal file {file}\n"));
            }
        }

        out
    }
}

/// Date strings for the last `days` days counting back from today, oldest first.
pub fn recent_days(now_unix: i64, offset_hours: i32, days: u32) -> Vec<String> {
    (0..days)
        .rev()
        .map(|back| {
            let seconds = now_unix - i64::from(back) * 86_400;
            Civil::from_unix(seconds, offset_hours).date_string()
        })
        .collect()
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
2026-09-14 10:00:05\t127.0.0.1\trebind.example.org\tA\trebind\tanswer points into the home network
";

    const EVENTS: &str = "\
2026-09-14 09:59:00\tstarted\tphylode started
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

    #[test]
    fn answers_dropped_for_pointing_inward_are_counted_separately() {
        // This is not the same thing as a blocklist hit; merged together, an attack on the
        // home network becomes invisible.
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
        assert!(text.contains("Cannot tell"));
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
            text.contains("⚠️"),
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
        let days = recent_days(1_789_388_676, 8, 3);
        assert_eq!(days, ["2026-09-12", "2026-09-13", "2026-09-14"]);
    }
}
