//! Query journal: the answer path drops a record into a channel and moves on; a dedicated
//! thread batches them to disk.
//!
//! What breaks if you change it: **no file I/O is allowed on the DNS answer path** — touching the disk inside
//! [`Journal::record`] makes everyone's web browsing track how busy the disk is.
//!
//! The channel is deliberately **bounded**. When it fills, records are dropped and
//! counted, never blocked — there is no unbounded queue anywhere, and losing a record is
//! far better than stalling a query.

mod civil;
mod writer;

use std::borrow::Cow;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::time::{Duration, SystemTime};

pub use civil::{Civil, LocalZone};
pub(crate) use writer::{DIR_MODE, FILE_MODE};
pub use writer::{FLUSH_INTERVAL, WriterError};

/// Channel capacity. What breaks if you change it: this is the buffer that absorbs a busy
/// disk. Larger costs memory; smaller drops more records at peak.
const CHANNEL_CAPACITY: usize = 4096;

/// Places in the channel query records may never take, kept for service events and flushes.
/// What breaks if you change it: with none, a flood of queries fills the channel and the event
/// saying why the service restarted, or that every upstream failed, is the one dropped.
const EVENT_RESERVE: usize = 256;

/// How a query was ultimately handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Blocklist hit; blocked.
    Blocked,
    /// Checked against the list and allowed.
    Allowed,
    /// The list was unavailable, so the query was allowed to keep the network online.
    /// **This category must stay visible** — the weekly summary has to be able to say
    /// "there was no protection during this window".
    FailOpen,
    /// Every upstream was down and the cache could not cover it; answered with a failure.
    Failed,
    /// The in-flight upstream limit was full, so this query neither reached an upstream nor
    /// hit the cache; answered with a failure. Kept separate from [`Disposition::Failed`]
    /// because the cause differs: the upstreams are fine, the gatekeeper is saturated.
    Overloaded,
    /// An upstream answered, but answered SERVFAIL (including on the CD retry). The
    /// upstream is fine; usually the domain's own name servers are broken.
    ServFail,
    /// Upstream signature validation failed (the CD retry returned an answer), so the device
    /// got SERVFAIL. A domain the user allowed is journalled as allowed instead.
    /// **This must stay distinct from a blocklist hit** — the weekly summary lists these
    /// domains so a wrongly signed site the household needs can be allowed.
    DnssecBogus,
    /// The upstream answer pointed at an address inside the local network, so the whole
    /// response was dropped (DNS rebinding defence).
    /// **This must stay distinct from a blocklist hit** — it means someone is using a
    /// domain name to attack devices on the network, not that an ad domain showed up.
    Rebind,
    /// A name that only means something inside the network (`.local`, `home.arpa`, private
    /// address reverse lookups), answered locally with "no such domain" and never sent
    /// upstream. **Not counted as blocked** — the weekly "blocked N" excludes these.
    Local,
}

impl Disposition {
    /// The code written into the journal file. This is part of the file format; changing
    /// it makes existing files unreadable.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Allowed => "allowed",
            Self::FailOpen => "fail-open",
            Self::Failed => "failed",
            Self::Overloaded => "overloaded",
            Self::ServFail => "servfail",
            Self::DnssecBogus => "dnssec-bogus",
            Self::Rebind => "rebind",
            Self::Local => "local",
        }
    }
}

/// Something that happened to the service itself, written to a file separate from queries.
///
/// Items 3, 6 and 7 of the weekly summary rely on these. What breaks if you change it:
/// printing these to the console is not enough — console output is swallowed by launchd
/// into the system log, which nobody reads, while the weekly summary has to be able to
/// say "there was no protection during this window".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// The service started. Repeated occurrences mean it keeps restarting.
    Started,
    /// Received a stop signal, flushed the journal and exited cleanly (update, shutdown,
    /// manual stop). Its presence between two "started" entries means that restart was
    /// deliberate, not a crash.
    Stopped,
    /// The blocklist loaded successfully.
    BlocklistLoaded,
    /// No blocklist could be loaded and none was loaded before — **nothing is being blocked
    /// during this window**.
    BlocklistFailed,
    /// A blocklist update could not be used, so the list loaded before stays in use and
    /// blocking continues. Repeated occurrences mean the daily update keeps failing.
    BlocklistKept,
    /// The allowlist could not be read (a missing file does not count) — domains the user
    /// allowed may be blocked again during this window.
    AllowlistFailed,
    /// Every upstream is unreachable — only the cache is holding things up.
    UpstreamsDown,
    /// An upstream recovered.
    UpstreamsRecovered,
    /// Records were dropped (the channel filled), with the count.
    RecordsDropped,
    /// One device queried too often within a window, so the rest of that window goes
    /// unanswered for it. Recorded once per window; `detail` names the device.
    RateLimited,
    /// A device outside the networks the service answers for asked and got no response.
    /// Recorded once per source; `detail` names it. A device on the network landing here
    /// means `serve_network` needs its range.
    OutsideClient,
    /// The self health check failed repeatedly and the service exited so the system would
    /// restart it. **Nothing on the network can resolve any name during this window**, which
    /// is worse than having no filtering.
    Unresponsive,
}

/// Every event kind. A new kind must be added here or the weekly summary will not
/// recognize it. Used by [`EventKind::from_wire`], which has a test guarding against
/// omissions.
const ALL_EVENT_KINDS: [EventKind; 12] = [
    EventKind::Started,
    EventKind::Stopped,
    EventKind::BlocklistLoaded,
    EventKind::BlocklistFailed,
    EventKind::BlocklistKept,
    EventKind::AllowlistFailed,
    EventKind::UpstreamsDown,
    EventKind::UpstreamsRecovered,
    EventKind::RecordsDropped,
    EventKind::RateLimited,
    EventKind::OutsideClient,
    EventKind::Unresponsive,
];

impl EventKind {
    /// The code written into the journal file. This is part of the file format; changing
    /// it makes existing files unreadable.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Stopped => "stopped",
            Self::BlocklistLoaded => "blocklist-loaded",
            Self::BlocklistFailed => "blocklist-failed",
            Self::BlocklistKept => "blocklist-kept",
            Self::AllowlistFailed => "allowlist-failed",
            Self::UpstreamsDown => "upstreams-down",
            Self::UpstreamsRecovered => "upstreams-recovered",
            Self::RecordsDropped => "records-dropped",
            Self::RateLimited => "rate-limited",
            Self::OutsideClient => "outside-client",
            Self::Unresponsive => "unresponsive",
        }
    }

    /// Recognizes a code read back from a journal file. Returns `None` for unknown codes —
    /// an old journal file may contain kinds that no longer exist, and that must not make
    /// the weekly summary fail.
    pub fn from_wire(text: &str) -> Option<Self> {
        ALL_EVENT_KINDS.into_iter().find(|k| k.as_str() == text)
    }

    /// The plain-language form. **The weekly summary prints this, not the wire code above.**
    /// What breaks if you change it: for anyone who does not read the source, this line is
    /// all they see of the event.
    pub fn label(self) -> &'static str {
        match self {
            Self::Started => "service started",
            Self::Stopped => "service stopped normally (update, shutdown or manual stop)",
            Self::BlocklistLoaded => "blocklist loaded",
            Self::BlocklistFailed => {
                "no blocklist could be loaded; nothing was blocked during this window"
            }
            Self::BlocklistKept => {
                "a blocklist could not be used; blocking continued with the lists already loaded"
            }
            Self::AllowlistFailed => {
                "allowlist could not be read; domains you allowed may have been blocked again \
                 during this window (Apple's hard rules still applied)"
            }
            Self::UpstreamsDown => "every upstream server was unreachable; only the cache held",
            Self::UpstreamsRecovered => "upstream servers recovered",
            Self::RecordsDropped => "records were dropped",
            Self::RateLimited => {
                "one device queried too frequently; the rest of that minute went unanswered for it"
            }
            Self::Unresponsive => "Phylode stopped answering and restarted itself",
            Self::OutsideClient => {
                "a device outside the networks this serves asked and got no answer; if it is \
                 yours, add its range with serve_network"
            }
        }
    }

    /// Whether the network was unprotected while this was happening.
    ///
    /// What breaks if you change it: item 6 of the weekly summary ("was there a window with
    /// no protection?") reads this. Adding an event kind without revisiting this function
    /// makes that unprotected window disappear silently.
    pub fn means_unprotected(self) -> bool {
        match self {
            // No list means nothing is blocked; no answers means nothing resolves at all.
            // Both must be visible.
            Self::BlocklistFailed | Self::UpstreamsDown | Self::Unresponsive => true,
            Self::Started
            // A deliberate stop; the gap afterwards is visible from the absence of the next
            // "started" entry.
            | Self::Stopped
            | Self::BlocklistLoaded
            // The previous list kept blocking; only the update was lost.
            | Self::BlocklistKept
            | Self::UpstreamsRecovered
            | Self::RecordsDropped
            // This blocks more than usual, not less; protection is not interrupted.
            | Self::AllowlistFailed
            // Affects one device only, and it will mostly just ask another resolver;
            // protection is not interrupted.
            | Self::RateLimited
            // Not a device this service is for.
            | Self::OutsideClient => false,
        }
    }
}

/// One service event.
#[derive(Clone, Debug)]
pub struct Event {
    pub at: SystemTime,
    pub kind: EventKind,
    /// Human-readable detail.
    pub detail: String,
}

/// One query to be journalled.
#[derive(Clone, Debug)]
pub struct Record {
    pub at: SystemTime,
    pub client: IpAddr,
    pub name: String,
    pub record_type: Cow<'static, str>,
    pub disposition: Disposition,
    /// Why it was handled that way — for instance, which list matched. Empty when there is
    /// no reason to give.
    pub reason: Cow<'static, str>,
}

/// The reason written for a query answered because the user allowed it with `phylode allow`.
/// The weekly summary counts these, so changing it empties that item for journals already
/// written.
pub const USER_ALLOWED: &str = "allowlist";

/// What flows through the channel: a query record or a service event.
#[derive(Clone, Debug)]
pub enum Entry {
    Query(Record),
    Event(Event),
    /// Write everything queued ahead of it to disk, then report back through this channel.
    /// See [`Journal::flush_blocking`].
    Flush(std::sync::mpsc::Sender<()>),
}

/// The journal handle. Cloning is cheap; clones share one channel.
#[derive(Clone, Debug)]
pub struct Journal {
    sender: SyncSender<Entry>,
    dropped: Arc<AtomicU64>,
    /// Query records in the channel, so they can be kept out of the events' reserve.
    queued: Arc<AtomicUsize>,
}

impl Journal {
    /// Opens the channel and starts the writer thread.
    ///
    /// `zone` decides where journal files split by date and when expiry runs.
    pub fn start(
        directory: PathBuf,
        retention_days: u32,
        zone: LocalZone,
    ) -> Result<Self, WriterError> {
        let (sender, receiver) = sync_channel(CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let queued = Arc::new(AtomicUsize::new(0));
        writer::spawn(
            receiver,
            directory,
            retention_days,
            zone,
            Arc::clone(&dropped),
            Arc::clone(&queued),
        )?;
        Ok(Self {
            sender,
            dropped,
            queued,
        })
    }

    /// Records something that happened to the service itself. Shares the channel with query
    /// records but is written to a different file.
    pub fn event(&self, kind: EventKind, detail: impl Into<String>) {
        self.send(Entry::Event(Event {
            at: SystemTime::now(),
            kind,
            detail: detail.into(),
        }));
    }

    /// Drops a record into the channel. **This function never touches the disk and never
    /// blocks.**
    pub fn record(&self, record: Record) {
        if self.queued.fetch_add(1, Ordering::Relaxed) >= CHANNEL_CAPACITY - EVENT_RESERVE {
            self.queued.fetch_sub(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.send(Entry::Query(record)) {
            self.queued.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Whether the entry went into the channel.
    fn send(&self, entry: Entry) -> bool {
        match self.sender.try_send(entry) {
            Ok(()) => true,
            // The channel is full, or the writer thread is gone. Drop this one and count
            // it — stalling queries would be the worse outcome.
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Writes everything queued up to this moment to disk and returns once it is done;
    /// returns `false` if it waits longer than `timeout`.
    ///
    /// Use before exiting the process. What breaks if you change it: `process::exit` runs
    /// no destructors and does not close the channel, so exiting without this step loses
    /// the last batch (up to [`FLUSH_INTERVAL`] worth) of records.
    /// It blocks the calling thread; wrap it in `spawn_blocking` inside async code.
    pub fn flush_blocking(&self, timeout: Duration) -> bool {
        let (done, finished) = std::sync::mpsc::channel();
        if self.sender.send(Entry::Flush(done)).is_err() {
            return false;
        }
        finished.recv_timeout(timeout).is_ok()
    }

    /// How many records have been dropped so far. The writer thread turns this count into
    /// "records dropped" events, which is how it reaches the weekly summary.
    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Formats an event as one TSV line: time, kind, detail.
fn format_event(event: &Event, zone: &LocalZone) -> String {
    let civil = Civil::from_unix(unix_seconds(event.at), zone);
    format!(
        "{}\t{}\t{}\n",
        civil.timestamp_string(),
        event.kind.as_str(),
        sanitize(&event.detail),
    )
}

/// What an event file's name starts with; a query file's name is the date alone.
/// What breaks if you change it: files already on disk keep the old name, so their events stop
/// appearing in the weekly summary and are never cleaned up.
const EVENTS_PREFIX: &str = "events-";

/// The file one day's queries are written to (`day` as `YYYY-MM-DD`).
pub fn queries_file(directory: &Path, day: &str) -> PathBuf {
    directory.join(format!("{day}.tsv"))
}

/// The file one day's service events are written to (`day` as `YYYY-MM-DD`).
pub fn events_file(directory: &Path, day: &str) -> PathBuf {
    directory.join(format!("{EVENTS_PREFIX}{day}.tsv"))
}

/// Whole seconds since the Unix epoch, the form every journal date is computed from. A clock
/// set before 1970 reads as 0.
pub fn unix_seconds(at: SystemTime) -> i64 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// [`unix_seconds`] for the current moment.
pub fn unix_now() -> i64 {
    unix_seconds(SystemTime::now())
}

/// Formats a record as one TSV line. The field order is fixed; changing it makes existing
/// files inconsistent with new ones.
fn format_line(record: &Record, zone: &LocalZone) -> String {
    let civil = Civil::from_unix(unix_seconds(record.at), zone);
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\n",
        civil.timestamp_string(),
        record.client,
        sanitize(&record.name),
        sanitize(&record.record_type),
        record.disposition.as_str(),
        sanitize(&record.reason),
    )
}

/// Strips characters that would break "one record per line, one field per column"; empty
/// values become `-`.
///
/// What breaks if you change it: domain names come off the network and are untrusted input.
/// Without this substitution, a name containing a newline could forge an entire query entry
/// in the journal. Empty values become `-` because a trailing empty column is swallowed by
/// any reader that trims whitespace, silently shortening the row.
/// Text read back from the journal directory, made safe to print: control characters other
/// than tabs and line breaks become `_`.
///
/// What breaks if you change it: the service account can write those files, so whoever took
/// it over could hide terminal escape sequences in them; printed as read, they would act on
/// the administrator's terminal. `sanitize` only covers what this program writes.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\t' && c != '\n' {
                '_'
            } else {
                c
            }
        })
        .collect()
}

fn sanitize(value: &str) -> String {
    if value.is_empty() {
        return "-".to_string();
    }
    value
        .chars()
        .map(|c| if c.is_control() || c == '\t' { '_' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn record(name: &str, disposition: Disposition) -> Record {
        Record {
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_789_388_676),
            client: "127.0.0.1".parse().unwrap(),
            name: name.to_string(),
            record_type: "A".into(),
            disposition,
            reason: "".into(),
        }
    }

    #[test]
    fn one_record_is_one_line_of_six_tsv_fields() {
        let line = format_line(
            &record("ads.example.com", Disposition::Blocked),
            &LocalZone::fixed_hours(8),
        );
        assert!(line.ends_with('\n'));
        let fields: Vec<&str> = line.trim_end().split('\t').collect();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], "2026-09-14 20:24:36");
        assert_eq!(fields[1], "127.0.0.1");
        assert_eq!(fields[2], "ads.example.com");
        assert_eq!(fields[4], "blocked");
        assert_eq!(
            fields[5], "-",
            "an empty column must be written as - so readers do not swallow it"
        );
    }

    #[test]
    fn every_event_kind_round_trips_and_has_a_plain_language_label() {
        // Symptom of omitting one: the weekly summary treats it as unknown and prints the
        // raw wire code, and "was there a window with no protection" undercounts it.
        for kind in ALL_EVENT_KINDS {
            assert_eq!(
                EventKind::from_wire(kind.as_str()),
                Some(kind),
                "{} does not round-trip",
                kind.as_str()
            );
            assert!(!kind.label().is_empty(), "{} has no label", kind.as_str());
            assert_ne!(
                kind.label(),
                kind.as_str(),
                "{} label is just the wire code, not something a person can read",
                kind.as_str()
            );
        }
        assert_eq!(EventKind::from_wire("no-such-event"), None);
    }

    /// Should change: after asking for a blocking flush, the record just queued is already
    /// in the file, without waiting for the batch interval.
    /// Should not change: returns `false` rather than hanging when the writer thread is gone.
    #[test]
    fn a_blocking_flush_returns_only_once_the_record_is_on_disk() {
        let dir = std::env::temp_dir().join(format!("phylode-flush-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::start(dir.clone(), 10, LocalZone::fixed_hours(8)).unwrap();
        journal.event(EventKind::Stopped, "received stop signal");

        assert!(journal.flush_blocking(Duration::from_secs(1)));
        let events: String = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("events-"))
            .map(|entry| std::fs::read_to_string(entry.path()).unwrap())
            .collect();
        assert!(
            events.contains("stopped\treceived stop signal"),
            "actual contents:\n{events}"
        );
        std::fs::remove_dir_all(&dir).unwrap();

        let (sender, receiver) = sync_channel(1);
        drop(receiver);
        let orphan = Journal {
            sender,
            dropped: Arc::new(AtomicU64::new(0)),
            queued: Arc::new(AtomicUsize::new(0)),
        };
        assert!(!orphan.flush_blocking(Duration::from_millis(100)));
    }

    #[test]
    fn the_event_kinds_that_mean_no_protection() {
        assert!(EventKind::BlocklistFailed.means_unprotected());
        assert!(EventKind::UpstreamsDown.means_unprotected());
        assert!(
            EventKind::Unresponsive.means_unprotected(),
            "not answering at all is worse than not filtering; it must be counted"
        );
        assert!(!EventKind::Started.means_unprotected());
        assert!(!EventKind::BlocklistLoaded.means_unprotected());
    }

    #[test]
    fn the_four_dispositions_are_written_distinctly() {
        let all = [
            Disposition::Blocked,
            Disposition::Allowed,
            Disposition::FailOpen,
            Disposition::Failed,
        ];
        let names: Vec<&str> = all.iter().map(|d| d.as_str()).collect();
        assert_eq!(names, ["blocked", "allowed", "fail-open", "failed"]);
    }

    #[test]
    fn a_domain_containing_newlines_or_tabs_cannot_forge_a_record() {
        let evil = "evil.example.com\n2026-01-01 00:00:00\t1.2.3.4\tapple.com\tA\tallowed\t";
        let line = format_line(
            &record(evil, Disposition::Blocked),
            &LocalZone::fixed_hours(8),
        );
        assert_eq!(
            line.matches('\n').count(),
            1,
            "only the trailing newline is allowed"
        );
        assert_eq!(
            line.trim_end().split('\t').count(),
            6,
            "input must not be able to add columns"
        );
    }

    #[test]
    fn a_full_channel_drops_and_counts_rather_than_blocking() {
        let (sender, receiver) = sync_channel(1);
        let journal = Journal {
            sender,
            dropped: Arc::new(AtomicU64::new(0)),
            queued: Arc::new(AtomicUsize::new(0)),
        };
        journal.record(record("a.example.com", Disposition::Allowed));
        journal.record(record("b.example.com", Disposition::Allowed));
        journal.record(record("c.example.com", Disposition::Allowed));
        assert_eq!(journal.dropped(), 2, "anything over capacity is counted");
        drop(receiver);
    }

    /// Should not change: query records the writer has taken stop counting against their
    /// share, or a long-running service would end up dropping every query.
    #[test]
    fn written_queries_give_their_place_back() {
        let dir = std::env::temp_dir().join(format!("phylode-queued-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::start(dir.clone(), 10, LocalZone::utc()).unwrap();
        for _ in 0..10 {
            journal.record(record("a.example.com", Disposition::Allowed));
        }
        assert!(journal.flush_blocking(Duration::from_secs(5)));
        assert_eq!(journal.queued.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: once query records have taken their share of the channel, further ones
    /// are dropped and counted while service events still get in.
    /// Should not change: queries below their share are queued as before.
    #[test]
    fn a_query_flood_leaves_room_for_service_events() {
        let (sender, receiver) = sync_channel(CHANNEL_CAPACITY);
        let journal = Journal {
            sender,
            dropped: Arc::new(AtomicU64::new(0)),
            queued: Arc::new(AtomicUsize::new(0)),
        };
        for _ in 0..CHANNEL_CAPACITY {
            journal.record(record("a.example.com", Disposition::Allowed));
        }
        assert_eq!(journal.dropped(), EVENT_RESERVE as u64);
        journal.event(EventKind::Unresponsive, "no response");
        assert_eq!(
            journal.dropped(),
            EVENT_RESERVE as u64,
            "the event was not dropped"
        );

        let entries: Vec<Entry> = receiver.try_iter().collect();
        assert_eq!(entries.len(), CHANNEL_CAPACITY - EVENT_RESERVE + 1);
        assert!(matches!(entries.last(), Some(Entry::Event(_))));
    }
}
