//! Writer thread: receives records from the channel, batches them into one file per day, and
//! deletes expired files.
//!
//! One file per day (`YYYY-MM-DD.tsv`) turns retention into "delete files that are too old"
//! rather than deleting rows from a database. What breaks if you change it: with a single
//! large file, retention would mean rewriting the whole file, and that rewrite would block
//! writes while it ran.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};

use thiserror::Error;

use super::{
    Civil, EVENTS_PREFIX, Entry, Event, EventKind, LocalZone, events_file, format_event,
    format_line, queries_file, unix_seconds,
};

/// Directory permissions: the owner (the service account) reads and writes, the group reads,
/// nobody else gets in. The group is inherited from the parent directory (BSD semantics), and
/// the install script sets that parent to `admin` so reading the summary needs no sudo.
/// What breaks if you change it: the journal is a complete browsing history; widening this to
/// other users makes it readable by every account on the machine.
pub(crate) const DIR_MODE: u32 = 0o750;
/// File permissions: the owner reads and writes, the group reads.
pub(crate) const FILE_MODE: u32 = 0o640;

/// The longest the buffer is held before being written out, regardless of whether new records
/// arrive. What breaks if you change it: this is the bound on "how many seconds of journal a
/// crash can lose", and the time anyone must wait before exiting the process (see
/// [`super::Journal`]).
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(2);

/// How many records may accumulate before a write is forced, so the buffer cannot grow without
/// bound at peak.
const FLUSH_BATCH: usize = 256;

/// How often to check whether expired files need deleting.
const CLEANUP_CHECK_INTERVAL: Duration = Duration::from_secs(600);

/// The most one day's query journal may hold. Ours, with no industry source: a line is about
/// 100 bytes, so a home's day is a few MB and 200 MB leaves room for dozens of times that.
/// Past it the day's remaining queries are counted, not written; events are never capped.
///
/// What breaks if you change it: with no cap, a device sending from forged addresses can grow
/// the journal until the disk is full, and the Mac and the network's DNS fail with it. Set it
/// too low and a busy network loses detail on an ordinary day.
const MAX_QUERY_BYTES_PER_DAY: u64 = 200 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("could not create journal directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "journal directory {path} can be read by other accounts and could not be restricted: {source}"
    )]
    OpenDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not start the journal writer thread: {source}")]
    SpawnThread {
        #[source]
        source: std::io::Error,
    },
}

/// Starts the writer thread. Failing to create the directory is an error — it means the
/// permissions or the path are wrong, and that has to be visible at startup.
///
/// `dropped` is the count the answer path keeps of records it could not queue; the writer
/// turns any increase into a "records dropped" event.
pub fn spawn(
    receiver: Receiver<Entry>,
    directory: PathBuf,
    retention_days: u32,
    zone: LocalZone,
    dropped: Arc<AtomicU64>,
) -> Result<(), WriterError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&directory)
        .map_err(|source| WriterError::CreateDir {
            path: directory.clone(),
            source,
        })?;
    restrict(&directory).map_err(|source| WriterError::OpenDirectory {
        path: directory.clone(),
        source,
    })?;

    std::thread::Builder::new()
        .name("phylode-journal".to_string())
        .spawn(move || run(receiver, directory, retention_days, zone, dropped))
        .map(|_| ())
        .map_err(|source| WriterError::SpawnThread { source })
}

/// Takes away any permission beyond [`DIR_MODE`] from a directory that already existed:
/// creating applies the mode only to a new directory.
///
/// What breaks if you change it: a `journal_dir` pointing at an existing open folder would
/// show every account the journal's file names. When the service cannot tighten it (it does
/// not own the folder), it runs without a journal rather than writing into the open.
fn restrict(directory: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(directory)?.permissions().mode() & 0o7777;
    if mode & !DIR_MODE == 0 {
        return Ok(());
    }
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode & DIR_MODE))
}

fn run(
    receiver: Receiver<Entry>,
    directory: PathBuf,
    retention_days: u32,
    zone: LocalZone,
    dropped: Arc<AtomicU64>,
) {
    let mut state = State::new(directory, zone.clone(), dropped);
    let mut cleaner = Cleaner::new(retention_days, zone);
    cleaner.maybe_clean(&state.directory, SystemTime::now());
    let mut last_cleanup_check = Instant::now();

    loop {
        match receiver.recv_timeout(FLUSH_INTERVAL) {
            Ok(Entry::Flush(done)) => {
                state.flush();
                let _ = done.send(());
            }
            Ok(entry) => {
                state.push(&entry);
                if state.flush_due() {
                    state.flush();
                }
            }
            Err(RecvTimeoutError::Timeout) => state.flush(),
            // The other end of the channel is gone, so the service is shutting down. Write
            // out what we are holding before leaving.
            Err(RecvTimeoutError::Disconnected) => {
                state.flush();
                return;
            }
        }

        if last_cleanup_check.elapsed() >= CLEANUP_CHECK_INTERVAL {
            last_cleanup_check = Instant::now();
            cleaner.maybe_clean(&state.directory, SystemTime::now());
        }
    }
}

/// Query records and service events each get their own daily file.
///
/// They are separate because the field counts differ, and because reading events for the
/// weekly summary should not mean scanning the entire query journal.
struct State {
    directory: PathBuf,
    zone: LocalZone,
    queries: DayFile,
    events: DayFile,
    pending: usize,
    last_flush: Instant,
    /// Records the answer path could not queue, and how many of those already have an event.
    dropped: Arc<AtomicU64>,
    reported_dropped: u64,
    /// Records that reached this thread but could not be written, not yet in an event.
    unwritten: u64,
    /// Queries left out because the day's file was full, not yet in an event.
    over_limit: u64,
}

/// What became of one line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Written {
    Yes,
    /// The file could not be opened or written.
    Failed,
    /// The day's file has reached its size limit.
    OverLimit,
}

/// A writer that rolls over to a new file each day.
struct DayFile {
    path_for: fn(&Path, &str) -> PathBuf,
    open_date: Option<String>,
    writer: Option<BufWriter<File>>,
    /// When a failed open may be tried again.
    retry_at: Option<Instant>,
    /// The most the day's file may hold; `None` means no limit.
    max_bytes: Option<u64>,
    /// What the day's file holds, counting what it held before this process opened it.
    bytes: u64,
}

impl DayFile {
    fn new(path_for: fn(&Path, &str) -> PathBuf, max_bytes: Option<u64>) -> Self {
        Self {
            path_for,
            open_date: None,
            writer: None,
            retry_at: None,
            max_bytes,
            bytes: 0,
        }
    }

    /// Appends one line to the day's file. A file that would not open is tried again at most
    /// once per [`FLUSH_INTERVAL`]; a line that would take the file past `max_bytes` is not
    /// written.
    ///
    /// What breaks if you change it: without the retry, one failed open (a full disk for a
    /// moment) loses the rest of that day's records; retrying on every record instead costs a
    /// failing system call per query while the disk stays full. Starting `bytes` at zero
    /// instead of the file's size lets each restart write another full day's worth.
    fn write(&mut self, directory: &Path, date: &str, line: &str) -> Written {
        if self.open_date.as_deref() != Some(date) {
            self.flush();
            self.writer = None;
            self.retry_at = None;
            self.open_date = Some(date.to_string());
        }
        if self.writer.is_none() && self.retry_at.is_none_or(|at| Instant::now() >= at) {
            self.writer = open_day_file(&(self.path_for)(directory, date));
            self.retry_at = self
                .writer
                .is_none()
                .then(|| Instant::now() + FLUSH_INTERVAL);
            self.bytes = self
                .writer
                .as_ref()
                .and_then(|writer| writer.get_ref().metadata().ok())
                .map_or(0, |metadata| metadata.len());
        }
        let Some(writer) = self.writer.as_mut() else {
            return Written::Failed;
        };
        let len = line.len() as u64;
        if self.max_bytes.is_some_and(|max| self.bytes + len > max) {
            return Written::OverLimit;
        }
        // Give up on a record that fails to write. Being unable to journal must not stop the
        // service.
        if writer.write_all(line.as_bytes()).is_err() {
            return Written::Failed;
        }
        self.bytes += len;
        Written::Yes
    }

    fn flush(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = writer.flush();
        }
    }
}

impl State {
    fn new(directory: PathBuf, zone: LocalZone, dropped: Arc<AtomicU64>) -> Self {
        Self {
            directory,
            zone,
            queries: DayFile::new(queries_file, Some(MAX_QUERY_BYTES_PER_DAY)),
            events: DayFile::new(events_file, None),
            pending: 0,
            last_flush: Instant::now(),
            dropped,
            reported_dropped: 0,
            unwritten: 0,
            over_limit: 0,
        }
    }

    fn push(&mut self, entry: &Entry) {
        match self.write(entry) {
            Written::Yes => {}
            Written::Failed => self.unwritten += 1,
            Written::OverLimit => self.over_limit += 1,
        }
    }

    /// Writes one entry and says what became of it.
    fn write(&mut self, entry: &Entry) -> Written {
        let (at, line, is_event) = match entry {
            Entry::Query(record) => (record.at, format_line(record, &self.zone), false),
            Entry::Event(event) => (event.at, format_event(event, &self.zone), true),
            // The main loop intercepts this first, so it never reaches here; if it did, it
            // would simply write no line.
            Entry::Flush(_) => return Written::Yes,
        };
        let date = Civil::from_unix(unix_seconds(at), &self.zone).date_string();

        let written = if is_event {
            self.events.write(&self.directory, &date, &line)
        } else {
            self.queries.write(&self.directory, &date, &line)
        };
        if written == Written::Yes {
            self.pending += 1;
        }
        written
    }

    /// Whether the records in hand should be written to disk now.
    ///
    /// What breaks if you change it: the time half cannot be removed. With only the batch
    /// count, a steady stream of queries means the channel receive never times out, so
    /// records sit in the buffer waiting to reach `FLUSH_BATCH` — a restart before that loses
    /// all of them, and `FLUSH_INTERVAL`'s "at most a few seconds" promise fails at the same
    /// time.
    fn flush_due(&self) -> bool {
        if self.pending == 0 {
            return false;
        }
        self.pending >= FLUSH_BATCH || self.last_flush.elapsed() >= FLUSH_INTERVAL
    }

    fn flush(&mut self) {
        self.note_dropped();
        self.queries.flush();
        self.events.flush();
        self.pending = 0;
        self.last_flush = Instant::now();
    }

    /// Writes a "records dropped" event for records lost since the last one: those the answer
    /// path could not queue, those that could not be written, and queries past the day's size
    /// limit. Written here rather than sent through the channel, because a full channel is one
    /// reason they were lost. A count is cleared only once its event is written, so a journal
    /// that cannot be written reports the loss when it can. At most one event per reason per
    /// flush, so a flood adds a few lines a minute, not one per query.
    ///
    /// What breaks if you change it: item 7 of the weekly summary reads only these events; the
    /// counters on their own are never seen by anyone.
    fn note_dropped(&mut self) {
        let total = self.dropped.load(Ordering::Relaxed);
        let lost = total.saturating_sub(self.reported_dropped);
        if lost > 0 && self.write_dropped(lost, "the journal could not keep up") {
            self.reported_dropped = total;
        }
        if self.unwritten > 0
            && self.write_dropped(self.unwritten, "the journal file could not be written")
        {
            self.unwritten = 0;
        }
        if self.over_limit > 0
            && self.write_dropped(self.over_limit, "the day's journal reached its size limit")
        {
            self.over_limit = 0;
        }
    }

    fn write_dropped(&mut self, count: u64, reason: &str) -> bool {
        self.write(&Entry::Event(Event {
            at: SystemTime::now(),
            kind: EventKind::RecordsDropped,
            detail: format!("{count} not written; {reason}"),
        })) == Written::Yes
    }
}

fn open_day_file(path: &Path) -> Option<BufWriter<File>> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(FILE_MODE)
        .open(path)
        .ok()
        .map(BufWriter::new)
}

/// Deletes expired journal files once per local day: at startup, then at the first check
/// after each midnight. Deleting a day's file is one directory listing and one unlink.
///
/// What breaks if you change it: tying this to a fixed hour means a Mac that is asleep at
/// that hour never deletes anything, and the journal outlives the retention it promises.
struct Cleaner {
    retention_days: u32,
    zone: LocalZone,
    last_cleaned_date: Option<String>,
}

impl Cleaner {
    fn new(retention_days: u32, zone: LocalZone) -> Self {
        Self {
            retention_days,
            zone,
            last_cleaned_date: None,
        }
    }

    fn maybe_clean(&mut self, directory: &Path, now: SystemTime) {
        let unix = unix_seconds(now);
        let today = Civil::from_unix(unix, &self.zone).date_string();
        if self.last_cleaned_date.as_deref() == Some(today.as_str()) {
            return;
        }
        self.last_cleaned_date = Some(today);

        let cutoff = cutoff_date(unix, self.retention_days, &self.zone);
        remove_files_before(directory, &cutoff);
    }
}

/// Journal files earlier than this date are deleted. The cutoff day itself is kept.
fn cutoff_date(now_unix: i64, retention_days: u32, zone: &LocalZone) -> String {
    zone.days_before(now_unix, i64::from(retention_days))
        .to_string()
}

/// File names are dates, so comparing strings compares dates without parsing them again.
///
/// What breaks if you change it: only files ending in `.tsv` are touched; anything else in the
/// directory is left alone.
fn remove_files_before(directory: &Path, cutoff: &str) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".tsv") else {
            continue;
        };
        // Event files carry an extra prefix, which has to come off before comparing dates.
        let date = stem.strip_prefix(EVENTS_PREFIX).unwrap_or(stem);
        if date < cutoff {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed test instant: `2026-09-14 20:24:36` at UTC+8.
    const FIXED_UNIX: i64 = 1_789_388_676;

    fn empty_writer_state() -> State {
        // Only the flush decision is tested here and the disk is never touched, so the path
        // does not need to exist.
        State::new(
            PathBuf::from("/phylode-nonexistent-test-path"),
            LocalZone::fixed_hours(8),
            Arc::new(AtomicU64::new(0)),
        )
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("phylode-journal-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Should change: records dropped on the answer path become one event with the count,
    /// and a later flush reports only the new ones.
    /// Should not change: a flush with nothing dropped writes no event.
    #[test]
    fn dropped_records_are_written_as_an_event_with_the_count() {
        let dir = scratch_dir("dropped");
        let dropped = Arc::new(AtomicU64::new(0));
        let mut state = State::new(dir.clone(), LocalZone::fixed_hours(8), Arc::clone(&dropped));

        state.flush();
        assert!(
            file_names(&dir).is_empty(),
            "nothing dropped, nothing written"
        );

        dropped.store(3, Ordering::Relaxed);
        state.flush();
        dropped.store(5, Ordering::Relaxed);
        state.flush();
        state.flush();

        let [events] = file_names(&dir).try_into().unwrap();
        let text = std::fs::read_to_string(dir.join(events)).unwrap();
        let details: Vec<&str> = text
            .lines()
            .map(|line| line.split('\t').nth(2).unwrap())
            .collect();
        assert_eq!(
            details,
            [
                "3 not written; the journal could not keep up",
                "2 not written; the journal could not keep up"
            ]
        );
        assert!(
            text.lines()
                .all(|line| line.contains("\trecords-dropped\t"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: an existing folder open to other accounts loses those permissions.
    /// Should not change: a folder already tighter than 750 is left as it is.
    #[test]
    fn an_existing_open_journal_folder_is_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("phylode-restrict-{}", std::process::id()));
        for (before, after) in [(0o777, 0o750), (0o755, 0o750), (0o700, 0o700)] {
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(before)).unwrap();
            restrict(&dir).unwrap();
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, after, "{before:o} became {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: when the day's file cannot be opened (a full disk, a folder that cannot
    /// be written), the records are counted, opening is tried again, and once it works an
    /// event says how many were lost — so the weekly summary does not call the day complete.
    /// Should not change: records arriving after the file opens are written as usual.
    #[test]
    fn records_that_could_not_be_written_are_reported_once_writing_works_again() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("unwritable");
        let mut state = State::new(
            dir.clone(),
            LocalZone::fixed_hours(8),
            Arc::new(AtomicU64::new(0)),
        );
        let query = |name: &str| {
            Entry::Query(super::super::Record {
                at: SystemTime::now(),
                client: "192.168.1.20".parse().unwrap(),
                name: name.to_string(),
                record_type: "A".into(),
                disposition: super::super::Disposition::Allowed,
                reason: "".into(),
            })
        };

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        state.push(&query("lost.example.com"));
        state.flush();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(file_names(&dir).is_empty(), "nothing could be written");

        std::thread::sleep(FLUSH_INTERVAL);
        state.push(&query("kept.example.com"));
        state.flush();

        let mut text = String::new();
        for name in file_names(&dir) {
            text += &std::fs::read_to_string(dir.join(name)).unwrap();
        }
        assert!(text.contains("kept.example.com"), "{text}");
        assert!(!text.contains("lost.example.com"), "{text}");
        assert!(
            text.contains(
                "\trecords-dropped\t1 not written; the journal file could not be written"
            ),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: once a day's query journal reaches its size limit, further queries that
    /// day are counted rather than written, and an event says how many — so a flood cannot
    /// fill the disk, and the weekly summary does not call the day complete.
    /// Should not change: events are still written past the limit.
    #[test]
    fn a_full_day_of_queries_stops_growing_and_says_how_many_it_left_out() {
        let dir = scratch_dir("day-limit");
        let mut state = State::new(
            dir.clone(),
            LocalZone::fixed_hours(8),
            Arc::new(AtomicU64::new(0)),
        );
        state.queries.max_bytes = Some(300);
        for n in 0..20 {
            state.push(&Entry::Query(super::super::Record {
                at: SystemTime::now(),
                client: "192.168.1.20".parse().unwrap(),
                name: format!("q{n}.example.com"),
                record_type: "A".into(),
                disposition: super::super::Disposition::Allowed,
                reason: "".into(),
            }));
        }
        state.flush();

        let mut queries = 0;
        let mut events = String::new();
        for name in file_names(&dir) {
            let text = std::fs::read_to_string(dir.join(&name)).unwrap();
            if name.starts_with(EVENTS_PREFIX) {
                events += &text;
            } else {
                assert!(text.len() <= 300, "{} bytes", text.len());
                queries = text.lines().count();
            }
        }
        assert!(queries > 0 && queries < 20, "{queries} written");
        assert!(
            events.contains(&format!(
                "\trecords-dropped\t{} not written; the day's journal reached its size limit",
                20 - queries
            )),
            "{events}"
        );

        // A restart picks up the day's file at the size it already has.
        let mut restarted = State::new(
            dir.clone(),
            LocalZone::fixed_hours(8),
            Arc::new(AtomicU64::new(0)),
        );
        restarted.queries.max_bytes = Some(300);
        restarted.push(&Entry::Query(super::super::Record {
            at: SystemTime::now(),
            client: "192.168.1.20".parse().unwrap(),
            name: "after-restart.example.com".to_string(),
            record_type: "A".into(),
            disposition: super::super::Disposition::Allowed,
            reason: "".into(),
        }));
        assert_eq!(restarted.over_limit, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: expired files are deleted at an ordinary hour (20:24 local), not only in
    /// a night window a sleeping Mac would miss.
    /// Should not change: within the same day it runs once; the next day it runs again.
    #[test]
    fn expired_files_are_deleted_once_a_day_at_any_hour() {
        let dir = scratch_dir("cleaner");
        let zone = LocalZone::fixed_hours(8);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(FIXED_UNIX as u64);
        let mut cleaner = Cleaner::new(10, zone);

        std::fs::write(dir.join("2026-09-01.tsv"), "x").unwrap();
        std::fs::write(dir.join("2026-09-14.tsv"), "x").unwrap();
        cleaner.maybe_clean(&dir, now);
        assert_eq!(file_names(&dir), ["2026-09-14.tsv"]);

        std::fs::write(dir.join("2026-09-02.tsv"), "x").unwrap();
        cleaner.maybe_clean(&dir, now + Duration::from_secs(60 * 60));
        assert_eq!(
            file_names(&dir),
            ["2026-09-02.tsv", "2026-09-14.tsv"],
            "the same day does not clean twice"
        );

        cleaner.maybe_clean(&dir, now + Duration::from_secs(24 * 60 * 60));
        assert_eq!(file_names(&dir), ["2026-09-14.tsv"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_steady_stream_still_flushes_on_time_rather_than_waiting_for_a_full_batch() {
        let mut state = empty_writer_state();
        state.pending = 1;
        state.last_flush = Instant::now().checked_sub(FLUSH_INTERVAL * 2).unwrap();
        assert!(
            state.flush_due(),
            "past the interval it must flush; with only the batch count, a steady stream of \
             queries would keep these records in memory and a restart would lose all of them"
        );
    }

    #[test]
    fn a_recent_flush_with_a_partial_batch_does_not_flush_again() {
        let mut state = empty_writer_state();
        state.pending = 1;
        state.last_flush = Instant::now();
        assert!(!state.flush_due());

        state.pending = FLUSH_BATCH;
        assert!(
            state.flush_due(),
            "a full batch flushes immediately rather than waiting out the interval"
        );
    }

    #[test]
    fn nothing_pending_means_no_pointless_flush() {
        let mut state = empty_writer_state();
        state.pending = 0;
        state.last_flush = Instant::now().checked_sub(FLUSH_INTERVAL * 10).unwrap();
        assert!(!state.flush_due());
    }

    #[test]
    fn a_ten_day_retention_puts_the_cutoff_ten_days_back() {
        assert_eq!(
            cutoff_date(FIXED_UNIX, 10, &LocalZone::fixed_hours(8)),
            "2026-09-04"
        );
        assert_eq!(
            cutoff_date(FIXED_UNIX, 0, &LocalZone::fixed_hours(8)),
            "2026-09-14"
        );
    }

    #[test]
    fn only_files_before_the_cutoff_are_deleted_and_nothing_else_is_touched() {
        let dir = scratch_dir("cutoff");

        for date in ["2026-09-01", "2026-09-04", "2026-09-05", "2026-09-14"] {
            std::fs::write(dir.join(format!("{date}.tsv")), "x").unwrap();
        }
        std::fs::write(dir.join("not-a-journal.txt"), "x").unwrap();

        remove_files_before(&dir, "2026-09-04");

        assert_eq!(
            file_names(&dir),
            [
                "2026-09-04.tsv",
                "2026-09-05.tsv",
                "2026-09-14.tsv",
                "not-a-journal.txt"
            ],
            "the cutoff day itself stays, and non-journal files must not be touched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
