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
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};

use thiserror::Error;

use super::{Civil, Entry, LocalZone, format_event, format_line};

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

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("could not create journal directory {path}: {source}")]
    CreateDir {
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
pub fn spawn(
    receiver: Receiver<Entry>,
    directory: PathBuf,
    retention_days: u32,
    zone: LocalZone,
) -> Result<(), WriterError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&directory)
        .map_err(|source| WriterError::CreateDir {
            path: directory.clone(),
            source,
        })?;

    std::thread::Builder::new()
        .name("phylode-journal".to_string())
        .spawn(move || run(receiver, directory, retention_days, zone))
        .map(|_| ())
        .map_err(|source| WriterError::SpawnThread { source })
}

fn run(receiver: Receiver<Entry>, directory: PathBuf, retention_days: u32, zone: LocalZone) {
    let mut state = State::new(directory, zone.clone());
    let mut last_cleanup_check = SystemTime::now();
    let mut cleaner = Cleaner::new(retention_days, zone);

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

        let now = SystemTime::now();
        if now
            .duration_since(last_cleanup_check)
            .is_ok_and(|elapsed| elapsed >= CLEANUP_CHECK_INTERVAL)
        {
            last_cleanup_check = now;
            cleaner.maybe_clean(&state.directory, now);
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
}

/// A writer that rolls over to a new file each day.
struct DayFile {
    prefix: &'static str,
    open_date: Option<String>,
    writer: Option<BufWriter<File>>,
}

impl DayFile {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            open_date: None,
            writer: None,
        }
    }

    fn write(&mut self, directory: &Path, date: &str, line: &str) -> bool {
        if self.open_date.as_deref() != Some(date) {
            self.flush();
            self.writer = open_day_file(directory, self.prefix, date);
            self.open_date = Some(date.to_string());
        }
        let Some(writer) = self.writer.as_mut() else {
            return false;
        };
        // Give up on a record that fails to write. Being unable to journal must not stop the
        // service.
        writer.write_all(line.as_bytes()).is_ok()
    }

    fn flush(&mut self) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = writer.flush();
        }
    }
}

impl State {
    fn new(directory: PathBuf, zone: LocalZone) -> Self {
        Self {
            directory,
            zone,
            queries: DayFile::new(""),
            events: DayFile::new("events-"),
            pending: 0,
            last_flush: Instant::now(),
        }
    }

    fn push(&mut self, entry: &Entry) {
        let (at, line, is_event) = match entry {
            Entry::Query(record) => (record.at, format_line(record, &self.zone), false),
            Entry::Event(event) => (event.at, format_event(event, &self.zone), true),
            // The main loop intercepts this first, so it never reaches here; if it did, it
            // would simply write no line.
            Entry::Flush(_) => return,
        };
        let unix = at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let date = Civil::from_unix(unix, &self.zone).date_string();

        let written = if is_event {
            self.events.write(&self.directory, &date, &line)
        } else {
            self.queries.write(&self.directory, &date, &line)
        };
        if written {
            self.pending += 1;
        }
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
        self.queries.flush();
        self.events.flush();
        self.pending = 0;
        self.last_flush = Instant::now();
    }
}

fn open_day_file(directory: &Path, prefix: &str, date: &str) -> Option<BufWriter<File>> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(FILE_MODE)
        .open(directory.join(format!("{prefix}{date}.tsv")))
        .ok()
        .map(BufWriter::new)
}

/// Deletes expired journal files. Scheduled for the middle of the night, because it is heavy
/// and nobody is using the network then.
///
/// The minute is a fixed random jitter.
struct Cleaner {
    retention_days: u32,
    zone: LocalZone,
    minute: u32,
    last_cleaned_date: Option<String>,
}

impl Cleaner {
    /// The hour cleanup runs. With the `minute` jitter this lands between 03:10 and 03:50.
    const HOUR: u32 = 3;

    fn new(retention_days: u32, zone: LocalZone) -> Self {
        Self {
            retention_days,
            zone,
            minute: 10 + pseudo_random_minute() % 40,
            last_cleaned_date: None,
        }
    }

    fn maybe_clean(&mut self, directory: &Path, now: SystemTime) {
        let unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let civil = Civil::from_unix(unix, &self.zone);
        let today = civil.date_string();

        if civil.hour != Self::HOUR || civil.minute < self.minute {
            return;
        }
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
        let date = stem.strip_prefix("events-").unwrap_or(stem);
        if date < cutoff {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Minute jitter for the cleanup window. This does not need cryptographic randomness; it only
/// keeps every machine from acting in the same second.
fn pseudo_random_minute() -> u32 {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos % 40
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
        )
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
    fn the_cleanup_window_always_lands_between_0310_and_0350() {
        for _ in 0..50 {
            let cleaner = Cleaner::new(10, LocalZone::fixed_hours(8));
            assert!(
                (10..50).contains(&cleaner.minute),
                "the jitter must land in minutes 10-49; got {}",
                cleaner.minute
            );
        }
    }

    #[test]
    fn only_files_before_the_cutoff_are_deleted_and_nothing_else_is_touched() {
        let dir = std::env::temp_dir().join(format!(
            "phylode-journal-test-{}-{}",
            std::process::id(),
            pseudo_random_minute()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        for date in ["2026-09-01", "2026-09-04", "2026-09-05", "2026-09-14"] {
            std::fs::write(dir.join(format!("{date}.tsv")), "x").unwrap();
        }
        std::fs::write(dir.join("not-a-journal.txt"), "x").unwrap();

        remove_files_before(&dir, "2026-09-04");

        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
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
