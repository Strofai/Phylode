//! Weekly archive: stores the summary of the last complete week (Monday to Sunday) as a
//! file, kept for 12 weeks.
//!
//! Weekly summaries are promised to survive 12 weeks — you can skip a fortnight and still
//! find them — while the detailed journal is kept
//! for only 10 days. Without archiving while the journal still exists, that promise fails.
//! What gets archived is [`Summary::render_archive`], which excludes ordinarily allowed
//! domains.
//!
//! What breaks if you change it: archives live in `weekly/` under the journal directory,
//! and journal expiry only matches `.tsv`, so it leaves them alone. Before changing the
//! file name or extension, check that the expiry pass
//! (`journal::writer::remove_files_before`) will not start deleting them as journal files.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::Summary;
use crate::journal::{self, DIR_MODE, FILE_MODE, LocalZone};

/// Name of the subdirectory under the journal directory that holds weekly archives.
pub const ARCHIVE_DIR: &str = "weekly";

/// How long archives are kept: 12 weeks.
const KEEP_DAYS: i64 = 12 * 7;

/// The seven dates of the last complete week (Monday to Sunday), oldest first.
pub fn last_full_week(now_unix: i64, zone: &LocalZone) -> Vec<String> {
    let since_monday = zone.date_of(now_unix).weekday().to_monday_zero_offset();
    let back_to_last_monday = i64::from(since_monday) + 7;
    (0..7)
        .map(|day| {
            zone.days_before(now_unix, back_to_last_monday - day)
                .to_string()
        })
        .collect()
}

/// Writes an archive if last week has not been archived yet and has any journal entries;
/// also deletes archives older than 12 weeks.
/// Returns the file just written, or `None` when there was nothing to write.
pub fn archive_due(
    journal_dir: &Path,
    now_unix: i64,
    zone: &LocalZone,
) -> std::io::Result<Option<PathBuf>> {
    let dir = journal_dir.join(ARCHIVE_DIR);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&dir)?;

    let cutoff = zone.days_before(now_unix, KEEP_DAYS).to_string();
    remove_before(&dir, &cutoff);

    let week = last_full_week(now_unix, zone);
    let (Some(first), Some(last)) = (week.first(), week.last()) else {
        return Ok(None);
    };
    let path = dir.join(format!("{first}_{last}.txt"));
    if path.exists() || !has_any_journal(journal_dir, &week) {
        return Ok(None);
    }

    let text = Summary::gather(journal_dir, &week).render_archive();
    // Write to a staging file and rename: a crash mid-write leaves no half-written
    // archive, so "the file exists" means "this week was archived successfully".
    let staged = dir.join(format!(".{first}_{last}.tmp"));
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&staged)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&staged, &path)?;
    Ok(Some(path))
}

fn has_any_journal(journal_dir: &Path, days: &[String]) -> bool {
    days.iter().any(|day| {
        journal::queries_file(journal_dir, day).exists()
            || journal::events_file(journal_dir, day).exists()
    })
}

/// Deletes archives whose Sunday is earlier than `cutoff`. File names are
/// `monday_sunday.txt`; nothing else is touched.
fn remove_before(dir: &Path, cutoff: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(sunday) = name
            .strip_suffix(".txt")
            .and_then(|stem| stem.split_once('_'))
            .map(|(_, sunday)| sunday)
        else {
            continue;
        };
        if sunday < cutoff {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `2026-09-28 12:00` UTC+8 (a Monday), the literal value produced by `date -j`.
    const MONDAY_NOON: i64 = 1_790_568_000;
    /// `2026-09-27 23:59` UTC+8 (a Sunday).
    const SUNDAY_NIGHT: i64 = 1_790_524_740;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("phylode-archive-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_last_full_week_runs_monday_to_sunday() {
        let week = last_full_week(MONDAY_NOON, &LocalZone::fixed_hours(8));
        assert_eq!(week.first().unwrap(), "2026-09-21");
        assert_eq!(week.last().unwrap(), "2026-09-27");
        assert_eq!(week.len(), 7);

        // On Sunday night that week is not over yet, so the last full week is the one
        // before it.
        let week = last_full_week(SUNDAY_NIGHT, &LocalZone::fixed_hours(8));
        assert_eq!(week.first().unwrap(), "2026-09-14");
        assert_eq!(week.last().unwrap(), "2026-09-20");
    }

    /// Should change: a week with journal entries is archived once, without the allowed
    /// domain that was being asked for repeatedly.
    /// Should not change: the on-demand summary still lists that domain (the control).
    #[test]
    fn the_archive_is_written_once_and_omits_allowed_domains() {
        let dir = temp_dir("once");
        let line = "2026-09-22 10:00:00\t192.168.0.20\tsecret-allowed.example.com\tA\tallowed\t-\n";
        std::fs::write(dir.join("2026-09-22.tsv"), line.repeat(600)).unwrap();

        let written = archive_due(&dir, MONDAY_NOON, &LocalZone::fixed_hours(8))
            .unwrap()
            .expect("the first call must write");
        assert_eq!(
            written.file_name().unwrap().to_str().unwrap(),
            "2026-09-21_2026-09-27.txt"
        );
        let text = std::fs::read_to_string(&written).unwrap();
        assert!(text.contains("keeps asking for one domain (600 times"));
        assert!(!text.contains("secret-allowed.example.com"));

        let full = Summary::gather(
            &dir,
            &last_full_week(MONDAY_NOON, &LocalZone::fixed_hours(8)),
        )
        .render();
        assert!(
            full.contains("secret-allowed.example.com"),
            "control: the on-demand summary must show the domain"
        );

        assert!(
            archive_due(&dir, MONDAY_NOON, &LocalZone::fixed_hours(8))
                .unwrap()
                .is_none(),
            "once archived, it is not written again"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_week_with_no_journal_is_not_archived() {
        let dir = temp_dir("empty");
        assert!(
            archive_due(&dir, MONDAY_NOON, &LocalZone::fixed_hours(8))
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Should change: archives whose Sunday is more than 12 weeks old are deleted.
    /// Should not change: those within 12 weeks stay, and files that do not look like
    /// archives are left alone.
    #[test]
    fn archives_older_than_twelve_weeks_are_deleted() {
        let dir = temp_dir("expire");
        let weekly = dir.join(ARCHIVE_DIR);
        std::fs::create_dir_all(&weekly).unwrap();
        // 84 days before `2026-09-28` is `2026-07-06`.
        for name in [
            "2026-06-29_2026-07-05.txt",
            "2026-07-06_2026-07-12.txt",
            "notes.md",
        ] {
            std::fs::write(weekly.join(name), "x").unwrap();
        }

        archive_due(&dir, MONDAY_NOON, &LocalZone::fixed_hours(8)).unwrap();

        assert!(!weekly.join("2026-06-29_2026-07-05.txt").exists());
        assert!(weekly.join("2026-07-06_2026-07-12.txt").exists());
        assert!(weekly.join("notes.md").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
