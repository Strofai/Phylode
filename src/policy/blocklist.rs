//! Blocklist: loads a set of domains from files for queries to match against.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BlocklistError {
    #[error("could not read blocklist {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The required lists were readable but produced no domains at all (or the
    /// configuration lists no files). Treated as a load failure: counting 0 entries as
    /// success would make the weekly summary claim "protection was continuous" while
    /// nothing was being blocked.
    #[error(
        "the blocklist is empty ({0} files, 0 domains in total), which is the same as no protection"
    )]
    Empty(usize),
    #[error(
        "blocklist {path} is larger than {} MB, which no real list comes close to; it was not \
         loaded and the previous list stays in place",
        MAX_LIST_BYTES / (1024 * 1024)
    )]
    TooLarge { path: std::path::PathBuf },
}

/// The most one list file may hold. The lists in use are under 20 MB each; this keeps
/// a damaged or hostile download from exhausting memory.
/// What breaks if you change it: it must equal `MAX_BYTES` in `deploy/update-blocklists.sh`
/// (a test compares them), or the updater accepts a file the service then refuses.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

/// Reads one list file, refusing anything over [`MAX_LIST_BYTES`] without reading the rest.
fn read_list(path: &Path) -> Result<String, BlocklistError> {
    let read_error = |source| BlocklistError::Read {
        path: path.to_path_buf(),
        source,
    };
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(read_error)?
        .take(MAX_LIST_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(read_error)?;
    if text.len() as u64 > MAX_LIST_BYTES {
        return Err(BlocklistError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    Ok(text)
}

/// The result of a list lookup.
///
/// `Unavailable` is not an error; it means "the list has not loaded yet or failed to load",
/// and the caller must allow the query on that basis.
/// What breaks if you change it: folding `Unavailable` into `Allowed` leaves the caller
/// unable to distinguish "checked, should not be blocked" from "never actually checked" —
/// and the allow in the second case must not be cached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Blocked,
    Allowed,
    Unavailable,
}

/// The loaded set of domains. Names are always lowercase with no trailing dot.
#[derive(Debug, Default)]
struct DomainSet {
    domains: HashSet<String>,
}

impl DomainSet {
    /// Whether the domain itself or any of its parents is on the list
    /// (`ads.example.com` matches `example.com`).
    fn contains(&self, name: &str) -> bool {
        super::any_suffix(name, |rest| self.domains.contains(rest))
    }

    fn len(&self) -> usize {
        self.domains.len()
    }
}

/// The shared holder of the list. `None` means nothing has loaded successfully yet, and
/// every lookup returns `Unavailable`.
///
/// What breaks if you change it: on the hot path, take the read lock, clone the `Arc` and
/// release immediately — never await while holding the lock.
#[derive(Clone, Debug, Default)]
pub struct Blocklist {
    inner: Arc<RwLock<Option<Arc<DomainSet>>>>,
}

impl Blocklist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, name: &str) -> Verdict {
        let Some(set) = self.snapshot() else {
            return Verdict::Unavailable;
        };
        if set.contains(name) {
            Verdict::Blocked
        } else {
            Verdict::Allowed
        }
    }

    /// How many domains are currently loaded; `None` before anything has loaded.
    pub fn loaded_len(&self) -> Option<usize> {
        self.snapshot().map(|set| set.len())
    }

    fn snapshot(&self) -> Option<Arc<DomainSet>> {
        match self.inner.read() {
            Ok(guard) => guard.clone(),
            // A poisoned lock means a writer panicked. Treat it as having no list and allow
            // the query rather than failing it too.
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Reads every source file and swaps the whole set in at once.
    ///
    /// If any file in `required` cannot be read, or they yield 0 domains between them, the
    /// entire batch is abandoned and the existing list stays in place. `optional` holds
    /// files whose absence is normal — for instance the one that only exists once
    /// `phylode block` has been used.
    ///
    /// What breaks if you change it: a failure must never clear the existing list — that
    /// would escalate "the update failed" into "nothing is blocked".
    pub fn load_all(
        &self,
        required: &[impl AsRef<Path>],
        optional: &[impl AsRef<Path>],
    ) -> Result<usize, BlocklistError> {
        let mut domains = HashSet::new();

        for path in required {
            parse_into(&read_list(path.as_ref())?, &mut domains);
        }
        if domains.is_empty() {
            return Err(BlocklistError::Empty(required.len()));
        }

        for path in optional {
            match read_list(path.as_ref()) {
                Ok(text) => parse_into(&text, &mut domains),
                // Not created yet simply means nothing has been blocked by hand; not an error.
                Err(BlocklistError::Read { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }

        Ok(self.install(domains))
    }

    /// Swaps in a list from contents already in hand. Used by the tests and the blocklist
    /// fuzz target; the service itself loads files through [`Blocklist::load_all`].
    pub fn load_from_str(&self, text: &str) -> usize {
        let mut domains = HashSet::new();
        parse_into(text, &mut domains);
        self.install(domains)
    }

    fn install(&self, domains: HashSet<String>) -> usize {
        let len = domains.len();
        let set = Arc::new(DomainSet { domains });
        match self.inner.write() {
            Ok(mut guard) => *guard = Some(set),
            Err(poisoned) => *poisoned.into_inner() = Some(set),
        }
        len
    }
}

/// Parses both the hosts format (`0.0.0.0 ads.example.com`) and plain domain lists,
/// skipping comments and blank lines.
fn parse_into(text: &str, out: &mut HashSet<String>) {
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut fields = line.split_whitespace();
        let first = fields.next().unwrap_or_default();
        // In the hosts format the first field is an address and the domains follow; in a
        // plain list the first field is already the domain.
        let candidates: Vec<&str> = if is_ip_literal(first) {
            fields.collect()
        } else {
            vec![first]
        };

        for candidate in candidates {
            let domain = candidate.trim_end_matches('.').to_ascii_lowercase();
            if is_plausible_domain(&domain) {
                out.insert(domain);
            }
        }
    }
}

fn is_ip_literal(field: &str) -> bool {
    field.parse::<std::net::IpAddr>().is_ok()
}

/// Rejects local entries common in hosts files, such as `localhost`, along with anything
/// that does not look like a domain.
fn is_plausible_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return false;
    }
    domain
        .split('.')
        .all(|label| !label.is_empty() && label.len() <= 63)
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(domains: &[&str]) -> DomainSet {
        DomainSet {
            domains: domains.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn matches_the_domain_itself_and_its_subdomains() {
        let s = set(&["example.com"]);
        assert!(s.contains("example.com"));
        assert!(s.contains("ads.example.com"));
        assert!(s.contains("a.b.example.com"));
        assert!(s.contains("EXAMPLE.COM."));
    }

    #[test]
    fn does_not_match_other_domains_sharing_a_suffix() {
        let s = set(&["example.com"]);
        assert!(!s.contains("notexample.com"));
        assert!(!s.contains("example.com.tw"));
        assert!(!s.contains("com"));
    }

    #[test]
    fn an_unloaded_list_returns_unavailable_not_allowed() {
        let list = Blocklist::new();
        assert_eq!(list.lookup("example.com"), Verdict::Unavailable);
        assert_eq!(list.loaded_len(), None);
    }

    #[test]
    fn parses_hosts_format_and_plain_lists_and_skips_comments() {
        let mut out = HashSet::new();
        parse_into(
            "# comment\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\ntracker.example.net\n\n:: bad\n",
            &mut out,
        );
        assert!(out.contains("ads.example.com"));
        assert!(out.contains("tracker.example.net"));
        assert!(
            !out.contains("localhost"),
            "localhost has no dot, so it is not a domain"
        );
        assert_eq!(out.len(), 2);
    }

    /// Should change: an empty required list counts as a load failure.
    /// Should not change: on failure the existing list keeps blocking.
    #[test]
    fn an_empty_list_fails_without_replacing_the_existing_one() {
        let dir = std::env::temp_dir().join(format!("phylode-bl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let full = dir.join("full.txt");
        let empty = dir.join("empty.txt");
        std::fs::write(&full, "ads.example.com\n").unwrap();
        std::fs::write(&empty, "# comments only\n").unwrap();
        let none: &[&Path] = &[];

        let list = Blocklist::new();
        assert!(matches!(
            list.load_all(&[&empty], none),
            Err(BlocklistError::Empty(1))
        ));
        assert_eq!(list.lookup("ads.example.com"), Verdict::Unavailable);

        assert_eq!(list.load_all(&[&full], none).unwrap(), 1);
        assert!(list.load_all(&[&empty], none).is_err());
        assert_eq!(
            list.lookup("ads.example.com"),
            Verdict::Blocked,
            "an empty update must not replace the list that was already loaded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: a list file over the size limit is refused without being read whole.
    /// Should not change: the list already loaded keeps blocking, and a file at the limit
    /// is not refused for its size.
    #[test]
    fn an_oversized_list_is_refused_and_the_existing_one_stays() {
        let dir = std::env::temp_dir().join(format!("phylode-bl-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let full = dir.join("full.txt");
        let at_limit = dir.join("at-limit.txt");
        let oversized = dir.join("oversized.txt");
        std::fs::write(&full, "ads.example.com\n").unwrap();
        // Sparse files of zero bytes: no disk space used, and no domains in them.
        std::fs::File::create(&at_limit)
            .unwrap()
            .set_len(MAX_LIST_BYTES)
            .unwrap();
        std::fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_LIST_BYTES + 1)
            .unwrap();
        let none: &[&Path] = &[];

        let list = Blocklist::new();
        assert_eq!(list.load_all(&[&full], none).unwrap(), 1);
        assert!(matches!(
            list.load_all(&[&full], &[&oversized]),
            Err(BlocklistError::TooLarge { .. })
        ));
        assert!(matches!(
            list.load_all(&[&oversized], none),
            Err(BlocklistError::TooLarge { .. })
        ));
        assert_eq!(list.lookup("ads.example.com"), Verdict::Blocked);
        assert_eq!(list.load_all(&[&full], &[&at_limit]).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should not change: the updater and the service agree on the largest list file, or the
    /// updater installs files the service then refuses to load.
    #[test]
    fn the_updater_uses_the_same_size_limit() {
        let script = include_str!("../../deploy/update-blocklists.sh");
        let limit = script
            .lines()
            .find_map(|line| line.strip_prefix("MAX_BYTES="))
            .expect("the updater sets MAX_BYTES");
        assert_eq!(limit.parse::<u64>().unwrap(), MAX_LIST_BYTES);
    }

    #[test]
    fn several_domains_on_one_line_are_all_collected() {
        let mut out = HashSet::new();
        parse_into("0.0.0.0 a.example.com b.example.com\n", &mut out);
        assert_eq!(out.len(), 2);
    }
}
