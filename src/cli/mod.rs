//! Commands: `phylode allow <domain>`, `phylode block <domain>`, `phylode status`.
//!
//! Allowing and blocking only edit two plain text files; the service notices and reloads by
//! itself.
//! What breaks if you change it: **there is deliberately no control channel** — no network
//! port, no unix socket. Without a channel there is no attack surface there, and file
//! permissions are the operating system's job. The cost is a few seconds of latency, well
//! inside the 10 seconds an allow or block is promised to take.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::dns::Name;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(
        "`{value}` does not look like a domain; write it like example.com, which also covers \
         everything under it"
    )]
    NotADomain { value: String },
    #[error("the configuration does not set {key}, so there is nowhere to write")]
    MissingPath { key: &'static str },
    #[error(
        "this account may not change {}; the lists belong to administrators, so run it from an \
         administrator account",
        path.display()
    )]
    NotPermitted { path: PathBuf },
    #[error("could not read or write {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A file error, told apart by whether it is a permissions problem the user can act on.
fn io_error(path: &Path, source: std::io::Error) -> CliError {
    let path = path.to_path_buf();
    if source.kind() == std::io::ErrorKind::PermissionDenied {
        CliError::NotPermitted { path }
    } else {
        CliError::Io { path, source }
    }
}

/// The result of one command, handed back for the caller to print.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Added to the allowlist (and removed from the blocklist).
    Allowed { domain: String, changed: bool },
    /// Added to the blocklist (and removed from the allowlist).
    Blocked { domain: String, changed: bool },
}

impl Outcome {
    /// The single line shown to the user.
    pub fn message(&self) -> String {
        match self {
            Self::Allowed {
                domain,
                changed: true,
            } => {
                format!(
                    "{domain} allowed, effective in a few seconds. To undo: phylode block {domain}"
                )
            }
            Self::Allowed {
                domain,
                changed: false,
            } => {
                format!("{domain} was already on the allowlist; nothing changed")
            }
            Self::Blocked {
                domain,
                changed: true,
            } => {
                format!(
                    "{domain} blocked, effective in a few seconds. To undo: phylode allow {domain}"
                )
            }
            Self::Blocked {
                domain,
                changed: false,
            } => {
                format!("{domain} was already on the blocklist; nothing changed")
            }
        }
    }
}

/// Allows a domain: adds it to the allowlist and removes it from the user blocklist.
pub fn allow(
    domain: &str,
    allowlist: Option<&Path>,
    user_blocklist: Option<&Path>,
) -> Result<Outcome, CliError> {
    let domain = normalize(domain)?;
    let path = allowlist.ok_or(CliError::MissingPath { key: "allowlist" })?;
    if let Some(blocked) = user_blocklist {
        remove_entry(blocked, &domain)?;
    }
    let changed = add_entry(path, &domain)?;
    Ok(Outcome::Allowed { domain, changed })
}

/// Blocks a domain: adds it to the user blocklist and removes it from the allowlist.
pub fn block(
    domain: &str,
    allowlist: Option<&Path>,
    user_blocklist: Option<&Path>,
) -> Result<Outcome, CliError> {
    let domain = normalize(domain)?;
    let path = user_blocklist.ok_or(CliError::MissingPath {
        key: "user_blocklist",
    })?;
    if let Some(allowed) = allowlist {
        remove_entry(allowed, &domain)?;
    }
    let changed = add_entry(path, &domain)?;
    Ok(Outcome::Blocked { domain, changed })
}

/// Converts the input to the form the lists store and queries arrive in, refusing anything
/// the lists would drop when they load.
fn normalize(value: &str) -> Result<String, CliError> {
    Name::from_typed(value)
        .map(|name| name.as_str().to_string())
        .filter(|domain| crate::policy::is_list_domain(domain))
        .ok_or_else(|| CliError::NotADomain {
            value: value.to_string(),
        })
}

/// Adds one line. Returns `false` when it was already there, without writing a duplicate.
fn add_entry(path: &Path, domain: &str) -> Result<bool, CliError> {
    let mut entries = read_entries(path)?;
    if !entries.insert(domain.to_string()) {
        return Ok(false);
    }
    write_entries(path, &entries)?;
    Ok(true)
}

/// Removes one line. Returns `false` when it was not there to begin with.
fn remove_entry(path: &Path, domain: &str) -> Result<bool, CliError> {
    let mut entries = read_entries(path)?;
    if !entries.remove(domain) {
        return Ok(false);
    }
    write_entries(path, &entries)?;
    Ok(true)
}

/// How many domains an allowlist or user blocklist file holds; a missing file holds none.
pub fn entry_count(path: &Path) -> Result<usize, CliError> {
    read_entries(path).map(|entries| entries.len())
}

/// Reads the domains out of a file. A missing file counts as an empty list — that is the
/// normal state before the command has ever been used.
fn read_entries(path: &Path) -> Result<BTreeSet<String>, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => return Err(io_error(path, source)),
    };
    Ok(text
        .lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            (!line.is_empty()).then(|| line.to_ascii_lowercase())
        })
        .collect())
}

/// Rewrites the file in full. A `BTreeSet` keeps the order stable, so the file stays
/// readable when opened directly.
///
/// What breaks if you change it: writing to a staging file and renaming avoids leaving half
/// a list behind on a power cut — half an allowlist means sites that were allowed suddenly
/// stop loading.
fn write_entries(path: &Path, entries: &BTreeSet<String>) -> Result<(), CliError> {
    let mut body = String::from(
        "# Maintained by phylode allow / phylode block. You can also edit it by hand.\n",
    );
    for entry in entries {
        body.push_str(entry);
        body.push('\n');
    }

    // Every failure names the list itself: the staging file is an implementation detail.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| io_error(path, source))?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, body).map_err(|source| io_error(path, source))?;
    std::fs::rename(&temporary, path).map_err(|source| io_error(path, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("phylode-cli-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn allowing_writes_the_file_and_allowing_twice_does_not_duplicate() {
        let dir = temp_dir("allow");
        let allow_file = dir.join("allow.txt");

        let first = allow("shop.example.com", Some(&allow_file), None).unwrap();
        assert_eq!(
            first,
            Outcome::Allowed {
                domain: "shop.example.com".to_string(),
                changed: true
            }
        );

        let again = allow("shop.example.com", Some(&allow_file), None).unwrap();
        assert_eq!(
            again,
            Outcome::Allowed {
                domain: "shop.example.com".to_string(),
                changed: false
            }
        );

        let text = std::fs::read_to_string(&allow_file).unwrap();
        assert_eq!(text.matches("shop.example.com").count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocking_removes_it_from_the_allowlist() {
        let dir = temp_dir("block");
        let allow_file = dir.join("allow.txt");
        let block_file = dir.join("block.txt");

        allow("shop.example.com", Some(&allow_file), Some(&block_file)).unwrap();
        block("shop.example.com", Some(&allow_file), Some(&block_file)).unwrap();

        let allowed = std::fs::read_to_string(&allow_file).unwrap();
        let blocked = std::fs::read_to_string(&block_file).unwrap();
        assert!(
            !allowed.contains("shop.example.com"),
            "it must no longer be on the allowlist"
        );
        assert!(blocked.contains("shop.example.com"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowing_removes_it_from_the_blocklist() {
        let dir = temp_dir("undo");
        let allow_file = dir.join("allow.txt");
        let block_file = dir.join("block.txt");

        block("shop.example.com", Some(&allow_file), Some(&block_file)).unwrap();
        allow("shop.example.com", Some(&allow_file), Some(&block_file)).unwrap();

        let blocked = std::fs::read_to_string(&block_file).unwrap();
        assert!(
            !blocked.contains("shop.example.com"),
            "it must no longer be on the blocklist"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Should change: an internationalized domain is stored in the `xn--` form queries
    /// arrive in, so allowing or blocking it takes effect.
    #[test]
    fn internationalized_domains_are_stored_in_punycode() {
        assert_eq!(normalize("Bücher.de").unwrap(), "xn--bcher-kva.de");
    }

    /// Should change: entries the lists would silently drop are refused when typed, rather
    /// than reported as allowed or blocked.
    #[test]
    fn entries_the_lists_would_ignore_are_rejected() {
        for bad in [
            "*.ads.example.com",
            "https://ads.example.com/path",
            "ads..example.com",
        ] {
            assert!(
                matches!(normalize(bad), Err(CliError::NotADomain { .. })),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn things_that_are_not_domains_are_rejected() {
        for bad in ["", "   ", "localhost", "not a domain"] {
            assert!(
                matches!(normalize(bad), Err(CliError::NotADomain { .. })),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn case_and_the_trailing_dot_are_normalized() {
        assert_eq!(
            normalize("  Shop.Example.COM. ").unwrap(),
            "shop.example.com"
        );
    }

    /// Should change: a folder this account cannot write gives the "use an administrator
    /// account" message, naming the list rather than the staging file.
    /// Should not change: the file is left as it was.
    #[test]
    fn a_list_this_account_may_not_change_says_what_to_do() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("locked");
        let allow_file = dir.join("allow.txt");
        std::fs::write(&allow_file, "kept.example.com\n").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = allow("shop.example.com", Some(&allow_file), None);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = result.expect_err("a read-only folder cannot take a new list");
        assert!(
            matches!(&error, CliError::NotPermitted { path } if path == &allow_file),
            "{error:?}"
        );
        assert!(
            error.to_string().contains("administrator account"),
            "{error}"
        );
        assert_eq!(
            std::fs::read_to_string(&allow_file).unwrap(),
            "kept.example.com\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unset_path_names_the_configuration_key() {
        assert!(matches!(
            allow("shop.example.com", None, None),
            Err(CliError::MissingPath { key: "allowlist" })
        ));
        assert!(matches!(
            block("shop.example.com", None, None),
            Err(CliError::MissingPath {
                key: "user_blocklist"
            })
        ));
    }

    #[test]
    fn the_message_tells_the_user_how_to_undo_it() {
        let outcome = Outcome::Allowed {
            domain: "shop.example.com".to_string(),
            changed: true,
        };
        assert!(outcome.message().contains("phylode block shop.example.com"));
    }
}
