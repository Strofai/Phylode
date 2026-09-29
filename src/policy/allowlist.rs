//! Allowlist: takes precedence over the blocklist — a match is always allowed.
//!
//! Two layers: **hardcoded Apple rules** (always pass, not configurable, not removable),
//! and the entries the user adds with `phylode allow`.
//!
//! What breaks if you change it: the hard rules are not read from the configuration and do
//! not depend on list loading state. A broken config, a blocklist that fails to load and an
//! emptied allowlist must all still let them through.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, RwLock};

use thiserror::Error;

/// Apple services that must never be blocked under any circumstances.
///
/// Sourced from Apple's enterprise network documentation (support.apple.com/101555):
/// - `captive.apple.com`: block it and every Apple device in the house repeatedly mistakes
///   the network for a captive portal, popping up login windows
/// - `push.apple.com`: block or proxy it and push notifications and iMessage stop working
/// - `mask` / `mask-h2` / `mask-api.icloud.com`: iCloud Private Relay, which this project
///   deliberately does not interfere with — without hardcoding, the day a blocklist picks
///   these up they would start being blocked
/// - `probe` / `pong.icloud.com`: iCloud connectivity checks; blocked, iCloud concludes
///   there is no network
/// - `metrics.icloud.com`: device diagnostics, on Apple's own must-allow list. Apple's other
///   advertising and telemetry endpoints are still blocked by the lists
///
/// What breaks if you change it: **this list must not move into the configuration file.**
/// There it could be edited wrongly or emptied, and the symptom would be every iPhone in the
/// house popping up login windows and missing messages, with no error message pointing here.
/// Widening an entry beyond Apple's own wording (say, all of `apple.com`) would stop Apple's
/// advertising and telemetry from ever being blocked.
const APPLE_HARD_ALLOW: &[&str] = &[
    "captive.apple.com",
    "push.apple.com",
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "mask-api.icloud.com",
    "probe.icloud.com",
    "pong.icloud.com",
    "metrics.icloud.com",
];

#[derive(Debug, Error)]
pub enum AllowlistError {
    #[error("could not read allowlist {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// The allowlist. Cloning is cheap; clones share one set of contents.
#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    user: Arc<RwLock<HashSet<String>>>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this name is allowed unconditionally. The domain itself or any of its
    /// parents matching counts.
    pub fn allows(&self, name: &str) -> bool {
        let user = self.snapshot();
        super::any_suffix(name, |rest| {
            APPLE_HARD_ALLOW.contains(&rest) || user.contains(rest)
        })
    }

    /// Checks the Apple hard rules only, ignoring user entries. Used ahead of rate limiting:
    /// a rate-limited device (and the source address can be forged) must still reach these,
    /// or it will fall back to an unfiltered resolver.
    pub fn hard_allows(name: &str) -> bool {
        super::any_suffix(name, |rest| APPLE_HARD_ALLOW.contains(&rest))
    }

    /// How many entries the user added. Hard rules are not counted.
    pub fn user_len(&self) -> usize {
        self.snapshot().len()
    }

    /// The hardcoded Apple rules, for status reporting.
    pub fn hard_rules() -> &'static [&'static str] {
        APPLE_HARD_ALLOW
    }

    /// Reads the user allowlist from a file: one domain per line, `#` starts a comment.
    ///
    /// A missing file counts as an empty list — that is the normal state before anything has
    /// been allowed, not an error.
    pub fn load_from_file(&self, path: &Path) -> Result<usize, AllowlistError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(AllowlistError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        Ok(self.load_from_str(&text))
    }

    pub fn load_from_str(&self, text: &str) -> usize {
        let entries: HashSet<String> = text
            .lines()
            .filter_map(|line| {
                let line = line.split('#').next().unwrap_or("").trim();
                let domain = line.trim_end_matches('.').to_ascii_lowercase();
                (!domain.is_empty() && domain.contains('.')).then_some(domain)
            })
            .collect();

        let len = entries.len();
        match self.user.write() {
            Ok(mut guard) => *guard = entries,
            Err(poisoned) => *poisoned.into_inner() = entries,
        }
        len
    }

    fn snapshot(&self) -> HashSet<String> {
        match self.user.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_hard_rules_pass_even_with_an_empty_list() {
        let list = Allowlist::new();
        assert!(list.allows("captive.apple.com"));
        assert!(list.allows("push.apple.com"));
        assert_eq!(list.user_len(), 0);
    }

    #[test]
    fn subdomains_of_apple_hard_rules_pass_too() {
        // Apple's push endpoints have the shape *.push.apple.com.
        let list = Allowlist::new();
        assert!(list.allows("1-courier.push.apple.com"));
        assert!(list.allows("gateway.push.apple.com"));
    }

    #[test]
    fn emptying_the_user_allowlist_does_not_affect_apple_hard_rules() {
        // A failed list load, a freshly booted service and an emptied allowlist must all
        // still let these through.
        let list = Allowlist::new();
        list.load_from_str("example.com");
        assert!(list.allows("captive.apple.com"));

        list.load_from_str("");
        assert_eq!(list.user_len(), 0);
        assert!(
            list.allows("captive.apple.com"),
            "hard rules must survive an empty list"
        );
    }

    #[test]
    fn a_user_allowed_domain_and_its_subdomains_pass() {
        let list = Allowlist::new();
        list.load_from_str("shop.example.com\n");
        assert!(list.allows("shop.example.com"));
        assert!(list.allows("checkout.shop.example.com"));
        assert!(
            !list.allows("example.com"),
            "the parent must not be allowed by association"
        );
    }

    /// Should change: Private Relay, iCloud connectivity checks and diagnostics are
    /// hardcoded as allowed.
    /// Should not change: Apple's own advertising and telemetry are not hard rules (they are
    /// blocked by the lists like anything else), and user entries are not hard rules.
    #[test]
    fn hard_rules_contain_only_apples_documented_must_allow_hosts() {
        for name in [
            "mask.icloud.com",
            "mask-h2.icloud.com",
            "mask-api.icloud.com",
            "probe.icloud.com",
            "pong.icloud.com",
            "metrics.icloud.com",
            "1-courier.push.apple.com",
        ] {
            assert!(Allowlist::hard_allows(name), "{name} should be a hard rule");
        }
        for name in [
            "iadsdk.apple.com",
            "metrics.apple.com",
            "icloud.com",
            "apple.com",
        ] {
            assert!(
                !Allowlist::hard_allows(name),
                "{name} must not be hardcoded as allowed"
            );
        }
        let list = Allowlist::new();
        list.load_from_str("shop.example.com");
        assert!(list.allows("shop.example.com"));
        assert!(!Allowlist::hard_allows("shop.example.com"));
    }

    #[test]
    fn nothing_that_was_never_allowed_passes() {
        let list = Allowlist::new();
        assert!(!list.allows("ads.example.com"));
        assert!(
            !list.allows("apple.com.evil.example.com"),
            "a shared prefix is not a match"
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let list = Allowlist::new();
        let count =
            list.load_from_str("# comment\n\nshop.example.com # trailing comment\nnotadomain\n");
        assert_eq!(count, 1);
        assert!(list.allows("shop.example.com"));
    }

    #[test]
    fn a_missing_file_is_an_empty_list_not_an_error() {
        let list = Allowlist::new();
        let missing = std::path::Path::new("/nonexistent/phylode/allowlist.txt");
        assert_eq!(list.load_from_file(missing).unwrap(), 0);
        assert!(list.allows("captive.apple.com"));
    }
}
