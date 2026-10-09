//! Policy layer: decides whether a query is blocked, allowed, or whether the list is
//! unavailable.
//!
//! This layer is kept separate from resolution. What breaks if you change it: policy decisions must not leak into the resolution path,
//! or a change to resolution silently changes what gets blocked.

pub mod allowlist;
pub mod attached;
pub mod blocklist;
pub mod clients;
pub mod local_zone;
pub mod ratelimit;
pub mod rebinding;

pub use allowlist::{Allowlist, AllowlistError};
pub use attached::AttachedNetworks;
pub use blocklist::{Blocklist, BlocklistError, Verdict};
pub use clients::ServedNetworks;
pub use ratelimit::{Admit, RateLimit};
pub use rebinding::{RebindGuard, Rebinding};

/// Whether a lowercase entry can match a query name: at least two labels, each 1–63
/// characters of ASCII letters, digits, `-` or `_`, 253 at most in all. The blocklist, the
/// allowlist and the `allow`/`block` commands all go through this.
///
/// What breaks if you change it: an entry the lists accept but no query can match (a `*.`
/// wildcard, a URL, Unicode instead of `xn--`) is reported as allowed or blocked and silently
/// does nothing.
pub(crate) fn is_list_domain(domain: &str) -> bool {
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

/// Matches if `hit` holds for the name itself or any of its parents (`ads.example.com` tries
/// `ads.example.com`, then `example.com`, then `com`). Lowercases and strips the trailing
/// dot first; an empty name never matches.
///
/// What breaks if you change it: the blocklist, allowlist, Apple hard rules, internal-domain
/// exemptions and local zones all depend on this one function. Narrow it to exact names and
/// every subdomain stops matching.
pub(crate) fn any_suffix(name: &str, hit: impl Fn(&str) -> bool) -> bool {
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return false;
    }
    // Names from the wire are already lowercase (`dns::Name`), so the common case borrows.
    let name: std::borrow::Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        name.to_ascii_lowercase().into()
    } else {
        name.into()
    };
    let mut rest = name.as_ref();
    loop {
        if hit(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, parent)) if !parent.is_empty() => rest = parent,
            _ => return false,
        }
    }
}
