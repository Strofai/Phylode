//! Policy layer: decides whether a query is blocked, allowed, or whether the list is
//! unavailable.
//!
//! This layer is kept separate from resolution. What breaks if you change it: policy decisions must not leak into the resolution path,
//! or a change to resolution silently changes what gets blocked.

pub mod allowlist;
pub mod blocklist;
pub mod local_zone;
pub mod ratelimit;
pub mod rebinding;

pub use allowlist::{Allowlist, AllowlistError};
pub use blocklist::{Blocklist, BlocklistError, Verdict};
pub use ratelimit::{Admit, RateLimit};
pub use rebinding::{RebindGuard, Rebinding};

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
