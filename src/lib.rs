//! Phylode — a DNS gatekeeper for networks with Apple devices on them.
//!
//! The layering follows one decision: the protocol layer stays behind `dns` (the only
//! module that touches an external DNS library), while policy, cache, upstream rotation,
//! journalling and reporting are all first-party. The reasoning is that a DNS library is
//! worth depending on for wire-format correctness, whereas the filtering behaviour is the
//! product and must not be hidden inside someone else's abstraction.

// No `unsafe` anywhere in this crate, with one exception in `dns::launchd` — adopting the
// descriptors launchd hands over as sockets, which buys the service never having to run as
// root. `deny` rather than `forbid`, because that exception needs an explicit allow; the
// number of exceptions is guarded by `tests/unsafe_budget.rs`, and one more fails the build.
// What breaks if you change it: remove this line and every memory-safety claim stops
// holding.
#![deny(unsafe_code)]

pub mod cache;
pub mod cli;
pub mod config;
pub mod diagnostics;
pub mod dns;
pub mod gatekeeper;
pub mod health;
pub mod install;
pub mod journal;
pub mod policy;
pub mod report;
pub mod upstream;
