//! Phylode — a DNS gatekeeper for networks with Apple devices on them.
//!
//! The layering follows one decision: the protocol layer stays behind `dns` (the only
//! module that touches an external DNS library), while policy, cache, upstream rotation,
//! journalling and reporting are all first-party. The reasoning is that a DNS library is
//! worth depending on for wire-format correctness, whereas the filtering behaviour is the
//! product and must not be hidden inside someone else's abstraction.

// No `unsafe` anywhere in this crate, with two exceptions: `dns::launchd` adopts the
// descriptors launchd hands over as sockets, which buys the service never having to run as
// root; `policy::attached` reads Apple's SystemConfiguration framework, which buys knowing
// which networks are really this Mac's. `deny` rather than `forbid`, because each exception
// needs an explicit allow; their number is guarded by `tests/unsafe_budget.rs`, and one more
// fails the build.
// What breaks if you change it: remove this line and every memory-safety claim stops
// holding.
#![deny(unsafe_code)]

/// Writes one line to the service log (standard error), carrying on if it cannot be written.
/// Use it instead of `eprintln!` everywhere in this program.
///
/// What breaks if you change it: `eprintln!` panics when the write fails, as it does on a full
/// disk, and a panic ends the background task it happened in — list reloading or the self
/// health check would stop with nothing to show for it.
#[macro_export]
macro_rules! log_line {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// Writes one line of command output (standard output), carrying on if it cannot be written.
/// Use it and [`out!`] instead of `println!` and `print!` everywhere in this program.
///
/// It carries on rather than stopping because an install or uninstall that loses its reader
/// halfway would leave the Mac half set up.
///
/// What breaks if you change it: `println!` panics when the reader has gone, as it has once
/// `phylode report | head -1` has its line, and the command ends with a crash message.
#[macro_export]
macro_rules! out_line {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

/// [`out_line!`] without the line break.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stdout(), $($arg)*);
    }};
}

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
