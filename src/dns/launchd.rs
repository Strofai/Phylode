//! Adopts sockets launchd has already bound (Apple's socket activation).
//!
//! Why: port 53 is privileged, so binding it ourselves would mean running as root. Letting
//! launchd bind it and hand the socket over keeps **the service unprivileged throughout** —
//! the native macOS approach, which also avoids the error-prone "bind as root then drop
//! privileges" dance.
//!
//! ⚠️ **One of two files allowed to contain `unsafe`** (the other is `policy/attached.rs`).
//! The crate is `deny(unsafe_code)`; this file opens one exception per function with a SAFETY
//! note, and `tests/unsafe_budget.rs` counts them — one more fails the build.

use std::net::{TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::os::fd::{FromRawFd, RawFd};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LaunchdError {
    #[error("launchd did not hand over a socket named {name}: {source}")]
    Activate {
        name: String,
        #[source]
        source: raunch::Error,
    },
    #[error("the socket launchd handed over could not be set non-blocking: {source}")]
    Configure {
        #[source]
        source: std::io::Error,
    },
}

/// Takes a set of already-bound sockets from launchd. `name` must match the key under
/// `Sockets` in the plist.
pub fn take_sockets(name: &str) -> Result<Vec<RawFd>, LaunchdError> {
    raunch::activate_socket(name).map_err(|source| LaunchdError::Activate {
        name: name.to_string(),
        source,
    })
}

/// Adopts a descriptor from launchd as a UDP socket.
///
/// # Safety
///
/// `fd` must be a descriptor launchd just handed over via `launch_activate_socket` that
/// nothing else has adopted. Callers only pass values returned by [`take_sockets`], which
/// yields each descriptor exactly once (launchd returns `AlreadyActivated` on a second call
/// for the same name), so ownership is unique.
#[allow(unsafe_code)]
pub fn adopt_udp(fd: RawFd) -> Result<StdUdpSocket, LaunchdError> {
    // SAFETY: see the # Safety section above — the fd comes from launchd, ownership is
    // unique, and nothing has adopted it.
    let socket = unsafe { StdUdpSocket::from_raw_fd(fd) };
    socket
        .set_nonblocking(true)
        .map_err(|source| LaunchdError::Configure { source })?;
    Ok(socket)
}

/// Adopts a descriptor from launchd as a TCP listener. Same safety requirements as
/// [`adopt_udp`].
#[allow(unsafe_code)]
pub fn adopt_tcp(fd: RawFd) -> Result<StdTcpListener, LaunchdError> {
    // SAFETY: see the # Safety section on [`adopt_udp`]; the requirements are identical.
    let listener = unsafe { StdTcpListener::from_raw_fd(fd) };
    listener
        .set_nonblocking(true)
        .map_err(|source| LaunchdError::Configure { source })?;
    Ok(listener)
}
