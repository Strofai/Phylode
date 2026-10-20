//! Drives a running Phylode from thousands of source addresses to check that a device over its
//! rate limit stays limited while new sources fill the table.
//!
//! It needs a server and the source addresses below assigned to this machine, which only the
//! throwaway runner in `.github/workflows/live.yml` sets up, so it is ignored in a normal
//! `cargo test`. What breaks if you change the addresses: they must match the aliases the
//! workflow adds, or every send fails to bind.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a helper that panics fails the test that called it, which is how a test should fail"
)]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Where the server listens; the workflow assigns it to the loopback interface.
const SERVER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 99, 255, 1)), 15353);
/// The device that floods. A private address, so it is served and rate-limited.
const DEVICE: Ipv4Addr = Ipv4Addr::new(10, 99, 255, 250);
/// A device that has never asked, used to show the table still makes room.
const NEWCOMER: Ipv4Addr = Ipv4Addr::new(10, 99, 255, 251);
/// How many other sources arrive. More than the 4096 the table tracks, so it has to forget some.
const OTHER_SOURCES: u32 = 5000;
/// Queries a device may send per window, as in `src/policy/ratelimit.rs`.
const MAX_PER_WINDOW: u32 = 1000;
/// A name on the server's blocklist, answered without asking an upstream.
const BLOCKED_NAME: &str = "ads.example.test";

/// The `n`th other source: 10.99.0.1 upwards, 250 per block of 256.
fn other_source(n: u32) -> Ipv4Addr {
    let block = u8::try_from(n / 250).expect("fewer than 64000 sources");
    let host = u8::try_from(n % 250 + 1).expect("host part is 1 to 250");
    Ipv4Addr::new(10, 99, block, host)
}

/// A standard A query for `name` with recursion desired.
fn query(id: u16, name: &str) -> Vec<u8> {
    let mut packet = Vec::with_capacity(32);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        packet.push(u8::try_from(label.len()).expect("label under 64 bytes"));
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

/// Sends one query from `source` and reports whether a reply arrived within `wait`.
fn answered(socket: &UdpSocket, id: u16, wait: Duration) -> bool {
    socket
        .set_read_timeout(Some(wait))
        .expect("read timeout is non-zero");
    socket
        .send_to(&query(id, BLOCKED_NAME), SERVER)
        .expect("send to the server");
    let mut reply = [0u8; 512];
    loop {
        match socket.recv_from(&mut reply) {
            Ok((len, _)) if len >= 2 && reply[..2] == id.to_be_bytes() => return true,
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
}

fn bind(source: Ipv4Addr) -> UdpSocket {
    UdpSocket::bind((source, 0)).unwrap_or_else(|error| {
        panic!("could not send from {source} ({error}); is it assigned to this machine?")
    })
}

/// Should change: a device over its limit that falls silent while more new sources arrive than
/// the table holds is still unanswered afterwards, rather than coming back to a fresh allowance.
/// Should not change: the device is answered up to its limit, and a new device is answered.
#[test]
#[ignore = "needs a running server and the source addresses from .github/workflows/live.yml"]
fn a_device_over_its_limit_stays_limited_while_new_sources_fill_the_table() {
    let reply_wait = Duration::from_secs(2);
    let started = Instant::now();

    let device = bind(DEVICE);
    for id in 0..MAX_PER_WINDOW {
        let id = u16::try_from(id).expect("fewer than 65536 queries");
        assert!(
            answered(&device, id, reply_wait),
            "query {id} within the limit went unanswered"
        );
    }
    assert!(
        !answered(&device, 60000, reply_wait),
        "the query past the limit was answered"
    );
    println!("device: {MAX_PER_WINDOW} answered, the next one not");

    assert!(
        answered(&bind(NEWCOMER), 1, reply_wait),
        "a device that had never asked went unanswered"
    );

    for n in 0..OTHER_SOURCES {
        let id = u16::try_from(n % 60000).expect("under 60000");
        assert!(
            answered(&bind(other_source(n)), id, reply_wait),
            "new source {} went unanswered",
            other_source(n)
        );
    }
    println!("{OTHER_SOURCES} other sources: all answered");

    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(50),
        "took {elapsed:?}, too close to the 60-second window to judge"
    );
    assert!(
        !answered(&device, 60001, reply_wait),
        "the device over its limit was answered again after {OTHER_SOURCES} new sources arrived"
    );
    println!("device after the new sources: still unanswered ({elapsed:?} into its window)");
}
