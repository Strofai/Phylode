//! Self health check: the gatekeeper sends itself a probe query at intervals, and exits the
//! process after enough consecutive failures.
//!
//! Why it exists: launchd's `KeepAlive` only checks whether the process is alive. When the
//! process is alive but stuck answering nothing, the system does nothing at all and the
//! whole household simply has no internet — **this is the only thing that catches that
//! failure**.
//!
//! What breaks if you change it: the event must be written to the journal, and given time to
//! land, before the process exits. Without that step the weekly summary never shows the
//! restart, and all anyone sees is "the network was odd for a while" with no explanation.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::dns::self_probe;
use crate::journal::{self, EventKind, Journal};

/// The domain used for probe queries.
///
/// It ends in `.invalid`: RFC 6761 §6.4 permanently reserves that TLD as non-existent, so it
/// cannot collide with a real domain, and answering "no such domain" is the truth.
///
/// What breaks if you change it: the gatekeeper recognizes its own probes by this exact
/// string and **keeps them out of the query journal**. Sending and recognizing use the same
/// constant; split them and health checks start appearing in the statistics.
pub const PROBE_NAME: &str = "health-check.phylode.invalid";

/// How often to send a probe.
///
/// ⚠️ **This value is ours**: Apple, Anthropic and Cloudflare publish none for a resolver
/// probing itself. The reasoning for 10 seconds: detecting
/// a failure takes interval × consecutive failures = 20 seconds, and the restart itself then
/// waits out launchd's 10-second throttle floor (`ThrottleInterval` in
/// `man launchd.plist`). Probing much more often than that cannot shorten recovery.
const PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// How long one probe may take before it counts as a failure.
///
/// ⚠️ **Ours as well.** A probe never touches the network (see [`PROBE_NAME`]) and normally
/// completes in milliseconds, so 2 seconds is already far past "clearly wrong".
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// How many consecutive failures trigger a restart.
///
/// Ours (Apple, Anthropic and Cloudflare publish no figure): the smallest number that is not
/// a single event. What matters is *consecutive* rather than cumulative — one dropped packet
/// must not restart the service.
const RESTART_AFTER_FAILURES: u32 = 2;

/// Exit code on restart: `EX_SOFTWARE` from `sysexits.h` (internal software error). A
/// non-zero value makes it visible in launchd's log that this was not a clean exit.
const EXIT_UNRESPONSIVE: i32 = 70;

/// How long to wait for the journal to land before exiting.
///
/// What breaks if you change it: `process::exit` runs no destructors and does not close the
/// channel, so the writer thread only has its own interval to flush the buffer — **a value
/// shorter than that interval is the same as not waiting at all**, and the symptom is a
/// restart that never appears in the weekly summary.
const FLUSH_WAIT: Duration = journal::FLUSH_INTERVAL.saturating_mul(2);

// These two turn "broke it" into "does not compile", rather than something found in
// production.
const _: () = assert!(
    FLUSH_WAIT.as_secs() > journal::FLUSH_INTERVAL.as_secs(),
    "the flush wait must exceed the writer thread's interval, or this restart will not appear \
     in the weekly summary"
);
const _: () = assert!(
    RESTART_AFTER_FAILURES >= 2,
    "a threshold of 1 would restart the service on a single dropped packet"
);

/// Whether this query is the gatekeeper's own probe. `own` holds the addresses the
/// gatekeeper is bound to.
///
/// What breaks if you change it: when bound to a LAN address the probe arrives from that
/// address, so recognizing only loopback would send it upstream as an ordinary query — and a
/// slow or dead upstream would then time out the probe and make the service restart itself.
/// In the other direction, a recognized query **is not journalled**, so the condition has to
/// stay tight: widening it to "anyone querying this name" opens an unlogged back door.
pub fn is_probe(name: &str, client: IpAddr, own: &[IpAddr]) -> bool {
    name == PROBE_NAME && (client.is_loopback() || own.contains(&client))
}

/// Starts the background self health check. `target` is the gatekeeper's own listening
/// address.
pub fn spawn(target: SocketAddr, journal: Option<Journal>) {
    tokio::spawn(async move { run(target, journal).await });
}

async fn run(target: SocketAddr, journal: Option<Journal>) {
    let reason = watch(target, PROBE_INTERVAL, PROBE_TIMEOUT).await;
    restart(journal.as_ref(), &reason);
}

/// Probes until consecutive failures reach the threshold; returns the last failure's reason.
///
/// The timing is passed in rather than read from the constants so the tests can finish — at
/// production timing one round takes over 20 seconds. The only production caller is [`run`],
/// which passes [`PROBE_INTERVAL`] and [`PROBE_TIMEOUT`].
///
/// Being separate from [`restart`] is likewise for testability: this function returns, and
/// the one that exits the process does not.
async fn watch(target: SocketAddr, interval: Duration, timeout: Duration) -> String {
    let mut consecutive_failures = 0;
    let mut ever_succeeded = false;
    loop {
        tokio::time::sleep(interval).await;
        match self_probe(target, PROBE_NAME, timeout).await {
            Ok(()) => {
                // Announce the first success. Without this line, "the health check never ran
                // at all" and "everything is fine" look identical in the log — and that is
                // exactly the class of failure this feature exists to catch.
                if !ever_succeeded {
                    ever_succeeded = true;
                    eprintln!(
                        "Self health check: first probe succeeded; probing every {} seconds from \
                         here (reported once)",
                        interval.as_secs()
                    );
                }
                // Reset rather than decrement: the threshold counts *consecutive* failures.
                consecutive_failures = 0;
            }
            Err(error) => {
                consecutive_failures += 1;
                eprintln!(
                    "Self health check: no response {consecutive_failures} time(s) in a row \
                     (restarting after {RESTART_AFTER_FAILURES}): {error}"
                );
                if consecutive_failures >= RESTART_AFTER_FAILURES {
                    return error.to_string();
                }
            }
        }
    }
}

/// Records the reason, waits for the journal to land, then exits so launchd restarts us.
fn restart(journal: Option<&Journal>, reason: &str) -> ! {
    record_unresponsive(journal, reason);

    // A deliberately blocking wait. We only get here because the service has stopped
    // answering, so async timers are not necessarily trustworthy any more; and the next line
    // exits the process, so blocking anyone is irrelevant.
    std::thread::sleep(FLUSH_WAIT);
    std::process::exit(EXIT_UNRESPONSIVE);
}

/// Writes "stopped answering" to the event journal and prints it to stderr so launchd's log
/// has it too.
///
/// Separate from [`restart`] for testability — exiting the process cannot be tested, this
/// can.
fn record_unresponsive(journal: Option<&Journal>, reason: &str) {
    let detail = format!(
        "no response to {RESTART_AFTER_FAILURES} consecutive probes ({reason}); exiting so the \
         system restarts the service"
    );
    eprintln!("{detail}");
    if let Some(journal) = journal {
        journal.event(EventKind::Unresponsive, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast timing for tests. Production probes every 10 seconds, which would make one round
    /// take over 20 seconds.
    fn fast_timing() -> (Duration, Duration) {
        (Duration::from_millis(10), Duration::from_millis(200))
    }

    /// How long a test waits at most. Far more than two rounds at `fast_timing` need, so a
    /// timeout here means "the threshold can never be reached", not "this machine is slow".
    fn test_patience() -> Duration {
        Duration::from_secs(10)
    }

    #[test]
    fn the_probe_domain_lives_under_invalid() {
        // RFC 6761 §6.4 guarantees .invalid never exists, so this name cannot collide with a
        // real domain.
        assert!(PROBE_NAME.ends_with(".invalid"));
    }

    #[test]
    fn only_our_own_queries_for_that_name_count_as_probes() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let loopback_v6: IpAddr = "::1".parse().unwrap();
        let other_device: IpAddr = "192.168.0.20".parse().unwrap();
        let our_lan_address: IpAddr = "192.168.0.192".parse().unwrap();
        let own = [our_lan_address];

        assert!(is_probe(PROBE_NAME, loopback, &own));
        assert!(is_probe(PROBE_NAME, loopback_v6, &own));
        assert!(
            is_probe(PROBE_NAME, our_lan_address, &own),
            "bound to a LAN address the probe comes from it; unrecognized, it goes upstream"
        );
        assert!(
            !is_probe(PROBE_NAME, other_device, &own),
            "another device querying this name must still be journalled, or this is an \
             unlogged back door"
        );
        assert!(!is_probe("example.com", loopback, &own));
        assert!(!is_probe("example.com", our_lan_address, &own));
    }

    // "The consecutive-failure threshold is at least 2" and "the flush wait exceeds the
    // writer's interval" are both enforced at compile time by the `const _` blocks at the top
    // of this file, so they are not re-tested here.

    #[tokio::test]
    async fn the_reason_for_a_restart_is_written_to_the_event_journal() {
        // Without it, the weekly summary shows "started twice" and no reason at all.
        let dir = std::env::temp_dir().join(format!(
            "phylode-health-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::start(dir.clone(), 10, 8).unwrap();

        record_unresponsive(Some(&journal), "no response within 2s of sending the probe");
        tokio::time::sleep(FLUSH_WAIT).await;

        let written = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("events-"))
            .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
            .collect::<String>();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(
            written.contains(EventKind::Unresponsive.as_str()),
            "unresponsive is missing from the event journal; actual contents:\n{written}"
        );
        assert!(
            written.contains("no response"),
            "the event journal must retain the reason; actual contents:\n{written}"
        );
    }

    #[tokio::test]
    async fn a_target_that_never_answers_reaches_the_restart_step() {
        // The whole reason this feature exists: the process is alive but answers nothing.
        let idle = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead = idle.local_addr().unwrap();
        drop(idle);

        let (interval, timeout) = fast_timing();
        let reason = tokio::time::timeout(test_patience(), watch(dead, interval, timeout))
            .await
            .expect("reaching the threshold must return; not returning means it never can");
        assert!(
            !reason.is_empty(),
            "it must return with a reason; the weekly summary uses it to explain the restart"
        );
    }

    #[tokio::test]
    async fn a_target_that_answers_never_reaches_the_restart_step() {
        // Without this, the test above would also pass against an implementation that always
        // judges failure.
        let responder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = responder.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            while let Ok((read, from)) = responder.recv_from(&mut buffer).await {
                let Ok(request) = hickory_proto::op::Message::from_vec(&buffer[..read]) else {
                    continue;
                };
                let mut reply = hickory_proto::op::Message::response(
                    request.metadata.id,
                    hickory_proto::op::OpCode::Query,
                );
                reply.add_queries(request.queries.iter().cloned());
                let _ = responder.send_to(&reply.to_vec().unwrap(), from).await;
            }
        });

        // Give it dozens of rounds. When healthy, `watch` never returns, so a timeout is the
        // expected outcome here.
        let (interval, timeout) = fast_timing();
        let outcome = tokio::time::timeout(interval * 50, watch(target, interval, timeout)).await;
        assert!(
            outcome.is_err(),
            "the target answered but it still restarted; returned: {outcome:?}"
        );
    }

    #[test]
    fn it_does_not_panic_without_a_journal() {
        // On a run where the journal could not be opened (main.rs prints a warning), the
        // restart path must still complete.
        record_unresponsive(None, "test");
    }
}
