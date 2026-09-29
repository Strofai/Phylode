//! Sends a probe query to ourselves, checking that "the process is alive" and "it still
//! answers" are the same thing.
//!
//! What breaks if you change it: building and parsing packets belongs under `dns` and nowhere
//! else — that is the protocol layer boundary. "How many consecutive failures trigger a
//! restart" is not a protocol concern and lives in [`crate::health`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, Query as WireQuery};
use hickory_proto::rr::{Name as WireName, RecordType as WireRecordType};
use thiserror::Error;
use tokio::net::UdpSocket;

/// Reply buffer size. A UDP response without EDNS is capped at 512 bytes (RFC 1035 §4.2.1),
/// and the query we send deliberately carries no EDNS, so this is enough.
const REPLY_BUFFER: usize = 512;

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("could not build a valid packet for probe domain {name}: {source}")]
    BadName {
        name: String,
        #[source]
        source: hickory_proto::ProtoError,
    },
    #[error("could not send the probe: {source}")]
    Send {
        #[source]
        source: std::io::Error,
    },
    #[error("no response within {waited:?} of sending the probe")]
    Timeout { waited: Duration },
    #[error("the probe response could not be parsed: {source}")]
    Malformed {
        #[source]
        source: hickory_proto::serialize::binary::DecodeError,
    },
    #[error("the probe response does not match the query that was sent")]
    Mismatched,
}

/// Sends one probe to `target` and waits for a response or a timeout.
///
/// **Any response that parses and matches the query counts as "still answering"**, including
/// SERVFAIL — with every upstream down the service is supposed to return SERVFAIL, and that is
/// not the service being broken. Counting it as a failure would turn one internet outage into
/// an endless restart loop. Only a network-layer error counts as not answering.
///
/// "Matches" compares two things: the transaction ID, and the domain in the response's
/// question section — two of the four checks RFC 5452 section 3 requires; the other two,
/// source address and port, are handled by the kernel, because the socket is connected.
pub async fn self_probe(
    target: SocketAddr,
    name: &str,
    timeout: Duration,
) -> Result<(), ProbeError> {
    let wire_name: WireName = name.parse().map_err(|source| ProbeError::BadName {
        name: name.to_string(),
        source,
    })?;

    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(WireQuery::query(wire_name.clone(), WireRecordType::A));
    let sent_id = message.metadata.id;
    let bytes = message.to_vec().map_err(|source| ProbeError::BadName {
        name: name.to_string(),
        source,
    })?;

    let socket = UdpSocket::bind(ephemeral_for(target))
        .await
        .map_err(|source| ProbeError::Send { source })?;
    // Connecting means the kernel only delivers packets from target; nothing else reaches us.
    socket
        .connect(target)
        .await
        .map_err(|source| ProbeError::Send { source })?;
    socket
        .send(&bytes)
        .await
        .map_err(|source| ProbeError::Send { source })?;

    let mut buffer = [0u8; REPLY_BUFFER];
    let read = tokio::time::timeout(timeout, socket.recv(&mut buffer))
        .await
        .map_err(|_| ProbeError::Timeout { waited: timeout })?
        .map_err(|source| ProbeError::Send { source })?;

    let reply =
        Message::from_vec(&buffer[..read]).map_err(|source| ProbeError::Malformed { source })?;
    if reply.metadata.id != sent_id {
        return Err(ProbeError::Mismatched);
    }
    // Compare through this crate's own normalization rather than the external library's name
    // type directly.
    // What breaks if you change it: a name decoded from the wire is the fully qualified form
    // with a root dot, which is not equal to the locally parsed one — compared directly,
    // **every probe would be judged a mismatch**, and the symptom is a perfectly healthy
    // service restarting itself every few dozen seconds.
    let expected = super::Name::parse(name);
    match reply.queries.first() {
        Some(question) if super::Name::from_wire(question.name()) == Some(expected) => Ok(()),
        _ => Err(ProbeError::Mismatched),
    }
}

/// Which address the probe goes out from: an ephemeral port on the same protocol as the
/// destination.
fn ephemeral_for(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_source_address_matches_the_destination_protocol() {
        let v4: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let v6: SocketAddr = "[::1]:53".parse().unwrap();
        assert!(ephemeral_for(v4).is_ipv4());
        assert!(ephemeral_for(v6).is_ipv6());
        assert_eq!(ephemeral_for(v4).port(), 0, "the system picks the port");
    }

    #[tokio::test]
    async fn an_address_with_no_listener_times_out_rather_than_hanging() {
        // Bind a port and release it, giving an address almost certainly nobody is listening on.
        let idle = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = idle.local_addr().unwrap();
        drop(idle);

        let waited = Duration::from_millis(150);
        let error = self_probe(target, "health-check.phylode.invalid", waited)
            .await
            .expect_err("no response must not be reported as success");
        assert!(
            matches!(error, ProbeError::Timeout { .. } | ProbeError::Send { .. }),
            "expected a timeout or send failure; got {error:?}"
        );
    }

    #[tokio::test]
    async fn a_response_with_a_mismatched_transaction_id_does_not_count() {
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = responder.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = [0u8; REPLY_BUFFER];
            let Ok((read, from)) = responder.recv_from(&mut buffer).await else {
                return;
            };
            let request = Message::from_vec(&buffer[..read]).unwrap();
            // Deliberately reply with a different transaction ID.
            let mut reply = Message::response(
                request.metadata.id.wrapping_add(1),
                hickory_proto::op::OpCode::Query,
            );
            reply.add_queries(request.queries.iter().cloned());
            let _ = responder.send_to(&reply.to_vec().unwrap(), from).await;
        });

        let error = self_probe(
            target,
            "health-check.phylode.invalid",
            Duration::from_secs(2),
        )
        .await
        .expect_err("a mismatched ID means this is not our response");
        assert!(matches!(error, ProbeError::Mismatched), "got {error:?}");
    }

    #[tokio::test]
    async fn a_servfail_response_still_counts_as_answering() {
        // With every upstream down the service returns SERVFAIL by design. Counting that as a
        // failure would make one outage restart the service repeatedly, which is worse.
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = responder.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = [0u8; REPLY_BUFFER];
            let Ok((read, from)) = responder.recv_from(&mut buffer).await else {
                return;
            };
            let request = Message::from_vec(&buffer[..read]).unwrap();
            let mut reply = Message::error_msg(
                request.metadata.id,
                hickory_proto::op::OpCode::Query,
                hickory_proto::op::ResponseCode::ServFail,
            );
            reply.add_queries(request.queries.iter().cloned());
            let _ = responder.send_to(&reply.to_vec().unwrap(), from).await;
        });

        self_probe(
            target,
            "health-check.phylode.invalid",
            Duration::from_secs(2),
        )
        .await
        .expect("SERVFAIL means the service is still responding, so it is alive");
    }
}
