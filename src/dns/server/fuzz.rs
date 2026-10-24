//! Fuzz entry point: treats arbitrary bytes as one UDP packet from a home device and runs
//! parsing, the decision and response assembly end to end.
//!
//! Only compiled under `cargo fuzz` (`cfg(fuzzing)`). What breaks if you change it: this path
//! must match `Handler::handle_request` — once they diverge, the fuzzer stops exercising the
//! real one.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::BinEncoder;
use hickory_server::net::NetError;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;

use super::handler::{Handler, send};
use crate::dns::{Query, Responder, Response};

/// Uses the packet's last byte to pick which response the responder returns and whether the
/// source is admitted, so every response shape gets fed strange names.
struct PickedResponder(u8);

impl Responder for PickedResponder {
    async fn respond(&self, _query: &Query, _client: IpAddr) -> Response {
        // The TTL deliberately includes the u64 maximum, checking the conversion to the
        // wire's u32 does not overflow.
        let ttl = match self.0 >> 4 {
            0 => Duration::ZERO,
            1 => Duration::from_secs(u64::MAX),
            _ => Duration::from_secs(2),
        };
        match self.0 % 5 {
            0 => Response::Blocked { ttl },
            1 => Response::NotFound {
                ttl,
                proof: crate::dns::Proof::default(),
            },
            2 => Response::NoRecords {
                ttl,
                proof: crate::dns::Proof::default(),
            },
            3 => Response::Failure,
            _ => Response::Ignored,
        }
    }

    fn admits(&self, _client: IpAddr) -> bool {
        self.0 & 0x08 == 0
    }
}

/// Encodes the response to wire format without sending it. An encoding failure is a valid
/// outcome (an over-long name, say); a panic is not.
#[derive(Clone)]
struct EncodeOnly;

#[async_trait::async_trait]
impl ResponseHandler for EncodeOnly {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        // The same 512-byte limit the library applies when sending UDP (its `encode` is not
        // public, so this mirrors that path's limit).
        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(512);
        Ok(response.destructive_emit(&mut encoder)?)
    }
}

/// Feeds one packet. The guarantee: no input panics or hangs (neither the responder nor the
/// encoder awaits anything, so a single poll must complete it).
pub fn request(bytes: &[u8]) {
    let src = SocketAddr::from(([192, 168, 1, 2], 5353));
    let Ok(request) = Request::from_bytes(bytes.to_vec(), src, Protocol::Udp) else {
        return;
    };
    let handler = Handler {
        responder: Arc::new(PickedResponder(bytes.last().copied().unwrap_or(0))),
    };
    let finished = async {
        let reply = handler.decide(&request).await;
        let _ = send(&request, &mut EncodeOnly, reply).await;
    }
    .now_or_never();
    assert!(
        finished.is_some(),
        "handling one packet must never need to wait"
    );
}
