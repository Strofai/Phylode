//! Turns one request packet into a [`Query`] for the responder, and its [`Response`] back into
//! a reply packet.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Edns, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{HINFO, SOA};
use hickory_proto::rr::{DNSClass, Name as WireName, RData, Record, RecordType as WireRecordType};
use hickory_server::net::NetError;
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::dns::{Name, Query, RecordType, Responder, Response, Signatures};

/// The retry and expire fields, in seconds, of the SOA in a blocked response.
/// These do not affect how soon a device asks again (the TTL decides that); they only give the
/// response the shape RFC 2308 requires.
const SOA_REFRESH: i32 = 3600;
const SOA_RETRY: i32 = 600;
const SOA_EXPIRE: i32 = 86_400;

/// How long a device caches the HINFO returned for an ANY query. RFC 8482 §4.2 leaves this to
/// the operator: long enough to suppress repeated ANY queries, not so long that a later change
/// of approach cannot be rolled out. One hour is ours, with no industry source.
const ANY_HINFO_TTL: u32 = 3600;

/// The request handler the UDP and TCP paths share.
pub(super) struct Handler<R: Responder> {
    pub(super) responder: Arc<R>,
}

#[async_trait::async_trait]
impl<R: Responder> RequestHandler for Handler<R> {
    async fn handle_request<H: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: H,
    ) -> ResponseInfo {
        let reply = self.decide(request).await;
        match send(request, &mut response_handle, reply).await {
            Ok(info) => info,
            // A failed send usually means the peer already disconnected; there is nothing to do
            // but let the layer above record a failure.
            Err(_) => ResponseInfo::from(hickory_proto::op::Header {
                metadata: failure_metadata(request),
                counts: Default::default(),
            }),
        }
    }
}

impl<R: Responder> Handler<R> {
    pub(super) async fn decide(&self, request: &Request) -> Reply {
        // A message that is itself a response is never answered: answering one lets two servers
        // be set against each other with a single forged packet.
        if request.metadata.message_type == MessageType::Response {
            return Reply::Ignore;
        }
        // A reply the server writes by itself still goes through the responder's admission:
        // sources outside the served networks, or over their rate limit, get nothing at all.
        let (query, wire_name, wire_type) = match parse(request) {
            Ok(parsed) => parsed,
            Err(reply) if self.responder.admits(request.src().ip()) => return reply,
            Err(_) => return Reply::Ignore,
        };

        match self.responder.respond(&query, request.src().ip()).await {
            Response::Answer(records) => Reply::Answer {
                records,
                asked: wire_type,
            },
            Response::Blocked { ttl } => Reply::Blocked {
                name: wire_name,
                ttl,
                record_type: wire_type,
            },
            Response::NotFound { ttl, proof } => Reply::Negative {
                name: wire_name,
                ttl,
                code: ResponseCode::NXDomain,
                proof,
            },
            // The name exists and simply has no records of this type: NOERROR, an empty answer
            // section, and the SOA attached.
            // What breaks if you change it: returning NXDOMAIN here makes a device conclude an
            // IPv4-only site does not exist at all once it asks for AAAA, so it stops trying
            // IPv4 too.
            Response::NoRecords { ttl, proof } => Reply::Negative {
                name: wire_name,
                ttl,
                code: ResponseCode::NoError,
                proof,
            },
            Response::Failure => Reply::Code(ResponseCode::ServFail),
            Response::Ignored => Reply::Ignore,
        }
    }
}

/// Turns a request into a query for the responder, or into the reply the server gives by
/// itself when the request is not one the responder handles.
fn parse(request: &Request) -> Result<(Query, WireName, WireRecordType), Reply> {
    // Only standard queries are handled. Other opcodes get "not implemented", which is the
    // protocol-correct answer and, unlike REFUSED, does not push the device to another
    // resolver.
    if request.metadata.op_code != OpCode::Query {
        return Err(Reply::Code(ResponseCode::NotImp));
    }

    let info = request
        .request_info()
        .map_err(|_| Reply::Code(ResponseCode::FormErr))?;
    let wire_query = info.query;
    if wire_query.query_class() != DNSClass::IN {
        return Err(Reply::Code(ResponseCode::NotImp));
    }

    let wire_name = WireName::from(wire_query.name().clone());
    let wire_type = wire_query.query_type();
    // ANY queries get a synthetic HINFO per RFC 8482 §4.2 and never go upstream: forwarding
    // them verbatim returns a large response, which is ammunition for reflection
    // amplification. Not "not implemented" either — like REFUSED, that can send the device
    // to another resolver.
    if wire_type == WireRecordType::ANY {
        return Err(Reply::AnyHinfo { name: wire_name });
    }
    // Names that do not convert to a valid domain fail here rather than going upstream; see
    // `Name::from_wire`.
    let Some(name) = Name::from_wire(&wire_name) else {
        return Err(Reply::Code(ResponseCode::ServFail));
    };
    let query = Query::new(name, RecordType::from_wire(wire_type));
    Ok((query, wire_name, wire_type))
}

pub(super) enum Reply {
    /// An answer; which records go out depends on whether the device asked for signatures and
    /// on the type it asked for.
    Answer {
        records: crate::dns::Records,
        asked: WireRecordType,
    },
    /// Blocked by a list: return an address nothing can connect to.
    Blocked {
        name: WireName,
        ttl: Duration,
        record_type: WireRecordType,
    },
    /// A response with no answer: the attached SOA tells the device how long to remember it.
    /// A device that asked for signatures gets the upstream's `proof` instead, when there is one.
    Negative {
        name: WireName,
        ttl: Duration,
        code: ResponseCode,
        proof: crate::dns::Proof,
    },
    /// The fixed answer for ANY queries (RFC 8482).
    AnyHinfo {
        name: WireName,
    },
    Code(ResponseCode),
    /// Send nothing.
    Ignore,
}

/// The addresses returned for a block: two wildcards nothing can ever connect to.
///
/// What breaks if you change it: pointing these at a real address (an explanation page, say)
/// makes that machine receive every blocked connection on the network, turning the filter into a
/// traffic funnel.
const BLOCKED_V4: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
const BLOCKED_V6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

/// Builds the record returned for a block. A and AAAA each get their own wildcard; other types
/// have no corresponding unreachable address and get "no records of this type" instead.
fn blocked_record(name: &WireName, ttl: Duration, record_type: WireRecordType) -> Option<Record> {
    let seconds = u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX);
    let rdata = match record_type {
        WireRecordType::A => RData::A(BLOCKED_V4.into()),
        WireRecordType::AAAA => RData::AAAA(BLOCKED_V6.into()),
        _ => return None,
    };
    let mut record = Record::from_rdata(name.clone(), seconds, rdata);
    record.dns_class = DNSClass::IN;
    Some(record)
}

/// The largest UDP reply sent to a device that says it can take more than 512 bytes: the DNS
/// Flag Day 2020 recommendation (dnsflagday.net/2020), small enough never to be split into IP
/// fragments, which some routers drop.
///
/// What breaks if you change it: set it higher and some large replies arrive as fragments that
/// are lost on the way. Leave EDNS out of replies altogether and every answer over 512 bytes is
/// truncated, sending the device to TCP, where the whole network shares a few connection slots.
pub(in crate::dns) const MAX_UDP_PAYLOAD: u16 = 1232;

/// The EDNS a reply carries when the query had one: the device's own size, within 512 and
/// [`MAX_UDP_PAYLOAD`] — the same as the library's own server, plus the upper bound — and the
/// device's DO bit echoed back, which tells it the signatures it asked for are included
/// (RFC 3225).
fn reply_edns(requested: &Edns) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(requested.max_payload().clamp(512, MAX_UDP_PAYLOAD));
    edns.set_dnssec_ok(requested.flags().dnssec_ok);
    edns
}

pub(super) async fn send<H: ResponseHandler>(
    request: &Request,
    handle: &mut H,
    reply: Reply,
) -> Result<ResponseInfo, NetError> {
    let edns = request.edns.as_ref().map(reply_edns);
    // Whether the device asked for signatures: only then do they, and the upstream's proofs,
    // go out (RFC 4035 §3.2.1).
    let signatures = if request
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok)
    {
        Signatures::Requested
    } else {
        Signatures::NotRequested
    };
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    let mut metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
    metadata.recursion_available = true;

    match reply {
        Reply::Answer { records, asked } => {
            let (answers, authority) = records.for_device(signatures, asked);
            let message =
                builder.build(metadata, answers.as_slice(), &[], authority.as_slice(), &[]);
            handle.send_response(message).await
        }
        Reply::Blocked {
            name,
            ttl,
            record_type,
        } => match blocked_record(&name, ttl, record_type) {
            Some(record) => {
                let answers = vec![record];
                let message = builder.build(metadata, answers.as_slice(), &[], &[], &[]);
                handle.send_response(message).await
            }
            // Types other than A/AAAA have no unreachable address to return.
            // NOERROR with an SOA (meaning "this name has no such record"), **never REFUSED** —
            // that would send the device to the next resolver on its list.
            None => {
                metadata.response_code = ResponseCode::NoError;
                let soa = vec![negative_soa(&name, ttl)];
                let message = builder.build(metadata, &[], &[], soa.as_slice(), &[]);
                handle.send_response(message).await
            }
        },
        Reply::Negative {
            name,
            ttl,
            code,
            proof,
        } => {
            metadata.response_code = code;
            // RFC 2308: a negative response needs an SOA, or the device has nothing to base its
            // caching on and will mostly just keep asking. A device that validates signatures
            // gets the upstream's own SOA and proof instead: one made up here is unsigned, and
            // proves nothing to it.
            let authority = if signatures == Signatures::Requested && !proof.as_wire().is_empty() {
                proof.as_wire().to_vec()
            } else {
                vec![negative_soa(&name, ttl)]
            };
            let message = builder.build(metadata, &[], &[], authority.as_slice(), &[]);
            handle.send_response(message).await
        }
        Reply::AnyHinfo { name } => {
            let hinfo = HINFO::new("RFC8482".to_string(), String::new());
            let mut record = Record::from_rdata(name, ANY_HINFO_TTL, RData::HINFO(hinfo));
            record.dns_class = DNSClass::IN;
            let answers = vec![record];
            let message = builder.build(metadata, answers.as_slice(), &[], &[], &[]);
            handle.send_response(message).await
        }
        // Send nothing at all. The returned info is only for the library's statistics and never
        // goes out.
        Reply::Ignore => Ok(ResponseInfo::from(hickory_proto::op::Header {
            metadata: failure_metadata(request),
            counts: Default::default(),
        })),
        Reply::Code(code) => {
            metadata.response_code = code;
            handle
                .send_response(builder.build_no_records(metadata))
                .await
        }
    }
}

/// Builds the SOA for a negative response. The TTL and MINIMUM use the same value, so the
/// device caches this "does not exist" for exactly the configured block TTL.
fn negative_soa(name: &WireName, ttl: Duration) -> Record {
    let seconds = u32::try_from(ttl.as_secs()).unwrap_or(u32::MAX);
    let zone = name.clone();
    let rdata = SOA::new(
        zone.clone(),
        zone.clone(),
        1,
        SOA_REFRESH,
        SOA_RETRY,
        SOA_EXPIRE,
        seconds,
    );
    let mut record = Record::from_rdata(zone, seconds, RData::SOA(rdata));
    record.dns_class = DNSClass::IN;
    record
}

fn failure_metadata(request: &Request) -> hickory_proto::op::Metadata {
    let mut metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
    metadata.response_code = ResponseCode::ServFail;
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_returns_an_unreachable_address_matching_the_queried_type() {
        let name: WireName = "ads.example.com.".parse().unwrap();
        let ttl = Duration::from_secs(2);

        let v4 =
            blocked_record(&name, ttl, WireRecordType::A).expect("an A query must get a record");
        assert_eq!(
            v4.ttl, 2,
            "the TTL must be the configured block seconds; larger and an allow stops taking effect promptly"
        );
        assert_eq!(
            v4.data.to_string(),
            "0.0.0.0",
            "any other address funnels every blocked connection on the network to that machine"
        );

        let v6 = blocked_record(&name, ttl, WireRecordType::AAAA)
            .expect("an AAAA query must get a record");
        assert_eq!(v6.data.to_string(), "::");

        assert!(
            blocked_record(&name, ttl, WireRecordType::HTTPS).is_none(),
            "outside A/AAAA there is no unreachable address, so it must take the no-such-type path"
        );
        assert!(blocked_record(&name, ttl, WireRecordType::MX).is_none());
    }
}
