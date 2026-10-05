//! Listens on UDP and TCP, translating wire packets into a [`Query`] and a [`Response`] back
//! into a packet.
//!
//! This is the adapter between the protocol layer and the external DNS library.
//! What breaks if you change it: this is the entry point for untrusted input, so every parse
//! failure must be "drop it or return SERVFAIL" — never a panic, never a REFUSED.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use hickory_proto::op::{Edns, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{HINFO, SOA};
use hickory_proto::rr::{DNSClass, Name as WireName, RData, Record, RecordType as WireRecordType};
use hickory_server::net::NetError;
use hickory_server::net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_server::net::runtime::{Time, TokioRuntimeProvider, TokioTime};
use hickory_server::net::tcp::TcpStream;
use hickory_server::net::udp::UdpStream;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::{
    Request, RequestHandler, ResponseHandle, ResponseHandler, ResponseInfo, TimeoutStream,
};
use hickory_server::zone_handler::MessageResponseBuilder;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use super::launchd::{self, LaunchdError};
use super::{Name, Query, RecordType, Responder, Response};

#[cfg(fuzzing)]
pub mod fuzz;

/// How long a TCP connection may idle before being closed. What breaks if you change it:
/// without a limit, opening many connections that send nothing exhausts the connection count.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Send buffer size per TCP connection. What breaks if you change it: this is the per-
/// connection memory bound, so raising it makes the same number of connections cost more.
const TCP_RESPONSE_BUFFER: usize = 4;

/// Maximum concurrent TCP connections. Ours: Apple, Anthropic and Cloudflare publish no figure
/// for a resolver serving one network.
///
/// What breaks if you change it: without a cap, opening many connections exhausts the file
/// descriptors and UDP stops receiving too. Queries are almost all UDP; TCP is only
/// used when an answer is truncated, so 10 is plenty. New connections arriving at the cap are
/// closed immediately and the device retries.
const MAX_TCP_CONNECTIONS: usize = 10;

/// Maximum UDP queries being handled at once, across every UDP socket; what arrives past it is
/// dropped. Ours: a few hundred devices each in the middle of a page load stay well below it.
///
/// What breaks if you change it: without a cap, each datagram that parses becomes a task
/// before the served-network and rate-limit checks run, so a flood grows memory with no
/// bound. Too low and an ordinary burst gets dropped; devices retry after about a second.
const MAX_UDP_IN_PROGRESS: usize = 1024;

/// Maximum concurrent TCP connections from one source address. The 3 is ours, with no industry
/// source: it lets the pool of 10 serve at least three devices.
///
/// What breaks if you change it: without this layer, one compromised device opening 10 idle
/// connections makes every truncated query on the network fail.
/// What it cannot cover: one device may hold several IPv6 addresses, and the whole network
/// shares one prefix, so these cannot be aggregated per prefix.
const MAX_TCP_PER_SOURCE: usize = 3;

/// How long to wait before accepting again after an accept error. What breaks if you change it:
/// without the pause, exhausted file descriptors make `accept` fail instantly in a tight loop
/// that saturates a core.
const TCP_ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Listeners that are bound but not yet serving.
///
/// They come from two places: in a real deployment launchd binds them and hands them over
/// ([`Listener::from_launchd`], which is why **the service needs no privileges**), and in
/// development the process binds them itself ([`Listener::bind`]).
/// What breaks if you change it: binding port 53 in-process means running as root, which is
/// exactly what this design avoids.
#[derive(Debug)]
pub struct Listener {
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
}

/// The two keys under `Sockets` in the plist. Renaming them means renaming them in the plist
/// too, or launchd hands over nothing.
pub const LAUNCHD_UDP_SOCKET: &str = "PhylodeUdp";
pub const LAUNCHD_TCP_SOCKET: &str = "PhylodeTcp";

impl Listener {
    /// Binds UDP and TCP on each address. This step needs privileges to reach port 53.
    ///
    /// Used in development; real deployments use [`Listener::from_launchd`], which needs none.
    pub async fn bind(addrs: &[SocketAddr]) -> std::io::Result<Self> {
        let mut udp = Vec::with_capacity(addrs.len());
        let mut tcp = Vec::with_capacity(addrs.len());
        for addr in addrs {
            udp.push(UdpSocket::bind(addr).await?);
            tcp.push(TcpListener::bind(addr).await?);
        }
        Ok(Self { udp, tcp })
    }

    /// Adopts sockets launchd already bound. **This is why the service needs no privileges.**
    ///
    /// Fails when not started by launchd; callers should fall back to [`Listener::bind`].
    pub fn from_launchd() -> Result<Self, LaunchdError> {
        let mut udp = Vec::new();
        for fd in launchd::take_sockets(LAUNCHD_UDP_SOCKET)? {
            let socket = launchd::adopt_udp(fd)?;
            udp.push(
                UdpSocket::from_std(socket).map_err(|source| LaunchdError::Configure { source })?,
            );
        }

        let mut tcp = Vec::new();
        for fd in launchd::take_sockets(LAUNCHD_TCP_SOCKET)? {
            let listener = launchd::adopt_tcp(fd)?;
            tcp.push(
                TcpListener::from_std(listener)
                    .map_err(|source| LaunchdError::Configure { source })?,
            );
        }

        Ok(Self { udp, tcp })
    }

    /// How many UDP and TCP listeners are held. Printed at startup to confirm launchd actually
    /// handed something over.
    pub fn counts(&self) -> (usize, usize) {
        (self.udp.len(), self.tcp.len())
    }

    /// The concrete addresses bound (wildcards excluded; loopback is recognized separately by
    /// the caller). Health check probes arrive from one of these.
    pub fn local_ips(&self) -> Vec<IpAddr> {
        let udp = self.udp.iter().filter_map(|s| s.local_addr().ok());
        let tcp = self.tcp.iter().filter_map(|s| s.local_addr().ok());
        let mut ips: Vec<IpAddr> = udp
            .chain(tcp)
            .map(|addr| addr.ip())
            .filter(|ip| !ip.is_unspecified())
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }

    /// Where the self health check should send its probe. `None` when there is no UDP listener.
    ///
    /// When bound to a wildcard (`0.0.0.0` / `::`) this uses loopback instead — those two are
    /// binding wildcards, not reachable destinations.
    /// What breaks if you change it: sending to whatever `local_addr()` returns means the probe
    /// cannot be delivered whenever launchd bound a wildcard, and the symptom is a perfectly
    /// healthy service restarting itself over and over.
    pub fn probe_target(&self) -> Option<SocketAddr> {
        let addr = self.udp.first()?.local_addr().ok()?;
        Some(match addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
            }
            IpAddr::V6(ip) if ip.is_unspecified() => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
            }
            _ => addr,
        })
    }
}

/// Starts serving until the process ends. Privileges should already have been dropped.
///
/// Both UDP and TCP are received here rather than by the library: its UDP loop answers a
/// datagram it cannot parse before any admission check, and its TCP path has no total
/// connection cap. Returns only when a receive loop stops, so the supervisor restarts the service.
pub async fn serve<R: Responder>(listener: Listener, responder: Arc<R>) -> Result<(), NetError> {
    let handler = Arc::new(Handler { responder });
    // Every receive loop is watched: when any of them ends, so does the service, and launchd
    // starts it again. What breaks if you change it: the self health check only probes UDP,
    // so a TCP loop that died unwatched would leave truncated answers failing for good.
    let mut loops = JoinSet::new();
    let slots = TcpSlots::new(MAX_TCP_CONNECTIONS, MAX_TCP_PER_SOURCE);
    for tcp in listener.tcp {
        let (handler, slots) = (Arc::clone(&handler), Arc::clone(&slots));
        loops.spawn(async move {
            serve_tcp(tcp, handler, slots).await;
            Err(NetError::from("a TCP listener stopped"))
        });
    }
    let udp_slots = Arc::new(Semaphore::new(MAX_UDP_IN_PROGRESS));
    for socket in listener.udp {
        loops.spawn(serve_udp(
            socket,
            Arc::clone(&handler),
            Arc::clone(&udp_slots),
        ));
    }
    match loops.join_next().await {
        Some(Ok(stopped)) => stopped,
        Some(Err(_)) => Err(NetError::from("a receive loop stopped unexpectedly")),
        None => std::future::pending().await,
    }
}

/// The receive loop for one UDP socket. A datagram that parses goes to the handler, which
/// decides whether its source gets any reply; one that does not parse is dropped unanswered,
/// as on TCP. Returns only on an error the socket cannot recover from.
///
/// What breaks if you change it: handing UDP back to the library's loop makes every malformed
/// datagram, from anywhere, get a "format error" reply — usable for reflection.
async fn serve_udp<R: Responder>(
    socket: UdpSocket,
    handler: Arc<Handler<R>>,
    slots: Arc<Semaphore>,
) -> Result<(), NetError> {
    // Replies go to each datagram's own source; this address is never used.
    let unused = SocketAddr::from(([127, 255, 255, 254], 0));
    let (mut datagrams, sender) = UdpStream::<TokioRuntimeProvider>::with_bound(socket, unused);
    while let Some(datagram) = datagrams.next().await {
        let message = match datagram {
            Ok(message) => message,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotConnected | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Err(error.into());
            }
            Err(_) => continue,
        };
        let (bytes, from) = message.into_parts();
        // A reply to port 0 or to the unspecified address cannot be delivered.
        if from.port() == 0 || from.ip().is_unspecified() {
            continue;
        }
        let Ok(request) = Request::from_bytes(bytes, from, Protocol::Udp) else {
            continue;
        };
        let Some(slot) = udp_slot(&slots, from.ip()) else {
            continue;
        };
        let reply_to = ResponseHandle::new(from, sender.with_remote_addr(from), Protocol::Udp);
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            handler
                .handle_request::<_, TokioTime>(&request, reply_to)
                .await;
            drop(slot);
        });
    }
    Err(NetError::from("the UDP socket closed"))
}

/// Whether a datagram from `source` gets handled: `Some` with the slot it holds until the
/// handling ends, or `None` to drop it because every slot is taken. Loopback is handled
/// without a slot.
///
/// What breaks if you change it: the self health check arrives over loopback and must never
/// be the one dropped, or a flood makes a working service restart itself. macOS discards
/// loopback sources arriving on any other interface (XNU `ip_input`, `ip6_input`), so they
/// cannot be forged from the network.
fn udp_slot(slots: &Arc<Semaphore>, source: IpAddr) -> Option<Option<OwnedSemaphorePermit>> {
    match Arc::clone(slots).try_acquire_owned() {
        Ok(permit) => Some(Some(permit)),
        Err(_) if source.to_canonical().is_loopback() => Some(None),
        Err(_) => None,
    }
}

/// The accept loop for one TCP listener. It does what the library's own loop does, plus
/// connection slots (one pool for the whole network, one per source): at the cap, new connections
/// are closed rather than queued.
///
/// What breaks if you change it: queries within one connection are handled one at a time with
/// no extra tasks spawned, so a single connection can never consume more than one query's worth
/// of processing (copied from the library's own approach).
async fn serve_tcp<R: Responder>(
    listener: TcpListener,
    handler: Arc<Handler<R>>,
    slots: Arc<TcpSlots>,
) {
    loop {
        let (socket, src) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                tokio::time::sleep(TCP_ACCEPT_BACKOFF).await;
                continue;
            }
        };
        // A source that is not admitted is disconnected before it can hold a slot; otherwise a
        // few outside addresses could fill the pool and lock the served devices out of TCP.
        if !handler.responder.admits(src.ip()) {
            drop(socket);
            continue;
        }
        let Some(slot) = slots.try_take(src.ip()) else {
            drop(socket);
            continue;
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _slot = slot;
            let (stream, sender) = TcpStream::from_stream_with_buffer_size(
                AsyncIoTokioAsStd(socket),
                src,
                TCP_RESPONSE_BUFFER,
            );
            let mut messages = TimeoutStream::new(stream, TCP_IDLE_TIMEOUT);
            while let Some(Ok(message)) = messages.next().await {
                let (bytes, from) = message.into_parts();
                // A packet that does not parse ends the connection: untrusted input gets no
                // response and never panics.
                let Ok(request) = Request::from_bytes(bytes, from, Protocol::Tcp) else {
                    return;
                };
                let reply_to = ResponseHandle::new(from, sender.clone(), Protocol::Tcp);
                handler
                    .handle_request::<_, TokioTime>(&request, reply_to)
                    .await;
            }
        });
    }
}

/// TCP connection slots: a network-wide total, plus a per-source-address cap.
struct TcpSlots {
    total: Arc<Semaphore>,
    per_source: usize,
    held: Mutex<HashMap<IpAddr, usize>>,
}

/// The slot one connection holds. Dropping it at the end of the connection returns both.
struct TcpSlot {
    _total: OwnedSemaphorePermit,
    slots: Arc<TcpSlots>,
    source: IpAddr,
}

impl TcpSlots {
    fn new(total: usize, per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            per_source,
            held: Mutex::new(HashMap::new()),
        })
    }

    /// Granted only when both kinds of slot are available; `None` means the caller closes the
    /// connection.
    fn try_take(self: &Arc<Self>, source: IpAddr) -> Option<TcpSlot> {
        let total = Arc::clone(&self.total).try_acquire_owned().ok()?;
        let mut held = self.lock();
        let count = held.entry(source).or_insert(0);
        if *count >= self.per_source {
            return None;
        }
        *count += 1;
        Some(TcpSlot {
            _total: total,
            slots: Arc::clone(self),
            source,
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
        // A poisoned lock means a thread panicked holding it; the counts are still usable, and
        // continuing to serve beats shutting TCP down entirely.
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for TcpSlot {
    fn drop(&mut self) {
        let mut held = self.slots.lock();
        if let Some(count) = held.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.source);
            }
        }
    }
}

struct Handler<R: Responder> {
    responder: Arc<R>,
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
    async fn decide(&self, request: &Request) -> Reply {
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
            Response::Answer(records) => Reply::Answer(records),
            Response::Blocked { ttl } => Reply::Blocked {
                name: wire_name,
                ttl,
                record_type: wire_type,
            },
            Response::NotFound { ttl } => Reply::Negative {
                name: wire_name,
                ttl,
                code: ResponseCode::NXDomain,
            },
            // The name exists and simply has no records of this type: NOERROR, an empty answer
            // section, and the SOA attached.
            // What breaks if you change it: returning NXDOMAIN here makes a device conclude an
            // IPv4-only site does not exist at all once it asks for AAAA, so it stops trying
            // IPv4 too.
            Response::NoRecords { ttl } => Reply::Negative {
                name: wire_name,
                ttl,
                code: ResponseCode::NoError,
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

enum Reply {
    Answer(super::Records),
    /// Blocked by a list: return an address nothing can connect to.
    Blocked {
        name: WireName,
        ttl: Duration,
        record_type: WireRecordType,
    },
    /// A response with no answer: the attached SOA tells the device how long to remember it.
    Negative {
        name: WireName,
        ttl: Duration,
        code: ResponseCode,
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
const MAX_UDP_PAYLOAD: u16 = 1232;

/// The EDNS a reply carries when the query had one: the device's own size, within 512 and
/// [`MAX_UDP_PAYLOAD`] — the same as the library's own server, plus the upper bound.
fn reply_edns(requested: &Edns) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(requested.max_payload().clamp(512, MAX_UDP_PAYLOAD));
    edns
}

async fn send<H: ResponseHandler>(
    request: &Request,
    handle: &mut H,
    reply: Reply,
) -> Result<ResponseInfo, NetError> {
    let edns = request.edns.as_ref().map(reply_edns);
    let mut builder = MessageResponseBuilder::from_message_request(request);
    if let Some(edns) = &edns {
        builder.edns(edns);
    }
    let mut metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
    metadata.recursion_available = true;

    match reply {
        Reply::Answer(records) => {
            let message = builder.build(metadata, records.as_wire(), &[], &[], &[]);
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
        Reply::Negative { name, ttl, code } => {
            metadata.response_code = code;
            // RFC 2308: a negative response needs an SOA, or the device has nothing to base its
            // caching on and will mostly just keep asking.
            let soa = vec![negative_soa(&name, ttl)];
            let message = builder.build(metadata, &[], &[], soa.as_slice(), &[]);
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
    use hickory_proto::op::{Message, Query as WireQuery};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A responder that answers "does not exist" to everything, keeping TCP tests away from the
    /// lists and upstreams.
    struct AlwaysNotFound;

    impl Responder for AlwaysNotFound {
        async fn respond(&self, _query: &Query, _client: IpAddr) -> Response {
            Response::NotFound {
                ttl: Duration::from_secs(2),
            }
        }

        fn admits(&self, _client: IpAddr) -> bool {
            true
        }
    }

    /// A responder whose answer is 40 addresses — about 670 bytes, past the 512 a reply
    /// without EDNS may use.
    struct ManyAddresses;

    impl Responder for ManyAddresses {
        async fn respond(&self, query: &Query, _client: IpAddr) -> Response {
            let addresses: Vec<IpAddr> =
                (1..=40u8).map(|n| IpAddr::from([203, 0, 113, n])).collect();
            Response::Answer(crate::dns::Records::from_addresses(
                query.name(),
                Duration::from_secs(60),
                &addresses,
            ))
        }

        fn admits(&self, _client: IpAddr) -> bool {
            true
        }
    }

    /// A responder that admits a single address, standing in for a network where every other
    /// source is outside.
    struct AdmitsOnly(IpAddr);

    impl Responder for AdmitsOnly {
        async fn respond(&self, _query: &Query, _client: IpAddr) -> Response {
            Response::NotFound {
                ttl: Duration::from_secs(2),
            }
        }

        fn admits(&self, client: IpAddr) -> bool {
            client == self.0
        }
    }

    /// A responder that admits nobody, standing in for a source outside the served networks.
    struct AdmitsNobody;

    impl Responder for AdmitsNobody {
        async fn respond(&self, _query: &Query, _client: IpAddr) -> Response {
            Response::Ignored
        }

        fn admits(&self, _client: IpAddr) -> bool {
            false
        }
    }

    /// A responder that counts how many times it was asked.
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);

    impl Responder for Counting {
        async fn respond(&self, _query: &Query, _client: IpAddr) -> Response {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Response::NotFound {
                ttl: Duration::from_secs(2),
            }
        }

        fn admits(&self, _client: IpAddr) -> bool {
            true
        }
    }

    async fn tcp_server(limit: usize) -> SocketAddr {
        tcp_server_with(limit, Arc::new(AlwaysNotFound)).await
    }

    async fn tcp_server_with<R: Responder>(limit: usize, responder: Arc<R>) -> SocketAddr {
        tcp_server_full(limit, limit, responder).await
    }

    async fn tcp_server_full<R: Responder>(
        total: usize,
        per_source: usize,
        responder: Arc<R>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(
            listener,
            Arc::new(Handler { responder }),
            TcpSlots::new(total, per_source),
        ));
        addr
    }

    /// Asks once over a TCP connection, returning true if an answer comes back.
    async fn ask(conn: &mut tokio::net::TcpStream) -> bool {
        ask_code(conn, "example.com.".parse().unwrap())
            .await
            .is_some()
    }

    /// Asks for `name` over a TCP connection and returns the response code, or `None` if there
    /// is no response.
    async fn ask_code(conn: &mut tokio::net::TcpStream, name: WireName) -> Option<ResponseCode> {
        ask_type(conn, name, WireRecordType::A)
            .await
            .map(|reply| reply.metadata.response_code)
    }

    /// Asks for `name` of `record_type` over a TCP connection and returns the whole response,
    /// or `None` if there is none.
    async fn ask_type(
        conn: &mut tokio::net::TcpStream,
        name: WireName,
        record_type: WireRecordType,
    ) -> Option<Message> {
        ask_query(conn, WireQuery::query(name, record_type)).await
    }

    /// Sends `query` over a TCP connection and returns the whole response, or `None` if there
    /// is none.
    async fn ask_query(conn: &mut tokio::net::TcpStream, query: WireQuery) -> Option<Message> {
        let mut message = Message::query();
        message.add_query(query);
        let bytes = message.to_vec().unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        conn.write_all(&framed).await.ok()?;
        let mut len = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), conn.read_exact(&mut len))
            .await
            .ok()?
            .ok()?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len))];
        conn.read_exact(&mut body).await.ok()?;
        Message::from_vec(&body).ok()
    }

    /// Should change: a fourth connection from one source is closed, and closing one frees it
    /// again.
    /// Should not change: while the total pool has room, the per-source cap is the only thing
    /// rejecting anything (3 of 10 used).
    #[tokio::test]
    async fn tcp_allows_at_most_three_connections_per_source() {
        let addr = tcp_server_full(10, 3, Arc::new(AlwaysNotFound)).await;
        let mut held = Vec::new();
        for _ in 0..3 {
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            assert!(
                ask(&mut conn).await,
                "connections within the cap must get an answer"
            );
            held.push(conn);
        }
        let mut fourth = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            !ask(&mut fourth).await,
            "the fourth from one source should be closed"
        );

        held.pop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut again = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            ask(&mut again).await,
            "closing one must return that source's slot"
        );
    }

    #[test]
    fn per_source_slots_are_counted_separately() {
        let slots = TcpSlots::new(10, 1);
        let a: IpAddr = "192.168.0.20".parse().unwrap();
        let b: IpAddr = "192.168.0.21".parse().unwrap();
        let first = slots.try_take(a).expect("a's first connection");
        assert!(slots.try_take(a).is_none(), "a has used up its own slots");
        let _b = slots.try_take(b).expect("b is unaffected by a");
        drop(first);
        assert!(
            slots.try_take(a).is_some(),
            "a can take one again after returning it"
        );
    }

    /// Should change: ANY returns an "RFC8482" HINFO and never reaches the responder (so it
    /// never goes upstream).
    #[tokio::test]
    async fn an_any_query_returns_the_rfc8482_hinfo() {
        let counting = Arc::new(Counting::default());
        let addr = tcp_server_with(10, Arc::clone(&counting)).await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();

        let reply = ask_type(
            &mut conn,
            "example.com.".parse().unwrap(),
            WireRecordType::ANY,
        )
        .await
        .expect("ANY must get a response");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
        match &reply.answers[0].data {
            RData::HINFO(hinfo) => assert_eq!(&*hinfo.cpu, b"RFC8482"),
            other => panic!("expected HINFO; got {other:?}"),
        }
        assert_eq!(
            counting.0.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "ANY must never reach the responder"
        );
    }

    /// Should change: a name sent as raw UTF-8 bytes returns SERVFAIL all three times and never
    /// reaches the responder (the upstreams sit behind the responder, so never reaching it means
    /// no upstream can be blamed).
    /// Should not change: an ordinary domain still reaches the responder.
    #[tokio::test]
    async fn a_name_that_does_not_convert_fails_without_being_forwarded() {
        let counting = Arc::new(Counting::default());
        let addr = tcp_server_with(10, Arc::clone(&counting)).await;
        let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();

        let raw = WireName::from_labels(vec!["δοκιμή".as_bytes(), b"com"]).unwrap();
        for _ in 0..3 {
            assert_eq!(
                ask_code(&mut conn, raw.clone()).await,
                Some(ResponseCode::ServFail)
            );
        }
        assert_eq!(counting.0.load(std::sync::atomic::Ordering::Relaxed), 0);

        assert_eq!(
            ask_code(&mut conn, "example.com.".parse().unwrap()).await,
            Some(ResponseCode::NXDomain)
        );
        assert_eq!(counting.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    /// Should change: a source the responder does not admit gets no reply to an ANY query, a
    /// non-Internet class or an unconvertible name — the replies the server writes by itself.
    /// Should not change: an admitted source gets each of those replies (the control).
    #[tokio::test]
    async fn replies_the_server_writes_itself_go_only_to_admitted_sources() {
        let any = WireQuery::query("example.com.".parse().unwrap(), WireRecordType::ANY);
        let mut chaos = WireQuery::query("version.bind.".parse().unwrap(), WireRecordType::TXT);
        chaos.set_query_class(DNSClass::CH);
        let raw = WireQuery::query(
            WireName::from_labels(vec!["δοκιμή".as_bytes(), b"com"]).unwrap(),
            WireRecordType::A,
        );

        let admitted = tcp_server(10).await;
        let mut conn = tokio::net::TcpStream::connect(admitted).await.unwrap();
        for (query, expected) in [
            (any.clone(), ResponseCode::NoError),
            (chaos.clone(), ResponseCode::NotImp),
            (raw.clone(), ResponseCode::ServFail),
        ] {
            let reply = ask_query(&mut conn, query).await;
            assert_eq!(reply.map(|r| r.metadata.response_code), Some(expected));
        }

        let outside = tcp_server_with(10, Arc::new(AdmitsNobody)).await;
        let mut conn = tokio::net::TcpStream::connect(outside).await.unwrap();
        for query in [any, chaos, raw] {
            assert!(ask_query(&mut conn, query).await.is_none());
        }
    }

    /// Serves UDP on a loopback port through `serve`, the path the installed service uses.
    async fn udp_server<R: Responder>(responder: Arc<R>) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let listener = Listener {
            udp: vec![socket],
            tcp: Vec::new(),
        };
        tokio::spawn(serve(listener, responder));
        addr
    }

    /// Sends one datagram and returns the reply, or `None` if none arrives within a second.
    async fn udp_ask(server: SocketAddr, packet: &[u8]) -> Option<Vec<u8>> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(packet, server).await.unwrap();
        let mut reply = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut reply))
            .await
            .ok()?
            .ok()?;
        reply.truncate(len);
        Some(reply)
    }

    /// Should change: with every slot taken, a datagram from the network is dropped, and a
    /// slot given back makes room again.
    /// Should not change: loopback (the self health check) is handled even when full.
    #[test]
    fn udp_drops_past_the_cap_except_loopback() {
        let slots = Arc::new(Semaphore::new(1));
        let device: IpAddr = "192.168.0.20".parse().unwrap();
        let held = udp_slot(&slots, device).expect("one slot is free");
        assert!(held.is_some());

        assert!(udp_slot(&slots, device).is_none(), "full: dropped");
        for loopback in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(
                matches!(udp_slot(&slots, loopback.parse().unwrap()), Some(None)),
                "{loopback}"
            );
        }

        drop(held);
        assert!(matches!(udp_slot(&slots, device), Some(Some(_))));
    }

    /// Should change: a datagram whose header reads but whose question does not gets no reply,
    /// from an admitted source or not, rather than the "format error" a reply would carry.
    /// Should not change: a well-formed query from an admitted source is answered (the control).
    #[tokio::test]
    async fn udp_sends_nothing_back_for_a_packet_it_cannot_parse() {
        let mut query = Message::query();
        query.add_query(WireQuery::query(
            "example.com.".parse().unwrap(),
            WireRecordType::A,
        ));
        let well_formed = query.to_vec().unwrap();
        // ID, flags, one question, then a name label cut off after two of its three bytes.
        let cut_off = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x03, b'a', b'b',
        ];

        let admitted = udp_server(Arc::new(AlwaysNotFound)).await;
        assert!(udp_ask(admitted, &well_formed).await.is_some());
        assert_eq!(udp_ask(admitted, &cut_off).await, None);

        let outside = udp_server(Arc::new(AdmitsNobody)).await;
        assert_eq!(udp_ask(outside, &cut_off).await, None);
    }

    /// Should change: a device that says it can take a larger reply (EDNS) gets the whole
    /// answer in one datagram, told the size it may use, rather than a truncated reply that
    /// sends it over to TCP; a size above 1232 bytes is lowered to 1232.
    /// Should not change: a query without EDNS still gets a reply within 512 bytes.
    #[tokio::test]
    async fn a_large_answer_fits_one_datagram_when_the_device_can_take_it() {
        let server = udp_server(Arc::new(ManyAddresses)).await;
        let mut query = Message::query();
        query.add_query(WireQuery::query(
            "big.example.com.".parse().unwrap(),
            WireRecordType::A,
        ));
        let plain = udp_ask(server, &query.to_vec().unwrap()).await.unwrap();
        assert!(plain.len() <= 512);
        assert!(Message::from_vec(&plain).unwrap().metadata.truncation);

        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        query.set_edns(edns);
        let reply = udp_ask(server, &query.to_vec().unwrap()).await.unwrap();
        let reply = Message::from_vec(&reply).unwrap();
        assert!(!reply.metadata.truncation);
        assert_eq!(reply.answers.len(), 40);
        assert_eq!(reply.edns.map(|edns| edns.max_payload()), Some(1232));
    }

    /// Should change: a message that is itself a response gets no reply, so a forged one cannot
    /// set this server talking to another.
    /// Should not change: the same message sent as a query is answered (the control).
    #[tokio::test]
    async fn a_message_that_is_a_response_gets_no_reply() {
        let mut message = Message::query();
        message.add_query(WireQuery::query(
            "example.com.".parse().unwrap(),
            WireRecordType::A,
        ));
        let server = udp_server(Arc::new(AlwaysNotFound)).await;
        assert!(udp_ask(server, &message.to_vec().unwrap()).await.is_some());

        message.metadata.message_type = MessageType::Response;
        assert_eq!(udp_ask(server, &message.to_vec().unwrap()).await, None);
    }

    /// Should change: a connection from a source that is not admitted is closed at once and
    /// holds no slot, so such sources cannot crowd out the devices that are served.
    /// Should not change: an admitted source still gets answers over TCP.
    #[tokio::test]
    async fn sources_that_are_not_admitted_hold_no_tcp_slot() {
        // One listener for both families: `::1` is admitted, and 127.0.0.1 (which arrives as
        // `::ffff:127.0.0.1`) is not.
        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responder = Arc::new(AdmitsOnly(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        tokio::spawn(serve_tcp(
            listener,
            Arc::new(Handler { responder }),
            TcpSlots::new(2, 2),
        ));

        let mut outside = Vec::new();
        for _ in 0..2 {
            let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let mut byte = [0u8; 1];
            let closed = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut byte))
                .await
                .is_ok_and(|read| matches!(read, Ok(0) | Err(_)));
            assert!(closed, "a source that is not admitted must be disconnected");
            outside.push(conn);
        }

        let mut served = tokio::net::TcpStream::connect(("::1", port)).await.unwrap();
        assert!(
            ask(&mut served).await,
            "the served device must still get an answer"
        );
    }

    /// Should change: new connections are closed once the pool is full.
    /// Should not change: connections within the cap still get answers, and closing one returns
    /// its slot.
    #[tokio::test]
    async fn tcp_closes_new_connections_when_full_and_returns_slots() {
        let addr = tcp_server(2).await;
        let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            ask(&mut first).await,
            "connections within the cap must get an answer"
        );
        assert!(ask(&mut second).await);

        let mut third = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            !ask(&mut third).await,
            "the third exceeds the cap and should be closed"
        );

        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut fourth = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            ask(&mut fourth).await,
            "a closed connection must return its slot"
        );
    }

    #[tokio::test]
    async fn a_specific_bind_address_is_where_the_probe_goes() {
        let listener = Listener::bind(&["127.0.0.1:0".parse().unwrap()])
            .await
            .unwrap();
        let target = listener
            .probe_target()
            .expect("a UDP listener means there is an address to probe");
        assert_eq!(target.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_ne!(
            target.port(),
            0,
            "it must report the port actually bound, not the configured 0"
        );
    }

    #[tokio::test]
    async fn our_own_addresses_list_concrete_ones_not_wildcards() {
        let specific = Listener::bind(&["127.0.0.1:0".parse().unwrap()])
            .await
            .unwrap();
        assert_eq!(specific.local_ips(), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let any = Listener::bind(&["0.0.0.0:0".parse().unwrap()])
            .await
            .unwrap();
        assert!(
            any.local_ips().is_empty(),
            "0.0.0.0 is nobody's source address"
        );
    }

    #[tokio::test]
    async fn a_wildcard_bind_sends_the_probe_to_loopback_instead() {
        // 0.0.0.0 is a binding wildcard, not a reachable destination. Sending to it directly
        // makes the probe fail, and a perfectly healthy service restarts itself endlessly.
        let listener = Listener::bind(&["0.0.0.0:0".parse().unwrap()])
            .await
            .unwrap();
        let target = listener.probe_target().unwrap();
        assert_eq!(target.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

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

    #[test]
    fn no_udp_listener_means_there_is_nothing_to_probe() {
        let listener = Listener {
            udp: Vec::new(),
            tcp: Vec::new(),
        };
        assert!(listener.probe_target().is_none());
    }
}
