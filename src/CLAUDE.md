# src/ — the gatekeeper itself

## Six behaviours that are visible when they go wrong

1. **A blocked answer may only be cached by the client for a few seconds.** Set the TTL
   higher and after allowing a domain, that iPhone still cannot reach it for hours.
2. **Never return `REFUSED`, under any circumstances.** Devices retry immediately, causing a
   storm, and then move on to the next resolver in their list — filtering drops to zero on
   the spot. Cloudflare Gateway returns REFUSED for non-A/AAAA types; do not follow suit.
   Their clients have exactly one resolver configured; a household typically has several.
3. **When the list is unavailable, allow — but never cache that allow.** Cached, the domain
   stays reachable for the cache lifetime even after the list recovers.
4. **"No such domain" and SERVFAIL from an upstream do not mean the upstream is down.**
   `Exchange::query` returns `Answer` (records, name does not exist, no such type); only a
   genuine connection failure is `Err`, and `Conductor` counts failures on `Err` alone.
   Merge them and every typo in the house produces "the server is broken" while a healthy
   upstream gets demoted. On SERVFAIL, `Exchange` retries with the CD flag: getting an
   answer means the signature failed to validate (`Signature::Bogus`, report-only); getting
   nothing returns `Answer::ServerFailure`. Neither counts as an upstream failure.
5. **Over the rate limit, do not respond at all — and still do not return REFUSED.** The
   loopback address is exempt; the self health check goes through it.
6. **TCP connections are accepted by our own code** (`serve_tcp` in `dns/server.rs`) because
   hickory's TCP path has no total connection cap. When upgrading hickory, re-check whether
   its `handle_tcp` has grown that protection.

## Module layering

`dns/` protocol layer, **the only place that touches the external DNS library** |
`upstream/` upstream rotation | `policy/` blocklist, allowlist, local zones, rate limiting,
rebinding defence | `cache/` bounded answer cache | `journal/` query and event journal |
`report/` weekly summary | `config/` first-party parser | `cli/` commands |
`install/` sets the boot service up and removes it |
`gatekeeper.rs` the single seam between the layers.

## Encode rules in types, not in comments

`UpstreamProtocol` has only Tls and Https (a plaintext option does not exist in the type);
`dns::Response` has no `Refused`; `CacheWrite` is a named type rather than a bool;
`dns::Answer` separates "the name does not exist" from "the upstream is unreachable".
Downgrading, returning REFUSED, caching a fail-open allow, or counting a negative answer as
a failure all require changing a type first, and the compiler will stop you. Keep that
property.

## Known boundaries

- **`unsafe` appears only in `dns/launchd.rs`** (adopting the descriptors launchd hands
  over). The crate is `deny(unsafe_code)`, and `tests/unsafe_budget.rs` counts the
  exceptions — one more fails the build.
- Packet-level bounds checking, compression-pointer loop defence and transaction ID matching
  are **done by hickory, not by us**. It has been audited by X41 D-Sec, but "someone else
  audited it" and "we verified it" are different claims; do not conflate them in a report.
