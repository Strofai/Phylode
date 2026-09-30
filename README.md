# Phylode

A DNS gatekeeper for Apple households. Every device on your network gets ads, trackers,
malicious domains and chatty appliances filtered out before they resolve — while Apple's
own services are always let through.

The name combines the Greek *phylax* (guardian) and *ōidē* (song): a guardian's song.

## Status (2026-09-30)

**The core works and six of the security hardening items are done. There are no releases yet;
`main` is what runs.**

Working today: domain blocking, encrypted upstream forwarding, answer caching, a query
journal, an allowlist, the `allow`/`block`/`status`/`report` commands, deployment files
that start the service at boot, plus:

- **Self health check** — sends itself a real query every 10 seconds; two silent rounds in
  a row and it writes the reason to the journal and exits so the supervisor restarts it.
- **DNS rebinding protection** — an upstream answer pointing into your home network is
  discarded in full.
- **Resource limits** — 1000 queries per minute per device, 300 in-flight upstream
  queries, 10 concurrent TCP connections.
- **Request coalescing** — the same domain is only asked upstream once at a time.
- **DNSSEC in report-only mode** — signature failures resolve as usual and are counted in
  the weekly summary.
- **Automatic upstream recovery** — a failed upstream is re-probed and returns to rotation
  when it recovers.
- **Dependency vulnerability checks** — `cargo deny check`, rules in `deny.toml`.
- **Daily blocklist updates** — Hagezi Pro plus Threat Intelligence Feeds, roughly 1.06
  million domains; the new list is only swapped in after its entry count is validated, and
  the previous version is kept.
- **CNAME cloaking defence** — a clean-looking name whose alias points at a tracker is
  blocked too.
- **Internal names never leave the house** — `.local`, the router's search domain and
  private-address reverse lookups are answered locally.
- **Upstream certificates verified against the macOS system trust store** — root
  certificates update with the OS.
- **Negative answers are cached too** — "no such domain" is remembered for up to an hour.
- **Weekly summaries archived for 12 weeks** — the archive excludes ordinarily allowed
  domains.

About 10,500 lines of first-party code, 9 direct dependencies (181 packages in
`Cargo.lock`), 187 tests.

**Fuzzing**: four entry points (packets from home devices, packets from upstream, the
blocklist parser, the config parser), under `fuzz/`, run by a GitHub Actions workflow. The
latest run gave each target 10 minutes: 114 million cases in total, no crashes or hangs.

**Not done yet**, in this order: packet-layer validation, macOS sandboxing.

## What it does

Every example below has been verified against a running instance.

```
$ dig @127.0.0.1 iadsdk.apple.com
iadsdk.apple.com.  2  IN  A  0.0.0.0      ← blocked (Apple ads, on the Hagezi list), TTL 2s

$ dig @127.0.0.1 apple.com
apple.com.  165  IN  A  17.253.144.10     ← fetched over an encrypted upstream

$ dig @127.0.0.1 no-such-domain.example
;; ->>HEADER<<- status: NXDOMAIN          ← upstream says it does not exist, relayed with its SOA

$ dig @127.0.0.1 192.168.0.1.nip.io
;; ->>HEADER<<- status: NOERROR, ANSWER: 0  ← this name resolves into the home network,
192.168.0.1.nip.io.  2  IN  SOA  ...           so the whole answer is dropped (rebinding defence)

$ phylode allow doubleclick.net
doubleclick.net allowed, effective in a few seconds. To undo: phylode block doubleclick.net

$ phylode report
Gatekeeper, week of 2026-09-14
1. Blocked 2 queries (4 total)
...
6. Was there a window with no protection?
   No — protection was continuous.
```

## Deliberate design choices

- **No downgrade when upstreams fail.** If every encrypted upstream is unreachable, stale
  cache entries carry the load — it will **never** fall back to plaintext DNS. This follows
  RFC 8310 Strict Privacy, which is also the factory default for Apple's encrypted DNS.
  The rule is encoded in the type system: there is no "plaintext query" variant in the code.

- **It never returns REFUSED.** That would make devices retry immediately and cause a
  storm, and would push them to the next resolver on their list — filtering would silently
  stop working. The `Response` type has no such variant; a device over the rate limit gets
  no answer at all instead.

- **"This domain does not exist" is an answer, not a failure.** The types keep the two
  apart (`Answer` vs `Err`), so a typo gets a correct NXDOMAIN while an upstream that
  answered correctly is never recorded as down.

- **It restarts itself when it hangs without exiting.** A boot supervisor only checks
  whether the process is alive; it cannot detect "still running but no longer answering".

- **An upstream answer pointing into the home network is discarded in full.** This is the
  technique for turning a browser into a pivot into your LAN. One internal address in a
  batch voids the entire batch — an attacker will mix in a public address betting that
  only individual records get filtered. Domains that genuinely belong to your network go
  in the config's `internal_domain`; the default is empty.

- **When the blocklist fails to load, queries are allowed — and that allow is not cached.**
  Caching it would keep the domain reachable after the list recovers.

- **`captive.apple.com` and `push.apple.com` are hardcoded to always resolve.** Block the
  first and every Apple device in the house pops up a captive-portal login window; block
  the second and push notifications and iMessage stop working.

- **The service does not run as root.** launchd binds port 53 and hands the socket over
  (Apple's native socket activation).

- **Zero file I/O on the answer path.** Journal entries go into a bounded channel and a
  dedicated thread batches them to disk.

- **No control channel of any kind.** The commands edit plain text files. No network port,
  no unix socket.

## Out of scope for v1

Routing all traffic through the gatekeeper, protection while away from home, a graphical
interface, telemetry of any kind.

## Built with

Rust, on macOS. The protocol layer uses [hickory-dns](https://github.com/hickory-dns/hickory-dns)
(independently audited; used by Let's Encrypt and Google Pixel) behind a thin local
interface. Policy, cache, journal, reporting, configuration and the CLI are all
first-party.

The whole crate is `deny(unsafe_code)`. The only exception is the pair of functions that
adopt launchd's file descriptors; a test counts the exceptions and fails the build if one
more appears.

## Install

Needs macOS and a Rust toolchain ([rustup](https://rustup.rs)). Tested on macOS 26 and 27 on
Apple silicon; installing, switching on and off, and uninstalling are exercised end to end in
CI on every change.

```bash
cargo build --release
sudo ./target/release/phylode install   # boot service, lists, daily updates
sudo phylode on                         # point this Mac's DNS at it
```

`sudo phylode off` puts this Mac's DNS back to automatic. `sudo phylode uninstall` does that
first, then removes the service; your configuration, lists and journal are left in place.

Install stops without changing anything if a folder it writes into as root (`/usr/local/bin`
and friends) can be changed by a standard, non-administrator account.

If something goes wrong, `phylode diagnostics` prints versions, states, counts and recent
service events with addresses and home folders removed — written to be pasted into a public
issue. Do not post the query journal or `phylode status`; they hold your browsing history and
configuration.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option, following the convention of the Rust ecosystem.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project shall be dual licensed as above, without any additional terms
or conditions.

---

繁體中文版：[README.zh-TW.md](README.zh-TW.md)
