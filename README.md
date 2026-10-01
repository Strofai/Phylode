**English** · [繁體中文](README.zh-TW.md)

# Phylode

Phylode keeps ads, trackers and malicious sites away from every device on your network —
phones, laptops, TVs, game consoles, smart speakers — from a single Mac. It works at the
DNS level, so nothing needs to be installed on the devices themselves, and it is built
with Apple devices in mind: Apple's own services always work, and iCloud Private Relay is
left alone.

It suits any network with a Mac that stays on: a home, an office, a studio, a school.

## What it blocks

Phylode blocks domains on two lists maintained by
[HaGeZi](https://github.com/hagezi/dns-blocklists), the combination HaGeZi recommends:

- **Multi PRO** — ads, trackers, analytics, telemetry from apps and appliances, and
  common scams, phishing and malware.
- **Threat Intelligence Feeds (Medium)** — domains known for malware, phishing, scams and
  cryptojacking, drawn from security feeds.

Together they hold about one million domains once duplicates are removed. The Mac
downloads both every day at 04:17 and only switches to a new copy after checking that it
is complete, keeping the previous one. The lists are not part of this repository; HaGeZi
publishes them under GPL-3.0.

A few things are never blocked, whatever any list says: `captive.apple.com`, which Apple
devices use to detect Wi-Fi sign-in pages, and Apple's push notification and Private
Relay services.

If something you need is blocked, allow it with one command; the change takes effect
within seconds on every device:

```bash
phylode allow example.com
```

Choosing between stricter or more relaxed lists is planned for a later version.

## Install

You need a Mac that stays on, running macOS, and the Rust toolchain
([rustup](https://rustup.rs)). Phylode is tested on macOS 26 and 27 on Apple silicon, and
every change to the program is installed, switched on and off, and uninstalled on a fresh
Mac in CI.

```bash
git clone https://github.com/Strofai/Phylode.git
cd Phylode
cargo build --release
sudo ./target/release/phylode install
sudo phylode on
```

`install` sets up the service so it starts when the Mac does, downloads the lists and waits
until it is answering. `on` points this Mac's own DNS at it and ends by printing the Mac's
address on the network, which you need for the next step.

Install stops without changing anything if one of the folders it writes to as root, such
as `/usr/local/bin`, can be changed by a standard account.

## Set up your network

To protect every device, they need to ask the Mac for DNS instead of your router or
internet provider.

1. In your router's settings, reserve a fixed address for the Mac, so it keeps the same
   address after a restart.
2. In the router's DHCP settings, set the DNS server to that address and remove any
   other DNS servers. Devices pick up the change when they next reconnect.
3. If your network has IPv6, check whether the router also hands out its own IPv6 DNS
   servers. Devices may use those instead and skip filtering; turn that option off or
   point it at the Mac too. See [SECURITY.md](SECURITY.md).

Without access to the router, you can set the DNS server on each device instead.
Step-by-step guides for common routers are planned.

Phylode answers devices on the private address ranges that home and office networks use
(10.x, 172.16–31.x, 192.168.x, 100.64–127.x, 169.254.x, and IPv6 `fc00::/7` and
`fe80::/10`), and nothing else. If your network uses public addresses, add a
`serve_network` line to `/usr/local/etc/phylode.conf` and run `sudo phylode install` again.

## Everyday use

| Command | What it does |
|---|---|
| `phylode allow <domain>` | Allow a domain on every device, within seconds |
| `phylode block <domain>` | Block a domain on every device, within seconds |
| `phylode report` | This week's summary: what was blocked, which devices kept calling home, whether protection ever lapsed |
| `phylode status` | The current configuration and the state of the lists |
| `sudo phylode off` | Return this Mac's DNS to automatic |
| `sudo phylode uninstall` | Turn it off and remove the service; your settings, lists and records stay |

`allow` and `block` undo each other. Changing the lists needs an administrator account.

### If something goes wrong

`phylode diagnostics` prints the versions, states, counts and recent service events, with
network addresses and home folder names removed, so it is safe to paste into a public
[bug report](https://github.com/Strofai/Phylode/issues/new/choose). Don't post the query
records or the output of `phylode status`: they contain the browsing history of everyone
on the network, and your settings.

## How it behaves

- **Keeping the network online comes first.** If the lists cannot be loaded, Phylode
  allows everything and says so in the weekly summary, rather than breaking the internet.
- **Queries leave the network encrypted.** Phylode forwards over DNS-over-TLS or
  DNS-over-HTTPS and never falls back to unencrypted DNS (RFC 8310 Strict Privacy, the
  same default Apple uses). If every upstream server is unreachable, recent answers are
  served from the cache.
- **Your records stay on the Mac.** Queries are recorded locally for 10 days and weekly
  summaries for 12 weeks. Nothing is sent anywhere, and there is no remote interface.
- **Blocks are short-lived.** A blocked domain is remembered by devices for 2 seconds, so
  allowing it works straight away.
- **It never answers REFUSED.** That answer makes devices switch to another DNS server and
  stop being filtered. A device sending too many queries, or one outside the networks
  Phylode serves, gets no answer at all.
- **It protects the network from itself.** Answers that point back into your local network
  are discarded (DNS rebinding protection), names that only exist on your network are
  never sent out, and a tracker hidden behind an innocent-looking alias (CNAME cloaking) is
  blocked too.
- **It looks after itself.** It checks every 10 seconds that it is still answering and
  restarts if not; a failed upstream server is tried again and returns when it recovers.
- **It runs with the least privilege it can.** The service runs as its own account, not
  root. macOS opens port 53 and hands it over.

## Status

Phylode works and runs every day, but there is no release yet: `main` is the current
version. It is about 11,000 lines of Rust with 9 direct dependencies (181 packages in
`Cargo.lock`) and 200 tests. Four entry points — packets from devices, packets from
upstream servers, the blocklist parser and the configuration parser — are fuzzed by a
GitHub Actions workflow.

Planned next: Phylode's own validation of incoming packets (today the DNS library does
it), a macOS sandbox profile, a choice of list strictness, and router guides.

Out of scope for now: routing all traffic through the Mac, protection away from your
network, a graphical interface, and telemetry of any kind.

## Built with

Rust, on macOS. The DNS protocol layer is [hickory-dns](https://github.com/hickory-dns/hickory-dns);
everything else — filtering, caching, records, summaries, configuration and the commands —
is Phylode's own code. The crate forbids `unsafe` code except for the two functions that
receive the network sockets from macOS, and a test fails the build if another appears.

To contribute, read [CONTRIBUTING.md](CONTRIBUTING.md). Writing follows
[docs/WRITING.md](docs/WRITING.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## The name

From the Greek *phylax* (guardian) and *ōidē* (song): a guardian's song.

## License

Phylode is available under either the [MIT](LICENSE-MIT) or the
[Apache 2.0](LICENSE-APACHE) license, at your option, following the convention of the
Rust ecosystem. Unless you explicitly state otherwise, any contribution you submit for
inclusion is licensed the same way, without additional terms or conditions.
