**English** · [繁體中文](README.zh-TW.md)

# Phylode

**Every device on your network, protected by one Mac.**

Phylode blocks ads, trackers and malicious websites for phones, computers, TVs and
everything else on your network. There's nothing to install on them, and Apple services
and iCloud Private Relay keep working as usual.

It suits any network with a Mac that stays on — at home, in an office, a studio or a
school.

## What Phylode blocks

Phylode uses two lists maintained by [HaGeZi](https://github.com/hagezi/dns-blocklists),
the combination HaGeZi recommends:

- **Multi PRO** blocks ads, trackers, analytics, telemetry from apps and appliances, and
  common scams, phishing and malware.
- **Threat Intelligence Feeds (Medium)** blocks domains known for malware, phishing,
  scams and cryptojacking, drawn from security feeds.

Together they cover about one million domains once duplicates are removed. Your Mac
downloads both every day at 04:17 and switches to a new copy only after checking that it's
complete, keeping the previous one. A new copy with under half the entries of the one in
use is set aside instead, in case the source was emptied or tampered with; the weekly
summary notes it and `phylode status` explains how to use it. The lists aren't part of
this repository; HaGeZi publishes them under GPL-3.0.

To block less or more, change `protection` in `/usr/local/etc/phylode.conf`, then run
`sudo phylode install` again:

| Setting | First list | Suits |
|---|---|---|
| `relaxed` | Multi NORMAL | Networks where nobody will unblock a site |
| `standard` (default) | Multi PRO | Most networks |
| `strict` | Multi PRO++ | Networks where someone will run `phylode allow` to fix the odd wrong block |

Every level uses the same threat intelligence feed. HaGeZi's strictest tier, Ultimate,
isn't offered: HaGeZi says it stops some apps working.

Some services are never blocked, whatever a list says: `captive.apple.com`, which Apple
devices use to find Wi-Fi sign-in pages, and Apple's push notification and Private Relay
services.

## Install Phylode

Before you begin, you need:

- A Mac that stays on. Phylode is tested on macOS 26 and 27 on Apple silicon.
- The Rust toolchain, from [rustup.rs](https://rustup.rs).

Then, in Terminal:

```bash
git clone https://github.com/Strofai/Phylode.git
cd Phylode
cargo build --release
sudo ./target/release/phylode install
sudo phylode on
```

`install` sets up Phylode to start with your Mac, downloads the lists and finishes once
Phylode is answering. `on` makes your Mac use Phylode too, then shows your Mac's address on
the network. You'll need that address in the next step.

If a folder Phylode installs into, such as `/usr/local/bin`, can be changed by a standard
account, installation stops without changing anything.

Every change to the program is tested by installing Phylode on a fresh Mac in CI, turning
it on and off, and uninstalling it.

## Set up your network

For Phylode to protect every device, they need to look up websites through your Mac
instead of your router or internet provider.

1. In your router's settings, reserve a fixed address for your Mac, so its address doesn't
   change when it restarts.
2. In the router's DHCP settings, set the DNS server to your Mac's address and remove any
   other DNS servers. Devices use the new setting the next time they connect.
3. If your network uses IPv6, check whether the router also advertises its own IPv6 DNS
   servers. Devices that use those aren't filtered, so turn that option off or point it
   at your Mac — which of your Mac's IPv6 addresses to use matters, and the guide below
   explains it.

The [network setup guide](docs/network-setup.md) walks through each step, how to check
that it's working, and how to set up devices one by one if you can't change your
router's settings.

Phylode answers devices on the networks your Mac is connected to itself, over Ethernet,
Wi-Fi or a bridge, when they use the private addresses home and office networks use (10.x,
172.16–31.x, 192.168.x, 169.254.x, the 100.64–127.x some routers hand out, and IPv6
`fc00::/7` and `fe80::/10`), and no one else. A VPN such as Tailscale is not one of those
networks, so its peers are not answered; nor is another private network behind a router,
such as a separate guest network or an office VLAN. To serve any of those, or a network on
public addresses, add a `serve_network` line to `/usr/local/etc/phylode.conf`, then run
`sudo phylode install` again.

## Allow or block a website

If something you need is blocked, allow it:

```bash
phylode allow example.com
```

To block a website that isn't on the lists:

```bash
phylode block example.com
```

The change reaches every device within a few seconds, and each command undoes the other.
You need an administrator account to change the lists.

## See what Phylode is doing

- `phylode report` shows this week's summary: what was blocked, which devices kept
  contacting the same servers, and whether protection ever lapsed.
- `phylode status` shows the current settings and the state of the lists.

## Turn Phylode off or uninstall it

- `sudo phylode off` puts your Mac's DNS back to what it was before `phylode on`. Other
  devices keep using Phylode until you change your router's settings.
- `sudo phylode uninstall` turns Phylode off and removes it. Your settings, lists and
  query journal stay on your Mac.
- `sudo phylode forget` deletes the query journal and the saved weekly summaries now,
  while Phylode keeps running.

## Update Phylode

Each version is listed on the [Releases](https://github.com/Strofai/Phylode/releases) page
with what changed. To hear about new ones, choose Watch > Custom > Releases at the top of
this page. Phylode never checks for updates itself, so nothing about your network leaves it.

To update, in the folder you installed from:

```bash
git pull
cargo build --release
sudo ./target/release/phylode install
```

`install` replaces the running copy without a gap: Phylode keeps answering throughout, and
your settings, lists and query journal stay as they are. `phylode --version` shows which
version is installed.

## If something goes wrong

Run `phylode diagnostics`. It shows versions, states, counts and recent events, with
network addresses and home folder names removed, so you can paste it into a public
[bug report](https://github.com/Strofai/Phylode/issues/new/choose).

Don't post your query journal or the output of `phylode status`. They contain the
browsing history of everyone on your network, and your settings.

## How Phylode protects your network

- **Your network stays online.** If a list update can't be used, Phylode keeps blocking
  with the previous list. If no list can be loaded at all, it allows everything and notes it
  in the weekly summary, rather than cutting off the internet.
- **Lookups leave your network encrypted.** Phylode uses DNS-over-TLS or DNS-over-HTTPS
  and never falls back to unencrypted DNS (RFC 8310 Strict Privacy, the same default Apple
  uses). If every upstream server is unreachable, it answers from recent results.
- **Your query journal stays on your Mac.** Lookups are kept for 10 days and weekly
  summaries for 12 weeks, and a day's lookups take at most 200 MB, so the journal can't
  fill your disk. Every administrator account on the Mac can read it; standard accounts
  can't. Nothing is sent anywhere, and there's no remote access. By default each lookup
  records the device, the domain and the time (`journal = All`). To keep less, set
  `journal = Domains` (no device) or `journal = Zero` (only how many lookups were allowed and
  blocked each day) in `/usr/local/etc/phylode.conf` and run `sudo phylode install`. The
  weekly summary says "cannot tell" for whatever it can no longer see. A change applies from
  then on; what is already kept stays until it expires, and `phylode status` says until when.
- **Apps that check signatures keep working.** Some apps ask the device to verify each
  answer's DNSSEC signature (Apple's `requiresDNSSECValidation`). Phylode passes the
  signatures, and the proof that a name doesn't exist, on unchanged to any device that asks
  for them, so these apps connect as they would on any other network. Blocked domains get
  an unsigned answer, so such an app can't reach them either.
- **Allowing works right away.** Devices remember a blocked answer for only 2 seconds.
- **Devices aren't pushed to another DNS server.** Phylode never answers REFUSED, which
  would make devices switch servers and stop being filtered. A device sending too many
  lookups, or one outside the networks Phylode serves, gets no answer at all.
- **Your local network stays private.** Answers that point back into your network are
  discarded (DNS rebinding protection), names that exist only on your network are never
  sent out, and trackers hidden behind an innocent-looking alias (CNAME cloaking, or an
  HTTPS record pointing elsewhere) are blocked too. "Your network" means the private
  ranges, any `serve_network`, and every network your Mac is connected to, as Apple defines
  a local network. If a name of your own points at a device at home, such as a
  remote-access name for a NAS, the weekly summary lists it; add an `internal_domain`
  line for it to `/usr/local/etc/phylode.conf`. On an IPv6-only network that reaches IPv4
  through NAT64, Phylode recognises the standard prefix `64:ff9b::/96` by itself; if your
  network uses another, add it as a `nat64_prefix` line, such as
  `nat64_prefix = 64:ff9b:1::/48`, and run `sudo phylode install` again.
- **It looks after itself.** Every 10 seconds, Phylode checks that it's still answering
  and restarts if it isn't. An upstream server that stops responding is tried again and
  returns when it recovers.
- **It runs with as little access as it can.** Phylode runs as its own account, not as
  root. macOS opens port 53 and hands it over.

## Project status

The current version is 1.0.0; `main` is tested on every change and may be ahead of it.
It's about 12,000 lines of Rust with 11 direct dependencies (181 packages in `Cargo.lock`)
and 288 tests. Four entry points — packets from devices, packets from upstream servers,
the blocklist parser and the configuration parser — are fuzzed by a GitHub Actions
workflow.

Coming next: installing with Homebrew, without the Rust toolchain.

Not planned for now: routing all traffic through the Mac, protection away from your
network, a graphical interface, and telemetry of any kind.

## Built with

Rust, on macOS. The DNS protocol layer is
[hickory-dns](https://github.com/hickory-dns/hickory-dns); filtering, caching, the journal,
summaries, configuration and the commands are Phylode's own code. The crate forbids
`unsafe` code except in two places: the two functions that receive network sockets from
macOS, and two lines that read which networks the Mac is on from Apple's
SystemConfiguration framework. A test fails the build if another appears.

To contribute, read [CONTRIBUTING.md](CONTRIBUTING.md); writing follows
[docs/WRITING.md](docs/WRITING.md). To report a security issue, see
[SECURITY.md](SECURITY.md).

## The name

From the Greek *phylax* (guardian) and *ōidē* (song): a guardian's song.

## License

Phylode is available under the [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) license,
at your option, following the convention of the Rust ecosystem. Unless you explicitly
state otherwise, any contribution you submit for inclusion is licensed the same way,
without additional terms or conditions.
