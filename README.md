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
complete, keeping the previous one. The lists aren't part of this repository; HaGeZi
publishes them under GPL-3.0.

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

Phylode answers devices on the private address ranges that home and office networks use
(10.x, 172.16–31.x, 192.168.x, 100.64–127.x, 169.254.x, and IPv6 `fc00::/7` and
`fe80::/10`), and no one else. If your network uses public addresses, add a
`serve_network` line to `/usr/local/etc/phylode.conf`, then run `sudo phylode install`
again.

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

- `sudo phylode off` sets your Mac's DNS back to automatic. Other devices keep using
  Phylode until you change your router's settings.
- `sudo phylode uninstall` turns Phylode off and removes it. Your settings, lists and
  query journal stay on your Mac.

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
  fill your disk. Nothing is sent anywhere, and there's no remote access.
- **Allowing works right away.** Devices remember a blocked answer for only 2 seconds.
- **Devices aren't pushed to another DNS server.** Phylode never answers REFUSED, which
  would make devices switch servers and stop being filtered. A device sending too many
  lookups, or one outside the networks Phylode serves, gets no answer at all.
- **Your local network stays private.** Answers that point back into your network are
  discarded (DNS rebinding protection), names that exist only on your network are never
  sent out, and trackers hidden behind an innocent-looking alias (CNAME cloaking) are
  blocked too.
- **It looks after itself.** Every 10 seconds, Phylode checks that it's still answering
  and restarts if it isn't. An upstream server that stops responding is tried again and
  returns when it recovers.
- **It runs with as little access as it can.** Phylode runs as its own account, not as
  root. macOS opens port 53 and hands it over.

## Project status

Phylode works and runs every day, but there's no release yet: `main` is the current
version. It's about 11,000 lines of Rust with 9 direct dependencies (181 packages in
`Cargo.lock`) and 224 tests. Four entry points — packets from devices, packets from
upstream servers, the blocklist parser and the configuration parser — are fuzzed by a
GitHub Actions workflow.

Coming next: Phylode's own validation of incoming packets (today the DNS library does
it), a macOS sandbox profile, and a choice of how strict the lists are.

Not planned for now: routing all traffic through the Mac, protection away from your
network, a graphical interface, and telemetry of any kind.

## Built with

Rust, on macOS. The DNS protocol layer is
[hickory-dns](https://github.com/hickory-dns/hickory-dns); filtering, caching, the journal,
summaries, configuration and the commands are Phylode's own code. The crate forbids
`unsafe` code except in the two functions that receive network sockets from macOS, and a
test fails the build if another appears.

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
