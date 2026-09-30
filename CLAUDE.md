# Phylode — project rules

A DNS gatekeeper for Apple households: blocks ads, trackers, malicious domains and chatty
appliances for every device on the network. Rust, running on macOS.

This file is the contract for anyone — human or AI — working on this repository. Read it
before writing code.

## Where each folder's rules live

| Working on | Read |
|---|---|
| `src/` | `src/CLAUDE.md`: the six behaviours that are visible when they go wrong, module layering, encoding rules in types |
| `deploy/` | `deploy/CLAUDE.md`: launchd, port 53, the firewall, daily list updates |
| `fuzz/` | `fuzz/CLAUDE.md`: how to run it, licensing |

## Four product principles, in priority order

Resolve trade-offs by going down this list.

1. **Keeping the household online matters more than blocking more.** When the two
   conflict, allow.
2. **Apple's own services always pass, and their encrypted traffic is never inspected.**
   iCloud Private Relay is not interfered with either. The cost: Apple states that Private
   Relay protects Safari browsing, **DNS queries** and unencrypted app traffic, so a device
   with it enabled resolves names entirely outside the gatekeeper.
3. **Data never leaves the house.** The journal is local only; outbound queries are
   encrypted and carry no information about the home network.
4. **Every block must be explainable** (which list matched), and a wrong block must be
   undoable immediately.

## Architectural boundaries

- **v1 only handles name resolution (DNS).** Routing all traffic through one machine is v2;
  the code leaves room for it but does not implement it.
- **Write anything important into the weekly summary.** The summary is what gets read;
  answers must be derivable from it without trawling the full journal.
- **First-party Rust, not an off-the-shelf server.** Studying how existing projects solve a
  problem is fine; vendoring one in is not.
- **Redundancy goes behind the gatekeeper, not beside it.** When an upstream fails the
  program rotates to the next one itself. Do not recommend configuring a second public
  resolver on the router — DNS has no notion of primary and secondary, clients ask whichever
  they like, and filtering silently stops applying.
- **Never query every upstream in parallel.** That leaks every query to every provider,
  violating principle 3. Pick one.
- **The journal is written to disk in batches, never to a RAM disk.** A reboot would empty
  it, breaking the promise that detail is retained for 10 days.
- **No inbound network access.** Reading the journal requires being on the home network
  with a registered key.

## Before touching dependencies

Run this once before starting work and put the result in the first paragraph of your report
(say "no known vulnerabilities" explicitly when there are none):

1. GitHub Dependabot alerts. `gh` has its connection reset on some networks; use curl
   instead:
   `curl -s -H "Authorization: Bearer $(gh auth token)" "https://api.github.com/repos/Strofai/Phylode/dependabot/alerts?state=open"`.
   An empty array means none.
2. `cargo deny check` (rules in `deny.toml`; all four lines must say ok). **Dependabot
   returning 0 does not mean you are clear** — run both.
3. If there is a vulnerability: upgrade, run the full test suite, exercise the binary once,
   then commit. Update the README if the dependency count or `Cargo.lock` package count
   changed. If there is merely a newer version and no vulnerability, list it rather than
   upgrading — an upgrade pulls in unreviewed code.

## Before writing to the repository

- **Nothing about a specific home network goes in this repository.** No ISP names, device
  models, network ranges or keys — not in code, not in comments, not in commit messages.
  Use RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) and RFC 1918 ranges in tests.
- Run `cargo deny check` whenever `Cargo.toml` or `Cargo.lock` changes; all four must say
  ok before committing. A new dependency under a license outside `deny.toml`'s list needs a
  decision, not a silent addition.
- Command output, weekly summaries and error messages are product surface. Write them in
  plain language.
- CI (`.github/workflows/ci.yml`) runs `cargo fmt --check`, clippy, the tests and
  `cargo deny` on every push and pull request; run the same locally before pushing.
  `install.yml` runs `phylode install`, `on`, `off` and `uninstall` for real on a throwaway
  macOS runner whenever `src/` or `deploy/` changes — that is where installation gets verified, not
  on a contributor's own machine.

## Commits and pushes

The history is read by contributors deciding whether to trust this code, so it should read
like a product's release history, not a work log. Modelled on how Apple's open-source
projects (`apple/swift-nio`, `apple/container`) and Anthropic's (`anthropics/claude-code`)
write theirs.

- **Batch the work.** One commit per coherent round of work — typically two or three related
  small fixes together — not one commit per fix. Push once that round is done and passes
  fmt, clippy, tests and `cargo deny`. Keep unrelated areas apart: a security fix and a
  README rewording do not share a commit.
- **Never commit a half-finished state.** Every commit on `main` builds and passes the tests.
- **Summary line:** imperative, at most 72 characters, saying what changes for the person
  using it rather than which files moved: `Keep the journal within its retention on a Mac
  that sleeps at night`, not `Update writer.rs`. No type prefixes, no trailing full stop.
- **Body** (wrapped at 72): why the change was needed, what changed, and what is now true —
  the same three parts as swift-nio's Motivation / Modifications / Result. For a batch, one
  short paragraph or bullet per fix.
- **Security fixes** are described the way Apple's security notes are: the impact in one
  line ("A standard account could replace the installed binary"), then how it was addressed
  ("Install now refuses folders that account can write"). No exploit detail.
- In English, like the rest of the repository: the people reading `git log` are
  contributors.

## Established facts you can design against

- **`captive.apple.com` and `*.push.apple.com` must never be blocked.** Block the first and
  every Apple device in the house repeatedly mistakes the network for a captive portal;
  block or proxy the second and push notifications and iMessage stop working.
- HTTPS content inspection of Apple services makes the connection fail outright (per
  Apple's own documentation).
- **IPv6, where present, bypasses IPv4-only filtering.** Apple supports RA RDNSS (RFC 8106),
  IPv6 resolvers can be advertised independently of IPv4 DHCP, and hosts keep the DNS
  configuration from every source — advertising your own RDNSS to override it is a race you
  cannot reliably win.
- Apple's managed DNS profile (`com.apple.dnsSettings.managed`) accepts encrypted resolvers
  only, and the official schema covers neither tvOS nor watchOS, so Apple TV and HomePod
  cannot be covered that way.
- Apple devices default to a stable private Wi-Fi address on an encrypted network, which
  makes a usable per-device identifier.
