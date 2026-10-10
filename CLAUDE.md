# Phylode — project rules

A DNS gatekeeper that runs on a Mac that stays on and blocks ads, trackers, malicious
domains and chatty appliances for every device on the network (a home, an office, a
studio, a school), with particular care for Apple devices. Written in Rust.

Documentation, command output and error messages follow `docs/WRITING.md`.

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

1. **Keeping the network online matters more than blocking more.** When the two
   conflict, allow.
2. **Apple's own services always pass, and their encrypted traffic is never inspected.**
   iCloud Private Relay is not interfered with either. The cost: Apple states that Private
   Relay protects Safari browsing, **DNS queries** and unencrypted app traffic, so a device
   with it enabled resolves names entirely outside the gatekeeper.
3. **Data never leaves the network.** The journal is local only; outbound queries are
   encrypted and carry no information about the local network.
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
- **DNS is the only thing listening on the network, and only for the networks it serves.**
  Port 53 answers loopback, the private-range networks this Mac is connected to itself
  (never through a VPN) and any `serve_network` block; everything else gets no response. There is no remote interface: the journal and the lists are read
  and changed on the Mac itself, or over SSH.

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

- **Nothing about a specific network goes in this repository.** No ISP names, device
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
  on a contributor's own machine. `live.yml` drives a release build from 5003 source addresses on
  a throwaway runner whenever the rate limit changes, for behaviour one Mac cannot produce.

## Commits and pushes

The history is read by contributors deciding whether to trust this code, so it should read
like a product's release history, not a work log.

- **One commit per coherent change, not per step.** A few closely related small fixes
  belong together; one substantial fix can stand alone. Coherence decides, not a count —
  never pad a commit to reach a number. Keep unrelated areas apart: a security fix and a
  README rewording do not share a commit.
- **Follow-ups belong to the change that caused them.** A number in the README that a
  change moved (test count, dependency count) goes in that change's commit, not a separate
  one. A breakage found before pushing is fixed inside the commit that introduced it; only
  a breakage found after it reached `main` gets its own `Fix:` commit.
- **What reaches `main` is finished.** Every commit pushed to `main` builds and passes the
  checks relevant to it: code or dependency changes need fmt, clippy, the tests and, when
  `Cargo.toml` or `Cargo.lock` changed, `cargo deny`; documentation-only changes need none of
  those (CI skips them too). Local checkpoints during long work are fine — tidy them into
  coherent commits before pushing.
- **What only CI can check goes through a branch first.** A change to `.github/workflows/`,
  or to anything `install.yml` exercises (`src/install/`, `deploy/`), cannot be verified
  locally: push it to a branch, run the workflow there (`install.yml` has a manual trigger),
  and bring it to `main` only once it passes. A step that has never run is not finished.
- **Summary line:** one of five type prefixes, then an imperative sentence; at most 72
  characters in total, no trailing full stop. The sentence says what changes for the person
  using it rather than which files moved: `Fix: Keep the journal within its retention on a
  Mac that sleeps at night`, not `Fix: Update writer.rs`. The prefixes are capitalised and
  there are exactly five; no others, no scope in parentheses:
  - `Feat:` something the program can do that it could not before
  - `Fix:` behaviour that was wrong, including security fixes
  - `Docs:` documentation only (README, SECURITY.md, CONTRIBUTING.md, `docs/`)
  - `Test:` tests only, no change to what the program does
  - `Chore:` everything else that does not change behaviour: CI workflows, dependencies,
    tooling
- **One trailer, nothing else:** when an AI wrote the change with you, end with
  `Co-Authored-By: Claude <model name> <noreply@anthropic.com>` (for example
  `Claude Opus 5.5`). Never add session links (`Claude-Session:`, `claude.ai/code/…`),
  "Generated with" lines or any other trailer a tool offers — the history is public and
  cannot be cleaned without recreating the repository.
- **Body** (wrapped at 72) reads like release notes, in two parts:
  1. One sentence on what changes for the person using Phylode. A fix that closes a security
     or safety gap starts it with `Impact:` and says what could happen before ("Impact: A
     standard account could replace the installed binary"), with no exploit detail.
  2. A blank line, then one line per change, each starting with `Added`, `Fixed`,
     `Changed`, `Corrected` or `Removed`.

  A correction states what is true, not a reply to an earlier commit: "Corrected the
  README: hickory-dns reads incoming packets, not Phylode's own code", not "The previous
  commit was wrong".

  ```
  Fix: Guard against rebinding through a network's own NAT64 prefix

  Impact: On an IPv6-only network with its own NAT64 prefix, a domain
  could point devices at addresses inside the network.

  - Added nat64_prefix for networks that use their own NAT64 prefix
  - Fixed rebinding protection missing addresses inside that prefix
  - Changed phylode status to list the prefixes in use
  ```
- In English, like the rest of the repository: the people reading `git log` are
  contributors.

## Established facts you can design against

- **`captive.apple.com` and `*.push.apple.com` must never be blocked.** Block the first and
  every Apple device on the network repeatedly mistakes it for a captive portal;
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
- **An app that requires DNSSEC validation (`requiresDNSSECValidation`) reaches nothing,
  not even unsigned domains, unless signatures and proofs reach the device unchanged.**
  Proving a domain is unsigned takes a signed negative answer from its parent zone; Apple
  treats an answer that fails validation as no answer at all (WWDC22 session 10079). The
  install workflow checks this against a 1.1.1.1 control.
