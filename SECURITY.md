# Security policy

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub instead:
**Security** tab → **Report a vulnerability**
(<https://github.com/Strofai/Phylode/security/advisories/new>).

Include what you ran, what you expected, what happened, and the commit you tested. A
crashing input from the fuzzers is ideal.

This is a small project maintained in spare time. Expect an acknowledgement within a week;
fixes land on `main`, and the advisory is published once a fix is available.

## Supported versions

There are no releases yet. Only the latest `main` is supported.

## In scope

- A packet from a device on the network, or a response from an upstream resolver, that
  crashes the service, hangs it, or exhausts its memory.
- Anything that makes `captive.apple.com`, `*.push.apple.com` or the other hard-coded Apple
  hosts fail to resolve.
- A way past the DNS rebinding protection or the per-device rate limit.
- Query data leaving the machine other than the encrypted query to the chosen upstream.
- A way for an unprivileged local user to change the allowlist, blocklist or configuration.

## Known limitations (not vulnerabilities)

- **DNS filtering only sees DNS.** A device that connects to an IP address directly, or
  resolves names through its own encrypted resolver, is not filtered.
- **iCloud Private Relay is deliberately left alone.** Apple states it protects Safari
  browsing, DNS queries and unencrypted app traffic, so a device with it enabled resolves
  names entirely outside the gatekeeper.
- **IPv6 can bypass IPv4-only setups.** If the router also advertises its own IPv6
  resolvers, devices may use them instead.
