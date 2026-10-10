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

Only the latest [release](https://github.com/Strofai/Phylode/releases) and the latest
`main` are supported. Fixes land on `main` first and ship in the next release.

## In scope

- A packet from a device on the network, or a response from an upstream server, that
  crashes the service, hangs it, or exhausts its memory.
- Anything that makes `captive.apple.com`, `*.push.apple.com` or the other hard-coded Apple
  hosts fail to resolve.
- A way past the DNS rebinding protection or the per-address rate limit.
- A way to get any answer from outside the networks the service serves, which would make it
  usable in reflection attacks.
- Query data leaving the machine other than the encrypted query to the chosen upstream.
- A way for an unprivileged local user to change the allowlist, blocklist or configuration.

## Known limitations (not vulnerabilities)

- **DNS filtering only sees DNS.** A device that connects to an IP address directly, or
  looks up names through its own encrypted DNS server, is not filtered.
- **iCloud Private Relay is deliberately left alone.** Apple states it protects Safari
  browsing, DNS queries and unencrypted app traffic, so a device with it enabled resolves
  names entirely outside Phylode.
- **IPv6 can bypass IPv4-only setups.** If the router also advertises its own IPv6
  DNS servers, devices may use them instead and skip filtering.
- **The rate limit counts each source address.** A device that changes its IPv6 address,
  or one that sends packets with forged source addresses, gets a separate allowance for
  each address it uses. The reverse also holds: a device on the network that forges
  another's address can use up that device's allowance, leaving it unanswered for the
  rest of the minute. Apple's hard-coded hosts have an allowance of their own, so they
  keep resolving.
- **DNSSEC is checked by the upstream and passed on.** When the upstream reports that an
  answer's signature did not validate, Phylode refuses it, as the upstream does, and names
  the domain in the weekly summary; `phylode allow` lets a domain through anyway. A device
  that asks for signatures gets them, and the upstream's proof that a name doesn't exist,
  unchanged, so it can check them itself. Answers Phylode writes itself — blocked domains,
  names that exist only on the network — are unsigned, so a device that requires signatures
  can't use them. Phylode does not validate signatures itself.
- **Anyone on a served network can use it.** On a shared network, such as a café or a
  hotel, that includes strangers, and their queries are recorded in the query journal.
  Phylode is meant for a Mac that stays on one network; on a laptop that travels, run
  `sudo phylode uninstall` before joining networks you don't control. Only networks
  the Mac is connected to itself are served, never one reached through a VPN; a Mac
  connected straight to a provider's network, as with a 100.64.0.0/10 address handed out by
  the provider, would also answer the provider's other customers on that network.
- **Packets are read by hickory-dns.** Turning the bytes of a query or an upstream
  response into names and records — bounds checks, name compression, matching a response
  to its query — is done by the DNS library, which X41 D-Sec audited in 2024. Phylode
  receives the packets itself, drops any the library can't read without replying to them,
  and fuzzes both paths, but it doesn't parse them with code of its own.
- **The blocklists are trusted as downloaded.** They come over HTTPS from HaGeZi's
  published mirrors and are checked for size, encoding and entry count, but not against a
  signature, since none is published. A download with under half the entries of the list
  in use is set aside rather than used. Someone who took over the source could still block
  any domain except Apple's hard-coded hosts, or remove entries a little at a time; a list
  can only block, never redirect.
