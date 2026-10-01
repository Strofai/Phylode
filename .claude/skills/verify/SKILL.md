---
name: verify
description: How to run Phylode and watch a change at its real surfaces — the DNS socket, the command line, the weekly summary and the install workflow. Use when verifying a change at runtime rather than through tests.
---

# Verifying Phylode at runtime

Phylode is a DNS service, so a change is verified by running it and sending it queries,
not by reading the code or running the test suite.

## Start a scratch instance

```bash
cargo build --release
W=$(mktemp -d)
printf '# Number of entries: 1\nads.example.com\n' > "$W/list.txt"
printf 'listen = [::]:15353\nupstream = "tls 1.1.1.1 cloudflare-dns.com"\nblock_ttl_secs = 2\nblocklist = %s/list.txt\njournal_dir = %s/journal\n' "$W" "$W" > "$W/c.conf"
./target/release/phylode --config "$W/c.conf" > "$W/serve.log" 2>&1 &
```

- Port 53 is bound by launchd in a real install; use a high port. 5353 belongs to mDNSResponder.
- Use the release binary. With the macOS application firewall on, a binary the firewall
  has not allowed gets no incoming traffic except over loopback, and every off-loopback
  test then looks like "no reply". Check `socketfilterfw --listapps`; never change firewall
  settings to get a test through.
- What the service did is in `$W/serve.log` and `$W/journal/events-*.tsv`.

## Drive it

| To see | Do |
|---|---|
| A served device | `dig @::1 -p 15353 example.com` (loopback is always served and never rate-limited), or from the Mac's private address with `dig -b <addr> @<addr>` (served and rate-limited) |
| A source outside the served networks | Query from the Mac's own public IPv6 address with `dig -b <addr> @<addr>`. An `outside-client` event proves the packet arrived |
| Packets `dig` will not send (malformed, response-type) | `printf '<bytes>' \| nc -6 -u -w 2 [-s <addr>] <addr> 15353 \| xxd` |
| TCP connection slots | Hold connections with `sleep 8 \| nc -6 ...`, then count the service's established sockets with `lsof -a -p <pid> -iTCP -sTCP:ESTABLISHED`. Each source may hold three |
| List loading | Replace the list file with `mv` while the service runs; it reloads within seconds. `phylode --config <file> status` and `report` read the same files |
| The daily updater | `bash deploy/update-blocklists.sh <scratch dir>` downloads the real lists; edit a copy of the script to test its limits |
| The installer | It changes system settings: never run it locally. Push to a branch, run `install.yml` (manual trigger) and read the run log |

## Always run the control

A missing reply proves nothing until the same path has produced a reply. For an outside
source, restart with `serve_network = <addr>/128` and confirm a query is answered; for raw
packets, send a well-formed query first.

## Gotchas

- In zsh, an unquoted variable holding several arguments is passed as one argument.
- A pipeline's exit status is the last command's, not the script's.
- `nc` keeps running until its input ends even after the service closes the connection;
  judge TCP from the service's side with `lsof`, not from how long `nc` ran.
