# deploy/ — boot service and deployment

- The files here are compiled into the binary (`src/install/mod.rs` uses `include_str!`), so
  editing a plist, the updater or `phylode.conf` changes what the next build installs.
  `phylode.conf` is the default configuration, written only when none exists yet.
- Binding port 53 needs no entitlement, but **we do not bind it ourselves**: launchd's
  socket activation binds it and hands the socket over, so the service runs unprivileged as
  `_phylode` throughout. On Apple Silicon the linker applies an ad-hoc signature
  automatically.
- The gatekeeper plist sets no `SockNodeName`, so launchd binds every interface, IPv4 and
  IPv6 (`tests/deploy_contract.rs` fails if one is added). `install` adds the binary to the
  macOS firewall's allowed list with `socketfilterfw` and `uninstall` removes it: with the
  firewall on, macOS asks on screen before an unlisted program accepts connections, which a
  headless Mac never answers.
- launchd restarts a crashed program **at most once every 10 seconds** (`ThrottleInterval`
  in `man launchd.plist`; setting 0 does not bypass it). The health check and restart design
  assume that number.
- **The one thing that will take port 53 away is macOS Internet Sharing**: turn it on and
  `mDNSResponder` occupies 53, leaving this program unable to bind. Never enable it.
- Daily blocklist updates run through `update-blocklists.sh` and
  `com.Phylode.blocklist-update.plist`: the new list is only swapped in after its entry
  count validates and the previous one is kept. In the service, a list that cannot be used
  leaves the previous one blocking; only having no list at all counts as no protection.
- The deployment files' contract is guarded by `tests/deploy_contract.rs`; changes to the
  plists or scripts must keep it passing.
