# deploy/ — boot service and deployment

- Binding port 53 needs no entitlement, but **we do not bind it ourselves**: launchd's
  socket activation binds it and hands the socket over, so the service runs unprivileged as
  `_phylode` throughout. On Apple Silicon the linker applies an ad-hoc signature
  automatically.
- launchd restarts a crashed program **at most once every 10 seconds** (`ThrottleInterval`
  in `man launchd.plist`; setting 0 does not bypass it). The health check and restart design
  assume that number.
- **The one thing that will take port 53 away is macOS Internet Sharing**: turn it on and
  `mDNSResponder` occupies 53, leaving this program unable to bind. Never enable it.
- Daily blocklist updates run through `update-blocklists.sh` and
  `com.Phylode.blocklist-update.plist`: the new list is only swapped in after its entry
  count validates, the previous one is kept, and an empty list counts as no protection.
- The deployment files' contract is guarded by `tests/deploy_contract.rs`; changes to the
  plists or scripts must keep it passing.
