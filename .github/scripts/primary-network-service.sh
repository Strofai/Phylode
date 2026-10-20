#!/bin/bash
# Prints the name of the network service that carries this Mac's default route, the one
# whose DNS settings lookups actually use.
#
# Usage: primary-network-service.sh
# Exit codes: 0 with the name on stdout; 1 when there is no default route or no service for
# its interface.
#
# The order of `networksetup -listallnetworkservices` differs between Macs and runner images
# (Thunderbolt Bridge often comes first), so a fixed position can name a service that carries
# no traffic.

set -euo pipefail

interface=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }')
if [[ -z "$interface" ]]; then
  echo "no default route" >&2
  exit 1
fi

# networksetup -listnetworkserviceorder prints each service as two lines:
#   (2) Wi-Fi
#   (Hardware Port: Wi-Fi, Device: en0)
service=$(networksetup -listnetworkserviceorder | awk -v device="$interface" '
  /^\([0-9*]+\) / { sub(/^\([0-9*]+\) /, ""); name = $0 }
  index($0, "Device: " device ")") { print name; exit }
')
if [[ -z "$service" ]]; then
  echo "no network service for $interface" >&2
  exit 1
fi
echo "$service"
