#!/bin/bash
# Live validation of Phase-3 correlation + destination divergence.
#
# Wraps a subtree that does two things:
#   1. curl https://example.com   — a DNS lookup, then a connection to the
#      resolved IP. Correlation should mark it RESOLVED (host: example.com).
#   2. curl https://1.1.1.1        — a connection to a hardcoded IP with no DNS
#      lookup. Correlation should flag it UNDECLARED (unresolved — no DNS) —
#      the hardcoded/exfil-IP signal.
#
# Usage:  ./scripts/demo-correlate.sh        (needs sudo; root, no FDA)
set -u
cd "$(dirname "$0")/.." || exit 1

echo "Building pounce..."
go build -o pounce ./cmd/pounce || exit 1

echo "Caching sudo credentials (enter your password if prompted)..."
sudo -v || { echo "sudo required"; exit 1; }

sudo pkill -f 'pounce daemon' 2>/dev/null
sleep 1

# Flush the DNS cache so the example.com lookup is actually observed on the wire
# (a cache hit would produce no DNS packet — see the caveats in the timeline).
echo "Flushing DNS cache (so the lookup is captured, not served from cache)..."
sudo dscacheutil -flushcache 2>/dev/null
sudo killall -HUP mDNSResponder 2>/dev/null

echo "Starting capture daemon..."
sudo ./pounce daemon --print 2>/tmp/pounced.log &
sleep 1.5

echo "Wrapping: resolve+connect example.com, then connect to hardcoded 1.1.1.1..."
./pounce wrap -- bash -c '
  curl -s -o /dev/null --max-time 6 https://example.com
  sleep 0.3
  curl -sk -o /dev/null --max-time 5 https://1.1.1.1
' 1>/dev/null 2>/tmp/pwrap.log

sleep 1
sudo pkill -f 'pounce daemon' 2>/dev/null

echo
echo "===== daemon log (/tmp/pounced.log) ====="
cat /tmp/pounced.log
echo
echo "===== TIMELINE + correlation ====="
./pounce view --color=never
