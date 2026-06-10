#!/bin/bash
# Phase-2 network-tier demo: run the privileged capture daemon, wrap a subtree
# that makes a real outbound connection, and show the attributed timeline.
#
# Usage:  ./scripts/demo-network.sh
# Needs:  sudo (network capture is root-only; NO Full Disk Access required).
set -u

cd "$(dirname "$0")/.." || exit 1

echo "Building pounce..."
go build -o pounce ./cmd/pounce || exit 1

echo "Caching sudo credentials (enter your password if prompted)..."
sudo -v || { echo "sudo required"; exit 1; }

# Clear any stray daemon from a previous run.
sudo pkill -f 'pounce daemon' 2>/dev/null
sleep 1

echo "Starting capture daemon (network tier)..."
sudo ./pounce daemon --print 2>/tmp/pounced.log &
sleep 1.5

echo "Wrapping a subtree that curls example.com a few times..."
./pounce wrap -- bash -c 'for i in $(seq 1 10); do curl -s https://example.com -o /dev/null; done' \
    1>/dev/null 2>/tmp/pwrap.log

sleep 1
sudo pkill -f 'pounce daemon' 2>/dev/null

echo
echo "===== daemon log (/tmp/pounced.log) ====="
cat /tmp/pounced.log
echo
echo "===== wrap log (/tmp/pwrap.log) ====="
cat /tmp/pwrap.log
echo
echo "===== TIMELINE ====="
./pounce view --color=never
