#!/bin/bash
# Parallel demo: two MCP servers wrapped at the same time, one trojan and one
# honest. The daemon attributes each server's connections to its own session by
# PID subtree; `pounce view --all` shows both with their verdicts side by side.
#
#   Server A: fetch(host_a)  — also leaks to a hardcoded IP  → ⚠ flagged
#   Server B: fetch(host_b)  — honest (POUNCE_DEMO_NO_EXFIL) → ✓ clean
#
# Hostnames are unique-per-run via sslip.io (<label>.<ip>.sslip.io resolves to
# <ip>), which forces a FRESH DNS lookup each run — so the resolution is captured
# on the wire instead of served from the OS cache (the demo would otherwise hit
# the DNS-cache caveat and mis-flag the legit connections).
#
# Usage:  ./scripts/demo-parallel.sh        (needs sudo; root, no FDA)
set -u
cd "$(dirname "$0")/.." || exit 1

echo "Building pounce..."
go build -o pounce ./cmd/pounce || exit 1

echo "Caching sudo credentials (enter your password if prompted)..."
sudo -v || { echo "sudo required"; exit 1; }

sudo pkill -f 'pounce daemon' 2>/dev/null
sleep 1

ts=$(date +%s%N)
HOST_A="a${ts}.93.184.216.34.sslip.io" # resolves to 93.184.216.34 (example.com's IP)
HOST_B="b${ts}.1.0.0.1.sslip.io"       # resolves to 1.0.0.1

echo "Starting capture daemon..."
sudo ./pounce daemon --print 2>/tmp/pounced.log &
sleep 1.5

drive() { # $1 = url
  cat <<JSON
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"$1"}}}
JSON
}

echo "Running two servers in parallel: A=trojan($HOST_A), B=honest($HOST_B)..."
( drive "https://$HOST_A"; sleep 6 ) | ./pounce wrap -- node examples/trojan-fetch-server.mjs \
    1>/dev/null 2>/tmp/pA.log &
A=$!
( drive "https://$HOST_B"; sleep 6 ) | POUNCE_DEMO_NO_EXFIL=1 ./pounce wrap -- node examples/trojan-fetch-server.mjs \
    1>/dev/null 2>/tmp/pB.log &
B=$!
# Wait for the two wrap jobs only — NOT the backgrounded daemon (it runs forever).
wait "$A" "$B"

sleep 1
sudo pkill -f 'pounce daemon' 2>/dev/null

echo
echo "===== daemon captured (resolves + connects) ====="
grep -E 'resolve|connect' /tmp/pounced.log | head
echo
echo "===== view --all (the two sessions from this run) ====="
./pounce view --all --limit 2
