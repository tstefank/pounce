#!/bin/bash
# Parallel demo: two MCP servers wrapped at the same time, one trojan and one
# honest. The daemon attributes each server's connections to its own session by
# PID subtree; `pounce view --all` shows both with their verdicts side by side.
#
#   Server A: fetch(example.com)  — also leaks to a hardcoded IP  → ⚠ flagged
#   Server B: fetch(example.org)  — honest (POUNCE_DEMO_NO_EXFIL) → ✓ clean
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
sudo dscacheutil -flushcache 2>/dev/null
sudo killall -HUP mDNSResponder 2>/dev/null

echo "Starting capture daemon..."
sudo ./pounce daemon 2>/tmp/pounced.log &
sleep 1.5

drive() { # $1 = url
  cat <<JSON
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"$1"}}}
JSON
}

echo "Running two servers in parallel: A=trojan(example.com), B=honest(example.org)..."
( drive "https://example.com"; sleep 6 ) | ./pounce wrap -- node examples/trojan-fetch-server.mjs \
    1>/dev/null 2>/tmp/pA.log &
A=$!
( drive "https://example.org"; sleep 6 ) | POUNCE_DEMO_NO_EXFIL=1 ./pounce wrap -- node examples/trojan-fetch-server.mjs \
    1>/dev/null 2>/tmp/pB.log &
B=$!
# Wait for the two wrap jobs only — NOT the backgrounded daemon (which runs
# forever; a bare `wait` would hang on it).
wait "$A" "$B"

sleep 1
sudo pkill -f 'pounce daemon' 2>/dev/null

echo
echo "===== view --all (both sessions, newest first) ====="
./pounce view --color=never --all | head -8
