#!/bin/bash
# End-to-end pounce demo: a real MCP server, a real tool call, and the
# correlation that catches a hidden exfil.
#
# It wraps examples/trojan-fetch-server.mjs (an MCP server whose `fetch` tool
# honestly fetches the URL but ALSO quietly connects to a hardcoded IP), drives
# it with a `fetch(https://example.com)` tool call, and shows pounce:
#   - record the tool call (Phase 1),
#   - capture the connections it caused (Phase 2),
#   - tie the example.com connection back to its DNS lookup, and flag the
#     hardcoded IP as an undeclared destination (Phase 3).
#
# Usage:  ./scripts/demo-e2e.sh        (needs sudo; root, no FDA)
set -u
cd "$(dirname "$0")/.." || exit 1

echo "Building pounce..."
go build -o pounce ./cmd/pounce || exit 1

echo "Caching sudo credentials (enter your password if prompted)..."
sudo -v || { echo "sudo required"; exit 1; }

sudo pkill -f 'pounce daemon' 2>/dev/null
sleep 1
echo "Flushing DNS cache (so the fetch's lookup is captured, not cached)..."
sudo dscacheutil -flushcache 2>/dev/null
sudo killall -HUP mDNSResponder 2>/dev/null

echo "Starting capture daemon..."
sudo ./pounce daemon --print 2>/tmp/pounced.log &
sleep 1.5

cat > /tmp/e2e-drive.jsonl <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://example.com"}}}
JSON

echo "Driving the trojan MCP server: tools/call fetch(https://example.com)..."
( cat /tmp/e2e-drive.jsonl; sleep 5 ) | ./pounce wrap -- node examples/trojan-fetch-server.mjs \
    1>/dev/null 2>/tmp/pwrap.log

sleep 1
sudo pkill -f 'pounce daemon' 2>/dev/null

echo
echo "===== daemon log (/tmp/pounced.log) ====="
cat /tmp/pounced.log
echo
echo "===== TIMELINE + correlation ====="
./pounce view --color=never
