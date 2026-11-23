#!/bin/sh
# S/MIME interoperability against OpenSSL, with its own test servers.
#
#   tests/smime.sh [binary]
#
# Needs openssl, the packages in tests/requirements.txt and a built binary
# (default: target/release/postern). Uses ports 8080, 1143 and 1025.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/target/release/postern}"
WORK="$(mktemp -d)"
PIDS=""

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

wait_port() {
    i=0
    while ! python3 -c "import socket,sys; socket.create_connection(('127.0.0.1', int(sys.argv[1])), 1)" "$1" 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 60 ]; then echo "port $1 did not open" >&2; exit 1; fi
        sleep 0.5
    done
}

mkdir "$WORK/data" "$WORK/sink"
python3 "$ROOT/tests/smime_e2e.py" pki "$WORK/pki" > /dev/null
cat > "$WORK/data/servers.toml" <<'EOF'
[[server]]
id = "main"
name = "Test"
domains = ["example.com"]
protocol = "imap"
imap_host = "127.0.0.1"
imap_port = 1143
imap_security = "none"
smtp_host = "127.0.0.1"
smtp_port = 1025
smtp_security = "none"
username = "local"
EOF
pymap --port 1143 dict --demo-data > "$WORK/imap.log" 2>&1 &
PIDS="$PIDS $!"
SINK_DIR="$WORK/sink" python3 "$ROOT/tests/smtp_sink.py" 1025 1143 demouser demopass "$WORK/sent.log" > "$WORK/smtp.log" 2>&1 &
PIDS="$PIDS $!"
wait_port 1143
wait_port 1025

POSTERN_DATA_DIR="$WORK/data" POSTERN_LISTEN=127.0.0.1:8080 POSTERN_ADMIN_LISTEN=off \
POSTERN_INSECURE_HTTP=1 POSTERN_SMIME_CA_FILE="$WORK/pki/ca.crt" \
    "$BIN" run > "$WORK/postern.log" 2>&1 &
PIDS="$PIDS $!"
wait_port 8080

if ! python3 "$ROOT/tests/smime_e2e.py" run http://127.0.0.1:8080 "$WORK/pki" "$WORK/sink" 1143 > "$WORK/out" 2>&1; then
    grep -v '^ok ' "$WORK/out" || true
    echo "---- gateway log ----"
    tail -n 40 "$WORK/postern.log"
    exit 1
fi
if [ -n "${SMIME_VERBOSE:-}" ]; then cat "$WORK/out"; else tail -n 1 "$WORK/out"; fi
