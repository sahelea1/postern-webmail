#!/bin/sh
# Runs the end-to-end suite against local test servers and cleans up after itself.
#
#   tests/e2e.sh imap [binary]    real IMAP server (pymap) + SMTP server with sign-in
#   tests/e2e.sh jmap [binary]    tests/jmap_mock.py
#
# Needs the packages in tests/requirements.txt and a built binary
# (default: target/release/postern). Uses ports 8080, 8081 and 1143/1025 or 8090.
set -eu

MODE="${1:-imap}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${2:-$ROOT/target/release/postern}"
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

mkdir "$WORK/data"
case "$MODE" in
imap)
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
    python3 "$ROOT/tests/smtp_sink.py" 1025 1143 demouser demopass "$WORK/sent.log" > "$WORK/smtp.log" 2>&1 &
    PIDS="$PIDS $!"
    wait_port 1143
    wait_port 1025
    EXTRA="--imap 127.0.0.1:1143:demouser:demopass --trash-name"
    TRASH="Deleted Items"   # pymap's demo Trash folder is read-only
    ;;
jmap)
    cat > "$WORK/data/servers.toml" <<'EOF'
[[server]]
id = "main"
name = "Test"
domains = ["example.com"]
protocol = "jmap"
jmap_url = "http://127.0.0.1:8090"
EOF
    python3 "$ROOT/tests/jmap_mock.py" 8090 demouser@example.com demopass "$WORK/sent.log" > "$WORK/jmap.log" 2>&1 &
    PIDS="$PIDS $!"
    wait_port 8090
    EXTRA=""
    TRASH=""
    ;;
*)
    echo "usage: $0 imap|jmap [binary]" >&2
    exit 2
    ;;
esac

export POSTERN_DATA_DIR="$WORK/data" POSTERN_LISTEN=127.0.0.1:8080 \
    POSTERN_ADMIN_LISTEN=127.0.0.1:8081 POSTERN_INSECURE_HTTP=1
"$BIN" run > "$WORK/postern.log" 2>&1 &
PIDS="$PIDS $!"
wait_port 8080

# shellcheck disable=SC2086
if ! python3 "$ROOT/tests/e2e.py" --base http://127.0.0.1:8080 \
    --email demouser@example.com --password demopass \
    --smtp-log "$WORK/sent.log" --admin http://127.0.0.1:8081 \
    --binary "$BIN" --data-dir "$WORK/data" $EXTRA ${TRASH:+"$TRASH"} > "$WORK/e2e.out" 2>&1; then
    grep -v '^ok ' "$WORK/e2e.out" || true
    echo "---- gateway log ----"
    tail -n 40 "$WORK/postern.log"
    exit 1
fi
tail -n 1 "$WORK/e2e.out"
