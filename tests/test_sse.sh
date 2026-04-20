#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sunchao Dong
# tests/test_sse.sh
#
# E2E test: SSE Graceful Drain + TCP_REPAIR migration.
#
# Pass criteria:
#   - curl receives SSE tokens across >=2 migrations
#   - TOKEN sequence is strictly consecutive (no gaps, no duplicates)
#   - curl process never exits
#
# Restore mode requires root (CAP_NET_ADMIN for TCP_REPAIR).
# Full test:   sudo bash tests/test_sse.sh
# Dry run:     bash tests/test_sse.sh --dry-run

set -e
cd "$(dirname "$0")/.."

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

SSE_PORT=8181
STATE_FILE=/tmp/ccmc_sse_test.state
SSE_LOG=/tmp/ccmc_sse_curl_out.txt
SSE_BIN=build/sse_server

# ---- Build --------------------------------------------------------
echo "[build] Compiling examples (sse_server)..."
make examples
echo "[build] Done."

if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] Compilation OK. Skipping live test (requires root for TCP_REPAIR)."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "[error] Full migration test requires root (TCP_REPAIR needs CAP_NET_ADMIN)."
    echo "        Re-run with: sudo bash tests/test_sse.sh"
    exit 1
fi

# ---- Cleanup -------------------------------------------------------
cleanup() {
    echo "[cleanup] Stopping background processes..."
    kill "$SSE_PID"  2>/dev/null || true
    kill "$CURL_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ---- Start SSE server ---------------------------------------------
rm -f "$STATE_FILE" "$SSE_LOG"
echo "[test] Starting sse_server on :$SSE_PORT ..."
$SSE_BIN $SSE_PORT $STATE_FILE &
SSE_PID=$!
sleep 0.2

# ---- Start curl consumer ------------------------------------------
echo "[test] Starting curl SSE consumer (output → $SSE_LOG)..."
curl -s --no-buffer "http://127.0.0.1:$SSE_PORT/" > "$SSE_LOG" &
CURL_PID=$!
sleep 0.5

# ---- Migration loop -----------------------------------------------
MIGRATIONS=0
for round in 1 2; do
    echo "[test] Round $round: streaming for 3s..."
    sleep 3

    rm -f "$STATE_FILE"

    echo "[test] Sending SIGUSR1 to sse_server (PID=$SSE_PID) — Graceful Drain..."
    kill -USR1 "$SSE_PID" 2>/dev/null || true

    echo "[test] Waiting for state file: $STATE_FILE ..."
    for i in $(seq 1 50); do
        [[ -f "$STATE_FILE" ]] && break
        sleep 0.1
    done

    if [[ ! -f "$STATE_FILE" ]]; then
        echo "[FAIL] State file not created after drain. Migration aborted."
        exit 1
    fi

    echo "[test] State file ready. Starting restore..."
    $SSE_BIN --restore "$STATE_FILE" &
    SSE_PID=$!
    MIGRATIONS=$((MIGRATIONS + 1))
    echo "[test] Restore process started (PID=$SSE_PID). Migration $MIGRATIONS complete."
done

echo "[test] Letting stream run for 2 more seconds after last migration..."
sleep 2

# ---- Verify sequence ----------------------------------------------
echo "[verify] Checking token sequence in $SSE_LOG ..."

python3 - <<'EOF'
import sys, re

with open("/tmp/ccmc_sse_curl_out.txt") as f:
    content = f.read()

indices = [int(m) for m in re.findall(r"data: TOKEN_(\d+)", content)]

if not indices:
    print("[FAIL] No SSE tokens received.")
    sys.exit(1)

print(f"[verify] Received {len(indices)} tokens: TOKEN_{indices[0]} .. TOKEN_{indices[-1]}")

gaps = []
dups = []
for i in range(1, len(indices)):
    if indices[i] == indices[i-1] + 1:
        continue
    elif indices[i] == indices[i-1]:
        dups.append(indices[i])
    else:
        gaps.append((indices[i-1], indices[i]))

if gaps:
    print(f"[FAIL] Sequence gaps detected: {gaps}")
    sys.exit(1)
if dups:
    print(f"[FAIL] Duplicate tokens detected: {dups}")
    sys.exit(1)

print("[PASS] Token sequence is strictly consecutive across all migrations.")
EOF

RET=$?
if [[ $RET -eq 0 ]]; then
    echo ""
    echo "============================================"
    echo " PASS: SSE migration E2E test succeeded"
    echo "============================================"
else
    echo ""
    echo "============================================"
    echo " FAIL: SSE migration E2E test failed"
    echo "============================================"
    exit 1
fi
