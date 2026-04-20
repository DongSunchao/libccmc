#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sunchao Dong
# tests/test_tcp_repair.sh
#
# CCMC live TCP_REPAIR validation.
#
# Validates on a real loopback TCP connection:
#   ccmc_tiocoutq_poll → ccmc_freeze_and_extract → ccmc_socket_restore
#
# No GPU, no vLLM required. Root required (TCP_REPAIR needs CAP_NET_ADMIN).
#
# Usage:
#   sudo bash tests/test_tcp_repair.sh
#
# Three assertions:
#   ① TIOCOUTQ == 0   send buffer fully drained before freeze
#   ② send_seq != 0   real kernel sequence number captured (not mock-zero)
#   ③ no RST          post-restore write reaches the server

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_PORT=19090

echo "════════════════════════════════════════════════════════════"
echo " CCMC: live TCP_REPAIR validation"
echo " Topology: [echo server :${SERVER_PORT}] ←— loopback —→ [client fd] → freeze → restore"
echo "════════════════════════════════════════════════════════════"
echo ""

# ── root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "[error] TCP_REPAIR requires root (CAP_NET_ADMIN)"
    echo "  Run with: sudo bash tests/test_tcp_repair.sh"
    exit 1
fi

# ── build libccmc.so ──────────────────────────────────────────────────
echo "[setup] Building libccmc.so..."
cd "$REPO_DIR"
make libccmc.so -s 2>&1
LIB_PATH="$REPO_DIR/build/libccmc.so"

# verify exported symbols
for sym in ccmc_tiocoutq ccmc_tiocoutq_poll ccmc_freeze_and_extract ccmc_socket_restore; do
    if ! nm -D "$LIB_PATH" | grep -q " T $sym"; then
        echo "[error] Symbol '$sym' not found in $LIB_PATH"
        exit 1
    fi
done
echo "  ✓ All symbols exported"
echo ""

cd "$REPO_DIR"

# ── main test (Python ctypes) ─────────────────────────────────────────
echo "[test] Running CCMC live TCP_REPAIR test..."
echo ""

python3 - "$LIB_PATH" "$SERVER_PORT" <<'PYEOF'
import ctypes, socket, threading, time, os, sys, struct, errno

lib_path    = sys.argv[1]
server_port = int(sys.argv[2])

# ── load libccmc.so ──────────────────────────────────────────────────
lib = ctypes.CDLL(lib_path)
lib.ccmc_tiocoutq.restype        = ctypes.c_int
lib.ccmc_tiocoutq.argtypes       = [ctypes.c_int]
lib.ccmc_tiocoutq_poll.restype   = ctypes.c_int
lib.ccmc_tiocoutq_poll.argtypes  = [ctypes.c_int, ctypes.c_int]
lib.ccmc_freeze_and_extract.restype  = ctypes.c_int
lib.ccmc_freeze_and_extract.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
lib.ccmc_socket_restore.restype  = ctypes.c_int
lib.ccmc_socket_restore.argtypes = [ctypes.c_void_p, ctypes.c_int]

# ── ccmc_state ctypes mirror (include/ccmc.h, 80 bytes) ─────────────
class SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_uint16),
        ("sin_port",   ctypes.c_uint16),    # network byte order
        ("sin_addr",   ctypes.c_uint32),    # network byte order
        ("sin_zero",   ctypes.c_uint8 * 8),
    ]  # 16 bytes

class TcpRepairWindow(ctypes.Structure):
    _fields_ = [
        ("snd_wl1",    ctypes.c_uint32),
        ("snd_wnd",    ctypes.c_uint32),
        ("max_window", ctypes.c_uint32),
        ("rcv_wnd",    ctypes.c_uint32),
        ("rcv_wup",    ctypes.c_uint32),
    ]  # 20 bytes

class CcmcTsState(ctypes.Structure):
    _fields_ = [
        ("ts_enabled", ctypes.c_uint8),
        ("_pad",       ctypes.c_uint8 * 3),
        ("tsval",      ctypes.c_uint32),
        ("tsecr",      ctypes.c_uint32),
    ]  # 12 bytes

class CcmcState(ctypes.Structure):
    _fields_ = [
        ("local_addr",    SockaddrIn),         # offset  0, 16 B
        ("remote_addr",   SockaddrIn),         # offset 16, 16 B
        ("send_seq",      ctypes.c_uint32),    # offset 32,  4 B
        ("recv_seq",      ctypes.c_uint32),    # offset 36,  4 B
        ("repair_window", TcpRepairWindow),    # offset 40, 20 B
        ("mss",           ctypes.c_int),       # offset 60,  4 B
        ("ts",            CcmcTsState),        # offset 64, 12 B
        ("token_index",   ctypes.c_int),       # offset 76,  4 B
    ]  # 80 bytes total

assert ctypes.sizeof(CcmcState) == 80, \
    f"Struct size mismatch: {ctypes.sizeof(CcmcState)} != 80"

# ── helpers ──────────────────────────────────────────────────────────
def ip_from_uint32(n):
    return socket.inet_ntoa(struct.pack(">I", socket.ntohl(n)))

def port_from_uint16(n):
    return socket.ntohs(n)

PASS = True
RESULTS = []

def check(name, cond, detail=""):
    global PASS
    if cond:
        print(f"  ✓ [{name}] {detail}")
        RESULTS.append(f"[OK]   {name}")
    else:
        print(f"  ✗ [{name}] FAILED — {detail}")
        RESULTS.append(f"[FAIL] {name}")
        PASS = False

# ── Step 1: echo server ──────────────────────────────────────────────
print("── Step 1: Echo Server ────────────────────────────────────────")
received_chunks = []
server_ready = threading.Event()
server_done  = threading.Event()

def echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", server_port))
    srv.listen(5)
    srv.settimeout(10.0)
    server_ready.set()
    try:
        conn, _ = srv.accept()
        conn.settimeout(5.0)
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break
                received_chunks.append(data)
            except socket.timeout:
                break
        conn.close()
    except Exception as e:
        received_chunks.append(f"SERVER_ERR:{e}".encode())
    finally:
        srv.close()
        server_done.set()

t = threading.Thread(target=echo_server, daemon=True)
t.start()
server_ready.wait(timeout=3.0)
print(f"  Server listening on 127.0.0.1:{server_port}")

# ── Step 2: connect + send ───────────────────────────────────────────
print("")
print("── Step 2: Connect + Send ─────────────────────────────────────")
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client.connect(("127.0.0.1", server_port))
fd = client.fileno()

payload = b"BEFORE_FREEZE_" * 357  # ~5000 bytes
client.sendall(payload)
print(f"  Sent {len(payload)} bytes  fd={fd}  local={client.getsockname()}")

# ── Step 3: TIOCOUTQ flush barrier (assertion ①) ────────────────────
print("")
print("── Step 3: TIOCOUTQ flush barrier (assertion ①) ───────────────")
time.sleep(0.001)
ret = lib.ccmc_tiocoutq_poll(fd, 1000)
tiocoutq = lib.ccmc_tiocoutq(fd)

check("TIOCOUTQ==0",
      tiocoutq == 0,
      f"TIOCOUTQ={tiocoutq} bytes (poll_ret={ret})")

if tiocoutq != 0:
    print("  [abort] Send buffer not empty — cannot freeze safely")
    sys.exit(1)

# ── Step 4: ccmc_freeze_and_extract (assertion ②) ────────────────────
print("")
print("── Step 4: ccmc_freeze_and_extract (assertion ②) ──────────────")
state = CcmcState()
ret = lib.ccmc_freeze_and_extract(fd, ctypes.byref(state), ctypes.sizeof(state))

check("freeze_ret==0",
      ret == 0,
      f"ret={ret}" + (f"  errno={ctypes.get_errno()}" if ret != 0 else ""))

local_ip    = ip_from_uint32(state.local_addr.sin_addr)
local_port  = port_from_uint16(state.local_addr.sin_port)
remote_ip   = ip_from_uint32(state.remote_addr.sin_addr)
remote_port = port_from_uint16(state.remote_addr.sin_port)

print(f"  Captured ccmc_state (80 bytes):")
print(f"    local       = {local_ip}:{local_port}")
print(f"    remote      = {remote_ip}:{remote_port}")
print(f"    send_seq    = {state.send_seq}")
print(f"    recv_seq    = {state.recv_seq}")
print(f"    snd_wnd     = {state.repair_window.snd_wnd}")
print(f"    rcv_wnd     = {state.repair_window.rcv_wnd}")
print(f"    mss         = {state.mss}")
ts = state.ts
print(f"    ts_enabled  = {ts.ts_enabled}  tsval={ts.tsval}")
print(f"    token_index = {state.token_index}")

check("send_seq!=0",
      state.send_seq != 0,
      f"send_seq={state.send_seq} (non-zero = real kernel seq)")

check("remote_addr",
      remote_ip == "127.0.0.1" and remote_port == server_port,
      f"remote={remote_ip}:{remote_port}")

# ── Step 5: close old fd (REPAIR mode: no RST/FIN sent) ──────────────
print("")
print("── Step 5: close(old_fd) in TCP_REPAIR mode ───────────────────")
client.detach()
os.close(fd)
print(f"  fd={fd} closed silently (no RST to peer)")
time.sleep(0.002)

# ── Step 6: ccmc_socket_restore ──────────────────────────────────────
print("")
print("── Step 6: ccmc_socket_restore ────────────────────────────────")
new_fd = lib.ccmc_socket_restore(ctypes.byref(state), ctypes.sizeof(state))

check("restore_ret>=0",
      new_fd >= 0,
      f"new_fd={new_fd}" + (f"  errno={ctypes.get_errno()}" if new_fd < 0 else ""))

if new_fd < 0:
    err = ctypes.get_errno()
    print(f"  [abort] restore failed: errno={err} ({os.strerror(err)})")
    sys.exit(1)

print(f"  Socket restored live (new_fd={new_fd})")

# ── Step 7: post-restore write (assertion ③) ─────────────────────────
print("")
print("── Step 7: post-restore data transfer (assertion ③) ───────────")
MAGIC = b"HELLO_POST_RESTORE"
try:
    os.write(new_fd, MAGIC)
    time.sleep(0.05)
    os.close(new_fd)
    post_restore_ok = True
except OSError as e:
    print(f"  [error] write failed: {e}")
    post_restore_ok = False

server_done.wait(timeout=3.0)
received_all = b"".join(received_chunks)

check("post_restore_write_ok",
      post_restore_ok,
      "os.write(new_fd) succeeded (no BrokenPipe)")

check("server_received_magic",
      MAGIC in received_all,
      f"Server received {len(received_all)} bytes including HELLO_POST_RESTORE")

check("server_received_prefreeze",
      b"BEFORE_FREEZE" in received_all,
      f"Server also received the {len(payload)}-byte pre-freeze payload")

# ── summary ──────────────────────────────────────────────────────────
print("")
print("════════════════════════════════════════════════════════════")
print(" Results")
print("════════════════════════════════════════════════════════════")
for r in RESULTS:
    print(f"  {r}")
print("")

if PASS:
    print(" ✅ PASS — TCP_REPAIR works on real loopback")
    print(f"    Freeze at send_seq={state.send_seq} → restore → no RST → data delivered")
    sys.exit(0)
else:
    print(" ❌ FAIL — at least one assertion failed")
    print("    Check: 1) running as root?  2) libccmc.so compiled?  3) kernel >= 3.11?")
    sys.exit(1)
PYEOF

EXIT=$?
echo ""
if [[ $EXIT -eq 0 ]]; then
    echo "════════════════════════════════════════════════════════════"
    echo " ✅ CCMC TCP_REPAIR validation PASS"
    echo "════════════════════════════════════════════════════════════"
else
    echo "════════════════════════════════════════════════════════════"
    echo " ❌ CCMC TCP_REPAIR validation FAIL"
    echo "════════════════════════════════════════════════════════════"
    exit 1
fi
