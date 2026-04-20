# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sunchao Dong

"""
python/ccmc.py — Python ctypes bindings for libccmc.

Usage:
    from ccmc import CCMC, CcmcState

    lib = CCMC("build/libccmc.so")

    # Source side (requires root / CAP_NET_ADMIN):
    lib.tiocoutq_poll(fd, timeout_ms=2000)
    state_bytes = lib.freeze_and_extract(fd)

    # Target side:
    new_fd = lib.socket_restore(state_bytes)

    # Bulk freeze (M concurrent connections):
    states = lib.freeze_batch(fd_list)
"""

import ctypes
import ipaddress
import os
import socket
import struct
from ctypes import c_int, c_uint8, c_uint16, c_uint32, c_void_p


# ── ctypes mirror of include/ccmc.h ──────────────────────────────────
# Sizes verified against C struct on x86-64 Linux (little-endian):
#   SockaddrIn        = 16 bytes
#   TcpRepairWindow   = 20 bytes (5 × uint32)
#   CcmcTsState       = 12 bytes (1 + 3 pad + 4 + 4)
#   CcmcState         = 80 bytes total

class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", c_uint16),
        ("sin_port",   c_uint16),      # network byte order
        ("sin_addr",   c_uint32),      # network byte order
        ("sin_zero",   c_uint8 * 8),
    ]


class _TcpRepairWindow(ctypes.Structure):
    _fields_ = [
        ("snd_wl1",    c_uint32),
        ("snd_wnd",    c_uint32),
        ("max_window", c_uint32),
        ("rcv_wnd",    c_uint32),
        ("rcv_wup",    c_uint32),
    ]


class _CcmcTsState(ctypes.Structure):
    _fields_ = [
        ("ts_enabled", c_uint8),
        ("_pad",       c_uint8 * 3),
        ("tsval",      c_uint32),
        ("tsecr",      c_uint32),
    ]


class CcmcState(ctypes.Structure):
    """
    Python mirror of struct ccmc_state (80 bytes).

    Attributes are accessible directly:
        st.send_seq, st.recv_seq, st.mss, st.token_index
        st.ts.ts_enabled, st.ts.tsval
        st.local_addr.sin_addr, st.remote_addr.sin_addr
    """
    _fields_ = [
        ("local_addr",    _SockaddrIn),
        ("remote_addr",   _SockaddrIn),
        ("send_seq",      c_uint32),
        ("recv_seq",      c_uint32),
        ("repair_window", _TcpRepairWindow),
        ("mss",           c_int),
        ("ts",            _CcmcTsState),
        ("token_index",   c_int),
    ]

    def local_endpoint(self) -> str:
        ip = str(ipaddress.IPv4Address(socket.ntohl(self.local_addr.sin_addr)))
        pt = socket.ntohs(self.local_addr.sin_port)
        return f"{ip}:{pt}"

    def remote_endpoint(self) -> str:
        ip = str(ipaddress.IPv4Address(socket.ntohl(self.remote_addr.sin_addr)))
        pt = socket.ntohs(self.remote_addr.sin_port)
        return f"{ip}:{pt}"

    def summary(self) -> str:
        ts_info = (f" tsval={self.ts.tsval}" if self.ts.ts_enabled else " ts=off")
        return (
            f"{self.local_endpoint()}→{self.remote_endpoint()} "
            f"send_seq={self.send_seq} recv_seq={self.recv_seq} "
            f"mss={self.mss}{ts_info} token={self.token_index}"
        )


_STATE_SIZE = ctypes.sizeof(CcmcState)
assert _STATE_SIZE == 80, f"CcmcState size mismatch: {_STATE_SIZE} != 80"


def _state_to_bytes(st: CcmcState) -> bytes:
    return bytes(ctypes.string_at(ctypes.addressof(st), _STATE_SIZE))


def _bytes_to_state(data: bytes) -> CcmcState:
    st = CcmcState()
    ctypes.memmove(ctypes.addressof(st), data, _STATE_SIZE)
    return st


# ── CCMC library wrapper ──────────────────────────────────────────────

class CCMC:
    """
    Thin wrapper around libccmc.so.

    All methods require CAP_NET_ADMIN (root) except tiocoutq().
    """

    def __init__(self, lib_path: str = "build/libccmc.so"):
        if not os.path.exists(lib_path):
            raise FileNotFoundError(
                f"libccmc.so not found at {lib_path}. "
                "Run: make libccmc.so"
            )
        self._lib = ctypes.CDLL(lib_path, use_errno=True)
        self._bind()

    def _bind(self):
        lib = self._lib
        lib.ccmc_tiocoutq.argtypes      = [c_int]
        lib.ccmc_tiocoutq.restype       = c_int
        lib.ccmc_tiocoutq_poll.argtypes = [c_int, c_int]
        lib.ccmc_tiocoutq_poll.restype  = c_int
        lib.ccmc_freeze_and_extract.argtypes = [c_int, c_void_p, c_int]
        lib.ccmc_freeze_and_extract.restype  = c_int
        lib.ccmc_socket_restore.argtypes = [c_void_p, c_int]
        lib.ccmc_socket_restore.restype  = c_int
        lib.ccmc_freeze_batch.argtypes   = [c_void_p, c_int, c_void_p, c_int]
        lib.ccmc_freeze_batch.restype    = c_int

    # ── public API ────────────────────────────────────────────────────

    def tiocoutq(self, fd: int) -> int:
        """Return unACKed bytes in send buffer, -1 on error."""
        return self._lib.ccmc_tiocoutq(fd)

    def tiocoutq_poll(self, fd: int, timeout_ms: int = 2000) -> int:
        """
        Spin-poll until send buffer drains or timeout.
        Returns 0 on clean drain, raises OSError on timeout/error.
        """
        ret = self._lib.ccmc_tiocoutq_poll(fd, timeout_ms)
        if ret < 0:
            raise OSError(ctypes.get_errno(), "ccmc_tiocoutq_poll failed")
        return ret

    def freeze_and_extract(self, fd: int, token_index: int = 0) -> bytes:
        """
        Enter TCP_REPAIR and capture full socket state.
        Returns raw 80-byte ccmc_state buffer.
        Requires CAP_NET_ADMIN.
        """
        buf = (_STATE_SIZE * ctypes.c_uint8)()
        ret = self._lib.ccmc_freeze_and_extract(fd, buf, _STATE_SIZE)
        if ret < 0:
            raise OSError(
                ctypes.get_errno(),
                "ccmc_freeze_and_extract failed (need root/CAP_NET_ADMIN)"
            )
        raw = bytes(buf)
        st = _bytes_to_state(raw)
        st.token_index = token_index
        return _state_to_bytes(st)

    def socket_restore(self, state_bytes: bytes) -> int:
        """
        Reconstruct a live ESTABLISHED socket from captured state bytes.
        Returns new fd (>= 0). Caller must close() when done.
        Requires CAP_NET_ADMIN.
        """
        if len(state_bytes) < _STATE_SIZE:
            raise ValueError(f"state_bytes too short: {len(state_bytes)} < {_STATE_SIZE}")
        fd = self._lib.ccmc_socket_restore(state_bytes, len(state_bytes))
        if fd < 0:
            raise OSError(
                ctypes.get_errno(),
                "ccmc_socket_restore failed (need root/CAP_NET_ADMIN)"
            )
        return fd

    def freeze_batch(self, fds: list[int]) -> list[bytes]:
        """
        Freeze N sockets atomically. Returns list of 80-byte state buffers.
        Requires CAP_NET_ADMIN.
        """
        n = len(fds)
        fd_arr = (c_int * n)(*fds)
        buf = (ctypes.c_uint8 * (n * _STATE_SIZE))()
        ret = self._lib.ccmc_freeze_batch(fd_arr, n, buf, _STATE_SIZE)
        if ret < 0:
            raise OSError(ctypes.get_errno(), "ccmc_freeze_batch failed")
        return [
            bytes(buf[i * _STATE_SIZE: (i + 1) * _STATE_SIZE])
            for i in range(n)
        ]

    @staticmethod
    def parse_state(state_bytes: bytes) -> CcmcState:
        """Deserialise raw bytes into a CcmcState for inspection."""
        return _bytes_to_state(state_bytes)
