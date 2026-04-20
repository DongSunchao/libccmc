// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sunchao Dong

/* include/ccmc.h
 *
 * Connection-Centric Micro-Checkpoint (CCMC) — public API.
 *
 * CCMC exports/imports a TCP connection's kernel state using TCP_REPAIR,
 * enabling live migration of ESTABLISHED sockets across hosts without
 * triggering FIN or RST.
 *
 * Struct layout (x86-64 Linux, little-endian):
 *   sizeof(struct ccmc_ts_state)     = 12 bytes
 *   sizeof(struct ccmc_state)        = 80 bytes
 *
 * Requires CAP_NET_ADMIN (root) for TCP_REPAIR setsockopt calls.
 *
 * Typical usage:
 *   // Source side — after all bytes ACKed (ccmc_tiocoutq_poll returns 0):
 *   struct ccmc_state st;
 *   ccmc_freeze_and_extract(fd, &st, sizeof(st));
 *   // ... send st to target over any channel ...
 *
 *   // Target side:
 *   int new_fd = ccmc_socket_restore(&st, sizeof(st));
 *   // new_fd is a live ESTABLISHED socket
 */

#pragma once
#include <stddef.h>       /* offsetof */
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  /* struct tcp_repair_window, TCP_REPAIR_* */

#ifdef __cplusplus
extern "C" {
#endif

/* ── TCP timestamp state ──────────────────────────────────────────────
 * Needed to pass PAWS check after cross-machine restore.
 * Captured via TCP_INFO (negotiation flag) + TCP_TIMESTAMP (current tsval).
 * If ts_enabled == 0, timestamps were not negotiated on this connection. */
struct ccmc_ts_state {
    uint8_t  ts_enabled;   /* 1 if TCP timestamps negotiated          */
    uint8_t  _pad[3];
    uint32_t tsval;        /* source's tcp_time_stamp_raw() at freeze  */
    uint32_t tsecr;        /* last received timestamp echo reply       */
};

/* ── Full CCMC checkpoint (80 bytes) ──────────────────────────────────
 *
 * Field layout (verified sizeof == 80 on x86-64):
 *   local_addr      16 B  offset  0   — source IP:port
 *   remote_addr     16 B  offset 16   — client IP:port
 *   send_seq         4 B  offset 32   — TCP snd_nxt at freeze
 *   recv_seq         4 B  offset 36   — TCP rcv_nxt at freeze
 *   repair_window   20 B  offset 40   — snd/rcv window parameters
 *   mss              4 B  offset 60   — negotiated MSS
 *   ts              12 B  offset 64   — PAWS timestamp state
 *   token_index      4 B  offset 76   — application-level cursor (caller fills)
 */
struct ccmc_state {
    /* L4 endpoints */
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;

    /* TCP sequence numbers */
    uint32_t send_seq;
    uint32_t recv_seq;

    /* TCP window parameters */
    struct tcp_repair_window repair_window;

    /* MSS negotiated during handshake */
    int mss;

    /* TCP timestamp state (PAWS) */
    struct ccmc_ts_state ts;

    /* Application-level cursor — libccmc sets this to 0; caller may overwrite */
    int token_index;
};


/* ── Core API ─────────────────────────────────────────────────────────*/

/**
 * ccmc_tiocoutq - Return unACKed bytes in the kernel TCP send buffer.
 *
 * Uses TIOCOUTQ (snd_nxt - snd_una). When the return value reaches 0,
 * every sent byte has been ACKed — safe to call ccmc_freeze_and_extract().
 *
 * Returns: byte count (>= 0) on success, -1 on error (errno set).
 */
int ccmc_tiocoutq(int fd);

/**
 * ccmc_tiocoutq_poll - Spin-poll until the send buffer drains or timeout.
 *
 * Polls every 1 ms. Returns 0 when all bytes are ACKed, -1 on timeout
 * (errno = ETIMEDOUT) or ioctl error (errno set by ioctl).
 *
 * @fd         : socket file descriptor
 * @timeout_ms : maximum wait time in milliseconds
 */
int ccmc_tiocoutq_poll(int fd, int timeout_ms);

/**
 * ccmc_freeze_and_extract - Enter TCP_REPAIR and capture full socket state.
 *
 * MUST be called only after ccmc_tiocoutq_poll() returns 0.
 * After this call the socket is frozen; the kernel discards it silently
 * on close() — no RST, no FIN is sent to the peer.
 *
 * @fd       : ESTABLISHED socket to freeze
 * @buf      : caller-allocated buffer; must be >= sizeof(struct ccmc_state)
 * @buf_size : size of buf in bytes
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int ccmc_freeze_and_extract(int fd, void *buf, int buf_size);

/**
 * ccmc_socket_restore - Reconstruct a live ESTABLISHED socket from state.
 *
 * Creates a new socket, enters TCP_REPAIR before bind/connect so that
 * connect() does not send SYN but jumps directly to ESTABLISHED, then
 * exits REPAIR mode — the returned fd is immediately live.
 *
 * @buf      : pointer to previously captured ccmc_state
 * @buf_size : must be >= sizeof(struct ccmc_state)
 *
 * Returns new socket fd (>= 0) on success, -1 on error (errno set).
 * Caller is responsible for close()-ing the returned fd.
 */
int ccmc_socket_restore(const void *buf, int buf_size);

/**
 * ccmc_freeze_batch - Freeze N sockets atomically in a tight C loop.
 *
 * Avoids repeated user/kernel transitions for bulk migration of N
 * concurrent connections. Each fd is TIOCOUTQ-polled (2 s timeout)
 * then frozen via ccmc_freeze_and_extract().
 *
 * @fds        : array of N ESTABLISHED socket file descriptors
 * @n          : number of file descriptors
 * @states_buf : caller-allocated buffer of at least n * state_size bytes;
 *               states_buf[i * state_size] holds the captured state for fds[i]
 * @state_size : must be >= sizeof(struct ccmc_state)
 *
 * Returns 0 if all freeze operations succeeded.
 * Returns -1 on first error (errno set); remaining fds are still attempted.
 */
int ccmc_freeze_batch(const int *fds, int n, void *states_buf, int state_size);

#ifdef __cplusplus
}
#endif

/* ── Compile-time ABI contract ────────────────────────────────────────
 * Any struct change that shifts field offsets or alters the wire size
 * will be caught at compile time on every platform. */
#ifndef __cplusplus
_Static_assert(sizeof(struct ccmc_ts_state) == 12,
               "ccmc_ts_state must be 12 bytes");
_Static_assert(sizeof(struct ccmc_state) == 80,
               "ccmc_state must be 80 bytes — ABI break detected");
_Static_assert(offsetof(struct ccmc_state, send_seq)      == 32,
               "send_seq offset must be 32");
_Static_assert(offsetof(struct ccmc_state, repair_window) == 40,
               "repair_window offset must be 40");
_Static_assert(offsetof(struct ccmc_state, ts)            == 64,
               "ts offset must be 64");
_Static_assert(offsetof(struct ccmc_state, token_index)   == 76,
               "token_index offset must be 76");
#endif
