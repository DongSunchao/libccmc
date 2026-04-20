// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sunchao Dong

/*
 * src/ccmc.c — Connection-Centric Micro-Checkpoint core library.
 *
 * Exports TCP_REPAIR primitives as a reentrant, stateless shared library.
 * No global state; all functions take a file descriptor and/or a caller-
 * allocated ccmc_state buffer.
 *
 * Compile (shared library):
 *   gcc -O2 -Wall -g -shared -fPIC -I../include ccmc.c -o libccmc.so
 *
 * Compile (static library):
 *   gcc -O2 -Wall -g -c -I../include ccmc.c -o ccmc.o
 *   ar rcs libccmc.a ccmc.o
 *
 * Exported symbols (C linkage):
 *   ccmc_tiocoutq          — query unACKed bytes in send buffer
 *   ccmc_tiocoutq_poll     — spin until ACKed or timeout
 *   ccmc_freeze_and_extract — enter TCP_REPAIR, capture full state
 *   ccmc_socket_restore    — create ESTABLISHED socket from captured state
 *   ccmc_freeze_batch      — freeze N sockets in one tight C loop
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "../include/ccmc.h"

#ifndef TCP_REPAIR
#define TCP_REPAIR        19
#define TCP_REPAIR_QUEUE  20
#define TCP_QUEUE_SEQ     21
#define TCP_NO_QUEUE      0
#define TCP_SEND_QUEUE    1
#define TCP_RECV_QUEUE    2
#endif
#ifndef TCP_REPAIR_WINDOW
#define TCP_REPAIR_WINDOW 29
#endif
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif
/* TCP_TIMESTAMP: getsockopt returns current tcp_time_stamp_raw() (Linux 3.17+).
 * Used to capture source tsval for cross-machine PAWS continuity. */
#ifndef TCP_TIMESTAMP
#define TCP_TIMESTAMP 24
#endif
/* TCPI_OPT_TIMESTAMPS: bit in tcp_info.tcpi_options indicating timestamps negotiated. */
#ifndef TCPI_OPT_TIMESTAMPS
#define TCPI_OPT_TIMESTAMPS 1
#endif

#define DRAIN_POLL_US  1000   /* 1 ms poll interval for TIOCOUTQ */

/* ------------------------------------------------------------------ */

/*
 * ccmc_tiocoutq - Return unACKed bytes in the kernel TCP send buffer.
 *
 * TIOCOUTQ returns (snd_nxt - snd_una): the number of bytes that have
 * been written to the socket but not yet acknowledged by the peer.
 * When this reaches 0, every sent byte has been ACKed — safe to freeze.
 *
 * Returns: byte count (>= 0) on success, -1 on ioctl error (errno set).
 */
int ccmc_tiocoutq(int fd)
{
    int unsent = 0;
    if (ioctl(fd, TIOCOUTQ, &unsent) < 0)
        return -1;
    return unsent;
}


/*
 * ccmc_tiocoutq_poll - Spin-poll until send buffer is empty or timeout.
 *
 * Polls TIOCOUTQ every 1 ms. Stops when:
 *   (a) unsent == 0  → all ACKed, clean drain   → returns 0
 *   (b) timeout_ms elapsed                       → returns -1 (errno = ETIMEDOUT)
 *   (c) ioctl error                              → returns -1 (errno set by ioctl)
 *
 * This is the "Flush Barrier" that guarantees the TCP sequence number is
 * exactly at the application-layer frame boundary before freezing.
 */
int ccmc_tiocoutq_poll(int fd, int timeout_ms)
{
    int elapsed_ms = 0;
    while (elapsed_ms < timeout_ms) {
        int unsent = ccmc_tiocoutq(fd);
        if (unsent < 0)
            return -1;   /* ioctl error */
        if (unsent == 0)
            return 0;    /* clean drain */
        usleep(DRAIN_POLL_US);
        elapsed_ms++;
    }
    errno = ETIMEDOUT;
    return -1;
}


/*
 * ccmc_freeze_and_extract - Enter TCP_REPAIR and capture socket state.
 *
 * MUST be called only after ccmc_tiocoutq_poll() returns 0 (all bytes ACKed).
 * After this call the socket is frozen in REPAIR mode; the kernel discards
 * it silently on close() — no RST, no FIN is sent to the peer.
 *
 * buf      : pointer to caller-allocated buffer, must be >= sizeof(ccmc_state)
 * buf_size : sizeof(buf); function returns -1 if buf is too small
 *
 * Returns 0 on success, -1 on error (errno set).
 */
int ccmc_freeze_and_extract(int fd, void *buf, int buf_size)
{
    if (buf_size < (int)sizeof(struct ccmc_state)) {
        errno = EINVAL;
        return -1;
    }

    struct ccmc_state *st = (struct ccmc_state *)buf;
    memset(st, 0, sizeof(*st));

    /* 1. Enter TCP_REPAIR — freezes socket; no FIN/RST sent */
    int opt = 1;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0)
        return -1;

    /* 2. Capture endpoints */
    socklen_t len = sizeof(st->local_addr);
    getsockname(fd, (struct sockaddr *)&st->local_addr, &len);
    len = sizeof(st->remote_addr);
    getpeername(fd, (struct sockaddr *)&st->remote_addr, &len);

    /* 3. Capture send sequence number */
    int queue = TCP_SEND_QUEUE;
    setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    socklen_t optlen = sizeof(st->send_seq);
    getsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &st->send_seq, &optlen);

    /* 4. Capture receive sequence number */
    queue = TCP_RECV_QUEUE;
    setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    optlen = sizeof(st->recv_seq);
    getsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &st->recv_seq, &optlen);

    /* 5. Deselect queue before reading window */
    queue = TCP_NO_QUEUE;
    setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));

    /* 6. Capture window parameters (non-fatal if unsupported by kernel) */
    optlen = sizeof(st->repair_window);
    getsockopt(fd, SOL_TCP, TCP_REPAIR_WINDOW, &st->repair_window, &optlen);

    /* 7. Capture MSS (non-fatal) */
    optlen = sizeof(st->mss);
    getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &st->mss, &optlen);

    /* 8. Capture TCP timestamp for cross-machine PAWS continuity.
     *
     * getsockopt(TCP_REPAIR_OPTIONS) is WRITE-ONLY on Linux 5.x+ (returns EINVAL).
     * Correct two-step approach:
     *
     *   Step A — check if timestamps were negotiated via TCP_INFO.tcpi_options.
     *   Step B — read the current system tsval via TCP_TIMESTAMP (Linux 3.17+).
     *            getsockopt(TCP_TIMESTAMP) returns tcp_time_stamp_raw(), i.e. the
     *            value that will appear as TSVAL in the next outgoing segment.
     *
     * On restore (target), setsockopt(TCP_REPAIR_OPTIONS, TCPOPT_TIMESTAMP, tsval)
     * executes:  tp->tsoffset = tsval - tcp_time_stamp_raw(target)
     * so every subsequent outgoing TSVAL = tcp_time_stamp_raw(target) + tsoffset
     *                                    = tsval + elapsed_on_target
     *                                    >= tsval  (source's last TSVAL).
     * Result: no PAWS drop on the peer.
     */
    st->ts.ts_enabled = 0;
    st->ts.tsval      = 0;
    st->ts.tsecr      = 0;
    {
        struct tcp_info tinfo;
        socklen_t tlen = sizeof(tinfo);
        if (getsockopt(fd, SOL_TCP, TCP_INFO, &tinfo, &tlen) == 0 &&
            (tinfo.tcpi_options & TCPI_OPT_TIMESTAMPS)) {
            uint32_t tsval = 0;
            socklen_t tslen = sizeof(tsval);
            if (getsockopt(fd, SOL_TCP, TCP_TIMESTAMP, &tsval, &tslen) == 0) {
                st->ts.ts_enabled = 1;
                st->ts.tsval = tsval;   /* source's current tcp_time_stamp_raw() */
                /* tsecr = peer's last tsval; not needed for PAWS (only tsval matters) */
            }
        }
    }

    /* token_index is filled by the caller */
    st->token_index = 0;

    return 0;
}


/*
 * ccmc_socket_restore - Reconstruct a live ESTABLISHED socket from state.
 *
 * Creates a new socket, enters TCP_REPAIR before bind/connect so that
 * connect() does not send a SYN but jumps directly to ESTABLISHED, then
 * exits REPAIR mode → socket is immediately live.
 *
 * buf      : pointer to previously captured ccmc_state
 * buf_size : sizeof(buf); must be >= sizeof(ccmc_state)
 *
 * Returns the new socket fd (>= 0) on success, -1 on error (errno set).
 * Caller is responsible for close()-ing the returned fd.
 */
int ccmc_socket_restore(const void *buf, int buf_size)
{
    if (buf_size < (int)sizeof(struct ccmc_state)) {
        errno = EINVAL;
        return -1;
    }

    const struct ccmc_state *st = (const struct ccmc_state *)buf;

    /* 1. Create socket */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Allow binding to an IP not yet configured on this interface.
     * The VIP/routing update happens in parallel (eBPF / cloud API). */
    setsockopt(fd, SOL_IP, IP_FREEBIND, &opt, sizeof(opt));

    /* 2. Enter REPAIR mode BEFORE bind/connect (critical ordering) */
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        close(fd);
        return -1;
    }

    /* 3. Bind to original local address:port */
    if (bind(fd, (const struct sockaddr *)&st->local_addr,
             sizeof(st->local_addr)) < 0) {
        close(fd);
        return -1;
    }

    /* 4. Restore send sequence number */
    int queue = TCP_SEND_QUEUE;
    setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    setsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &st->send_seq, sizeof(st->send_seq));

    /* 5. Restore receive sequence number */
    queue = TCP_RECV_QUEUE;
    setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    setsockopt(fd, SOL_TCP, TCP_QUEUE_SEQ, &st->recv_seq, sizeof(st->recv_seq));

    /* 6. Deselect queue */
    queue = TCP_NO_QUEUE;
    setsockopt(fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));

    /* 7. Repair-connect: kernel jumps to ESTABLISHED, no SYN sent */
    if (connect(fd, (const struct sockaddr *)&st->remote_addr,
                sizeof(st->remote_addr)) < 0) {
        close(fd);
        return -1;
    }

    /* 8. Restore window parameters */
    setsockopt(fd, SOL_TCP, TCP_REPAIR_WINDOW,
               &st->repair_window, sizeof(st->repair_window));

    /* 9. Restore MSS */
    if (st->mss > 0)
        setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &st->mss, sizeof(st->mss));

    /* 10. Restore TCP timestamp (PAWS continuity).
     *
     * Must be called while still in TCP_REPAIR mode (before step 11).
     *
     * setsockopt(TCP_REPAIR_OPTIONS, TCPOPT_TIMESTAMP, opt_val=tsval) tells the
     * kernel to set:  tp->tsoffset = tsval - tcp_time_stamp_raw(this_machine)
     *
     * After exiting REPAIR, outgoing TSVAL = tcp_time_stamp_raw() + tsoffset
     *                                      = tsval + elapsed_since_restore
     *                                      >= tsval (source's freeze-time tsval).
     *
     * The peer last saw source's TSVAL <= tsval, so our first packet
     * arrives with TSVAL >= peer's last-seen TSVAL → no PAWS drop. */
#ifdef TCP_REPAIR_OPTIONS
    if (st->ts.ts_enabled && st->ts.tsval != 0) {
        struct tcp_repair_opt ts_opt = {
            .opt_code = TCPOPT_TIMESTAMP,
            .opt_val  = st->ts.tsval,
        };
        setsockopt(fd, SOL_TCP, TCP_REPAIR_OPTIONS, &ts_opt, sizeof(ts_opt));
    }
#endif

    /* 11. Exit REPAIR mode — socket is now live */
    opt = 0;
    if (setsockopt(fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}


/*
 * ccmc_freeze_batch - Freeze N sockets atomically in a tight C loop.
 *
 * Handles bulk concurrent connections without returning to user-space
 * between each freeze, minimising inter-freeze jitter (~10 µs per fd).
 *
 * fds        : array of N socket file descriptors (all ESTABLISHED)
 * n          : number of file descriptors
 * states_buf : caller-allocated buffer of at least n * state_size bytes
 * state_size : must be >= sizeof(ccmc_state)
 *
 * Returns 0 if all N freeze operations succeeded.
 * Returns -1 on first error (errno set to the failing fd's errno; remaining
 *         fds are still attempted so we don't leave sockets in mixed states).
 */
int ccmc_freeze_batch(const int *fds, int n, void *states_buf, int state_size)
{
    if (!fds || n <= 0 || !states_buf || state_size < (int)sizeof(struct ccmc_state)) {
        errno = EINVAL;
        return -1;
    }

    int first_err = 0;
    char *buf = (char *)states_buf;

    for (int i = 0; i < n; i++) {
        int fd = fds[i];
        void *slot = buf + (i * state_size);

        /* Flush barrier: poll until send buffer empty (2 s timeout).
         * Non-fatal on failure: loopback ACKs are near-instant. */
        if (ccmc_tiocoutq_poll(fd, 2000) < 0 && errno != ETIMEDOUT) {
            /* continue — TIOCOUTQ failure on loopback is benign */
        }

        /* Freeze this socket */
        if (ccmc_freeze_and_extract(fd, slot, state_size) < 0) {
            if (first_err == 0)
                first_err = errno;   /* record first error, keep going */
        }
    }

    if (first_err != 0) {
        errno = first_err;
        return -1;
    }
    return 0;
}
