// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sunchao Dong

/* gateway/sse_server.c
 *
 * HTTP/1.1 SSE server with Graceful Drain and TCP_REPAIR migration.
 * Implements the "Boundary Alignment" principle: migration is only
 * triggered between two complete SSE frames, never mid-frame.
 *
 * Normal mode:  ./sse_server <port> [state_file]
 * Restore mode: sudo ./sse_server --restore [state_file]
 *
 * SIGUSR1 triggers Graceful Drain:
 *   stop token production → poll TIOCOUTQ until 0 → TCP_REPAIR export → exit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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

#define DEFAULT_STATE_FILE  "/tmp/sse_server.state"
#define TOKEN_INTERVAL_US   100000   /* 100ms per token */
#define DRAIN_POLL_US       1000     /* 1ms TIOCOUTQ poll interval */
#define DRAIN_TIMEOUT_MS    2000     /* 2s max wait for ACKs before forced freeze */

static volatile sig_atomic_t g_drain = 0;
static int  g_client_fd   = -1;
static int  g_token_index = 0;

static void handle_sigusr1(int sig) { (void)sig; g_drain = 1; }

/* ------------------------------------------------------------------
 * HTTP/1.1 handshake: read GET, reply with SSE response headers.
 * ------------------------------------------------------------------ */
static int do_http_handshake(int fd)
{
    char buf[4096];
    int n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';

    if (strncmp(buf, "GET ", 4) != 0) {
        const char *bad = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        write(fd, bad, strlen(bad));
        return -1;
    }

    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n";
    if (write(fd, resp, strlen(resp)) <= 0) return -1;
    return 0;
}

/* ------------------------------------------------------------------
 * CCMC Export: freeze socket via TCP_REPAIR, capture state to file.
 * Must only be called when TIOCOUTQ == 0 (all bytes ACKed).
 * ------------------------------------------------------------------ */
static void do_ccmc_export(const char *state_file)
{
    struct ccmc_state state = {};
    state.token_index = g_token_index;

    /* 1. Enter TCP_REPAIR — freezes socket, no FIN/RST sent */
    int opt = 1;
    if (setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        perror("[CCMC Export] TCP_REPAIR ON failed");
        return;
    }

    /* 2. Capture endpoints */
    socklen_t len = sizeof(state.local_addr);
    getsockname(g_client_fd, (struct sockaddr *)&state.local_addr, &len);
    len = sizeof(state.remote_addr);
    getpeername(g_client_fd, (struct sockaddr *)&state.remote_addr, &len);

    /* 3. Capture send sequence */
    int queue = TCP_SEND_QUEUE;
    setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    socklen_t optlen = sizeof(state.send_seq);
    getsockopt(g_client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.send_seq, &optlen);

    /* 4. Capture receive sequence */
    queue = TCP_RECV_QUEUE;
    setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    optlen = sizeof(state.recv_seq);
    getsockopt(g_client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.recv_seq, &optlen);

    /* 5. Deselect queue before reading window */
    queue = TCP_NO_QUEUE;
    setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));

    /* 6. Capture window parameters */
    optlen = sizeof(state.repair_window);
    if (getsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_WINDOW,
                   &state.repair_window, &optlen) < 0) {
        perror("[CCMC Export] TCP_REPAIR_WINDOW (non-fatal)");
    }

    /* 7. Capture MSS */
    optlen = sizeof(state.mss);
    if (getsockopt(g_client_fd, IPPROTO_TCP, TCP_MAXSEG,
                   &state.mss, &optlen) < 0) {
        perror("[CCMC Export] TCP_MAXSEG (non-fatal)");
    }

    /* 8. Write checkpoint */
    FILE *f = fopen(state_file, "wb");
    if (!f) { perror("[CCMC Export] fopen state"); return; }
    fwrite(&state, sizeof(state), 1, f);
    fclose(f);

    printf("[CCMC Export] send_seq=%u recv_seq=%u mss=%d "
           "snd_wnd=%u rcv_wnd=%u next_token=%d → %s\n",
           state.send_seq, state.recv_seq, state.mss,
           state.repair_window.snd_wnd, state.repair_window.rcv_wnd,
           state.token_index, state_file);
}

/* ------------------------------------------------------------------
 * Token streaming loop + Graceful Drain.
 * ------------------------------------------------------------------ */
static void run_token_loop(const char *state_file)
{
    /* Flush each frame immediately; don't coalesce via Nagle */
    int flag = 1;
    setsockopt(g_client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    printf("[SSE] Streaming from TOKEN_%d...\n", g_token_index);

    while (!g_drain) {
        char frame[64];
        int n = snprintf(frame, sizeof(frame), "data: TOKEN_%d\n\n", g_token_index);
        if (write(g_client_fd, frame, n) <= 0) {
            printf("[SSE] Client disconnected at TOKEN_%d (errno=%d)\n",
                   g_token_index, errno);
            close(g_client_fd);
            g_client_fd = -1;
            return;
        }
        g_token_index++;
        usleep(TOKEN_INTERVAL_US);
    }

    /* ---- Graceful Drain ----
     *
     * We stopped producing new tokens. The last complete frame is already
     * in the kernel send buffer. Wait until every byte has been ACKed by
     * the client before entering TCP_REPAIR — this guarantees snd_seq aligns
     * exactly at the boundary between TOKEN_{N-1} and TOKEN_N.
     *
     * TIOCOUTQ returns (snd_nxt - snd_una): unacknowledged byte count.
     * When it hits 0, all data is ACKed → safe to freeze.
     */
    printf("[Drain] Signal received after TOKEN_%d. Waiting for ACKs...\n",
           g_token_index - 1);

    int unsent;
    int remaining_ms = DRAIN_TIMEOUT_MS;
    do {
        ioctl(g_client_fd, TIOCOUTQ, &unsent);
        if (unsent > 0) {
            usleep(DRAIN_POLL_US);
            if (--remaining_ms <= 0) {
                printf("[Drain] Timeout after %dms — client may be dead. "
                       "Forcing freeze with %d bytes unacked.\n",
                       DRAIN_TIMEOUT_MS, unsent);
                break;
            }
        }
    } while (unsent > 0);

    printf("[Drain] Freezing socket and exporting state.\n");
    do_ccmc_export(state_file);

    /* Socket stays in REPAIR mode — kernel discards it silently, no RST */
    close(g_client_fd);
    g_client_fd = -1;
    exit(0);
}

/* ------------------------------------------------------------------
 * CCMC Import: restore a frozen TCP socket from checkpoint file.
 * ------------------------------------------------------------------ */
static int restore_from_checkpoint(const char *state_file)
{
    FILE *f = fopen(state_file, "rb");
    if (!f) { perror("[CCMC Import] open state file"); return 1; }

    struct ccmc_state state = {};
    if (fread(&state, sizeof(state), 1, f) != 1) {
        fprintf(stderr, "[CCMC Import] failed to read state\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("[CCMC Import] Restoring: send_seq=%u recv_seq=%u mss=%d "
           "snd_wnd=%u rcv_wnd=%u next_token=%d\n",
           state.send_seq, state.recv_seq, state.mss,
           state.repair_window.snd_wnd, state.repair_window.rcv_wnd,
           state.token_index);

    /* 1. Create socket */
    g_client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_client_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(g_client_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Allow binding to an IP not yet owned by this machine.
     * VIP will be added via `ip addr add` + gratuitous ARP after restore. */
    setsockopt(g_client_fd, SOL_IP, IP_FREEBIND, &opt, sizeof(opt));

    /* 2. Enter REPAIR mode BEFORE bind/connect */
    if (setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        perror("[CCMC Import] TCP_REPAIR ON (need root/CAP_NET_ADMIN)");
        return 1;
    }

    /* 3. Bind to original local address:port */
    if (bind(g_client_fd, (struct sockaddr *)&state.local_addr,
             sizeof(state.local_addr)) < 0) {
        perror("[CCMC Import] bind");
        return 1;
    }

    /* 4. Set send sequence BEFORE connect */
    int queue = TCP_SEND_QUEUE;
    setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    setsockopt(g_client_fd, SOL_TCP, TCP_QUEUE_SEQ,
               &state.send_seq, sizeof(state.send_seq));

    /* 5. Set receive sequence */
    queue = TCP_RECV_QUEUE;
    setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    setsockopt(g_client_fd, SOL_TCP, TCP_QUEUE_SEQ,
               &state.recv_seq, sizeof(state.recv_seq));

    /* 6. Deselect queue */
    queue = TCP_NO_QUEUE;
    setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));

    /* 7. Repair-connect: no SYN sent, kernel jumps to ESTABLISHED */
    if (connect(g_client_fd, (struct sockaddr *)&state.remote_addr,
                sizeof(state.remote_addr)) < 0) {
        perror("[CCMC Import] repair-connect");
        return 1;
    }

    /* 8. Restore window parameters (prevents deadlock on resume) */
    if (setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR_WINDOW,
                   &state.repair_window, sizeof(state.repair_window)) < 0) {
        perror("[CCMC Import] TCP_REPAIR_WINDOW (non-fatal)");
    }

    /* 9. Restore MSS */
    if (state.mss > 0)
        setsockopt(g_client_fd, IPPROTO_TCP, TCP_MAXSEG,
                   &state.mss, sizeof(state.mss));

    /* 10. Exit REPAIR mode — socket is now live */
    opt = 0;
    if (setsockopt(g_client_fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        perror("[CCMC Import] TCP_REPAIR OFF");
        return 1;
    }

    printf("[CCMC Import] Socket LIVE. Sending SSE keepalive frame.\n");

    /* Send an SSE comment frame to reset the browser's EventSource
     * reconnect timer before the next real token arrives. */
    const char *keepalive = ": keepalive\n\n";
    write(g_client_fd, keepalive, strlen(keepalive));

    /* Resume token stream from the exported index */
    g_token_index = state.token_index;
    run_token_loop(state_file);
    return 0;
}

/* ------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, handle_sigusr1);

    const char *state_file = DEFAULT_STATE_FILE;

    if (argc > 1 && strcmp(argv[1], "--restore") == 0) {
        if (argc > 2) state_file = argv[2];
        return restore_from_checkpoint(state_file);
    }

    int port = (argc > 1) ? atoi(argv[1]) : 8080;
    if (argc > 2) state_file = argv[2];

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(sfd, 1);
    printf("[SSE] Listening on :%d  state=%s  (SIGUSR1 triggers Graceful Drain)\n",
           port, state_file);

    while (1) {
        g_client_fd = accept(sfd, NULL, NULL);
        if (g_client_fd < 0) { perror("accept"); continue; }
        g_token_index = 0;
        g_drain = 0;
        printf("[SSE] Client connected.\n");

        if (do_http_handshake(g_client_fd) < 0) {
            fprintf(stderr, "[SSE] HTTP handshake failed, dropping connection.\n");
            close(g_client_fd);
            g_client_fd = -1;
            continue;
        }
        run_token_loop(state_file);
    }
    return 0;
}
