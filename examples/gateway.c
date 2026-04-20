// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sunchao Dong

/* gateway/gateway.c
 * SSE Proxy with Graceful Drain and TCP_REPAIR export (Milestone 2).
 *
 * Usage: ./gateway <listen_port> <backend_ip:port> <ctl_unix_sock>
 *
 * Control protocol (via Unix socket):
 *   → "DRAIN\n"   trigger Graceful Drain
 *   → "STATUS\n"  query current state
 *   ← "DRAINED\n" + binary tcp_repair_state  (sent when queue is empty)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>

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

#define MAX_EVENTS       16
#define BUF_SIZE         4096
#define DRAIN_TIMEOUT_MS 2000   /* force freeze if ACKs don't arrive within 2s */

enum gw_state {
    GW_RUNNING,
    GW_DRAINING,
    GW_DRAINED,
};

struct gateway {
    int client_fd;
    int backend_fd;
    int ctl_fd;
    int ctl_client_fd;
    int epfd;

    enum gw_state state;
    uint64_t tokens_forwarded;

    int drain_timerfd;
    int drain_elapsed_ms;
};

static void forward_token(struct gateway *gw, const char *token, int len)
{
    char sse_buf[BUF_SIZE];
    int n = snprintf(sse_buf, sizeof(sse_buf), "data: %.*s\n\n", len, token);
    write(gw->client_fd, sse_buf, n);
    gw->tokens_forwarded++;
}

static void enter_drain_state(struct gateway *gw)
{
    gw->state = GW_DRAINING;
    if (gw->backend_fd >= 0) {
        epoll_ctl(gw->epfd, EPOLL_CTL_DEL, gw->backend_fd, NULL);
    }

    int flag = 1;
    setsockopt(gw->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    gw->drain_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    struct itimerspec ts = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 1000000 },
        .it_value    = { .tv_sec = 0, .tv_nsec = 1000000 },
    };
    timerfd_settime(gw->drain_timerfd, 0, &ts, NULL);

    struct epoll_event ev = { .events = EPOLLIN, .data = {.fd = gw->drain_timerfd} };
    epoll_ctl(gw->epfd, EPOLL_CTL_ADD, gw->drain_timerfd, &ev);
}

/* Perform TCP_REPAIR export and send state to ctl client.
 * Called only when TIOCOUTQ == 0: all bytes ACKed, snd_seq is
 * boundary-aligned at the end of the last complete SSE frame. */
static void do_ccmc_export(struct gateway *gw)
{
    struct ccmc_state state = {};
    state.token_index = (int)gw->tokens_forwarded;

    int opt = 1;
    if (setsockopt(gw->client_fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        perror("[CCMC] TCP_REPAIR ON");
        return;
    }

    socklen_t len = sizeof(state.local_addr);
    getsockname(gw->client_fd, (struct sockaddr *)&state.local_addr, &len);
    len = sizeof(state.remote_addr);
    getpeername(gw->client_fd, (struct sockaddr *)&state.remote_addr, &len);

    int queue = TCP_SEND_QUEUE;
    setsockopt(gw->client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    socklen_t optlen = sizeof(state.send_seq);
    getsockopt(gw->client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.send_seq, &optlen);

    queue = TCP_RECV_QUEUE;
    setsockopt(gw->client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    optlen = sizeof(state.recv_seq);
    getsockopt(gw->client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.recv_seq, &optlen);

    queue = TCP_NO_QUEUE;
    setsockopt(gw->client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));

    optlen = sizeof(state.repair_window);
    if (getsockopt(gw->client_fd, SOL_TCP, TCP_REPAIR_WINDOW,
                   &state.repair_window, &optlen) < 0) {
        perror("[CCMC] TCP_REPAIR_WINDOW (non-fatal)");
    }

    optlen = sizeof(state.mss);
    if (getsockopt(gw->client_fd, IPPROTO_TCP, TCP_MAXSEG,
                   &state.mss, &optlen) < 0) {
        perror("[CCMC] TCP_MAXSEG (non-fatal)");
    }

    printf("[CCMC Export] send_seq=%u recv_seq=%u mss=%d next_token=%d\n",
           state.send_seq, state.recv_seq, state.mss, state.token_index);

    if (gw->ctl_client_fd >= 0) {
        /* "DRAINED\n" text header followed by binary state struct */
        const char *hdr = "DRAINED\n";
        write(gw->ctl_client_fd, hdr, strlen(hdr));
        write(gw->ctl_client_fd, &state, sizeof(state));
    }
}

static void check_drain_complete(struct gateway *gw)
{
    uint64_t exp;
    read(gw->drain_timerfd, &exp, sizeof(exp));
    gw->drain_elapsed_ms += (int)exp;   /* timerfd may batch multiple ticks */

    int unsent = 0;
    ioctl(gw->client_fd, TIOCOUTQ, &unsent);

    int timed_out = (gw->drain_elapsed_ms >= DRAIN_TIMEOUT_MS);
    if (timed_out && unsent > 0) {
        printf("[Drain] Timeout after %dms — client may be dead. "
               "Forcing freeze with %d bytes unacked.\n",
               DRAIN_TIMEOUT_MS, unsent);
    }

    if (unsent == 0 || timed_out) {
        gw->state = GW_DRAINED;
        epoll_ctl(gw->epfd, EPOLL_CTL_DEL, gw->drain_timerfd, NULL);
        close(gw->drain_timerfd);
        gw->drain_timerfd = -1;

        do_ccmc_export(gw);
    }
}

static void handle_ctl_cmd(struct gateway *gw, const char *cmd)
{
    if (strncmp(cmd, "DRAIN", 5) == 0 && gw->state == GW_RUNNING) {
        enter_drain_state(gw);
    }
    else if (strncmp(cmd, "STATUS", 6) == 0 && gw->ctl_client_fd >= 0) {
        char resp[128];
        snprintf(resp, sizeof(resp), "STATE=%d TOKENS=%lu\n", gw->state, gw->tokens_forwarded);
        write(gw->ctl_client_fd, resp, strlen(resp));
    }
}

static void run_gateway(struct gateway *gw)
{
    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int n = epoll_wait(gw->epfd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == gw->backend_fd && gw->state == GW_RUNNING) {
                char buf[BUF_SIZE];
                int r = read(fd, buf, sizeof(buf));
                if (r > 0)
                    forward_token(gw, buf, r);
                else if (r == 0) {
                    close(fd);
                    gw->backend_fd = -1;
                }
            }
            else if (fd == gw->drain_timerfd && gw->state == GW_DRAINING) {
                check_drain_complete(gw);
            }
            else if (fd == gw->ctl_fd) {
                int cfd = accept(gw->ctl_fd, NULL, NULL);
                if (cfd >= 0) {
                    if (gw->ctl_client_fd >= 0) close(gw->ctl_client_fd);
                    gw->ctl_client_fd = cfd;
                    struct epoll_event ev = { .events = EPOLLIN, .data = {.fd = cfd} };
                    epoll_ctl(gw->epfd, EPOLL_CTL_ADD, cfd, &ev);
                }
            }
            else if (fd == gw->ctl_client_fd) {
                char buf[256];
                int r = read(fd, buf, sizeof(buf) - 1);
                if (r > 0) {
                    buf[r] = '\0';
                    handle_ctl_cmd(gw, buf);
                } else {
                    close(fd);
                    gw->ctl_client_fd = -1;
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    // Close inherited FDs from the IDE/PTY to ensure a clean CRIU snapshot
    for (int i = 3; i < 1024; i++) {
        close(i);
    }
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <port> <vllm_ip:port> <ctl_sock>\n", argv[0]);
        return 1;
    }

    int listen_port = atoi(argv[1]);
    
    char backend_ip[64] = "127.0.0.1";
    int backend_port = 9000;
    if (strchr(argv[2], ':')) {
        sscanf(argv[2], "%[^:]:%d", backend_ip, &backend_port);
    } else {
        backend_port = atoi(argv[2]);
    }
    
    const char *ctl_path = argv[3];

    struct gateway gw = {};
    gw.state = GW_RUNNING;
    gw.drain_timerfd = -1;
    gw.ctl_client_fd = -1;

    gw.epfd = epoll_create1(EPOLL_CLOEXEC);

    // Setup listener
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(listen_port), .sin_addr = {.s_addr = INADDR_ANY} };
    bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sfd, 1);
    
    printf("Gateway listening on %d, expecting backend at %s:%d\n", listen_port, backend_ip, backend_port);
    
    // Accept one client connection
    gw.client_fd = accept(sfd, NULL, NULL);
    printf("Client connected.\n");
    close(sfd);

    // HTTP/1.1 SSE handshake: read GET request, reply with SSE headers
    {
        char buf[4096];
        int n = read(gw.client_fd, buf, sizeof(buf) - 1);
        if (n > 0 && strncmp(buf, "GET ", 4) == 0) {
            const char *resp =
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: keep-alive\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n";
            write(gw.client_fd, resp, strlen(resp));
        }
    }

    // Connect to backend
    gw.backend_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in baddr = { .sin_family = AF_INET, .sin_port = htons(backend_port) };
    inet_pton(AF_INET, backend_ip, &baddr.sin_addr);
    connect(gw.backend_fd, (struct sockaddr *)&baddr, sizeof(baddr));

    struct epoll_event ev_b = { .events = EPOLLIN, .data = {.fd = gw.backend_fd} };
    epoll_ctl(gw.epfd, EPOLL_CTL_ADD, gw.backend_fd, &ev_b);

    // Setup ctl Unix socket
    unlink(ctl_path);
    gw.ctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un caddr = { .sun_family = AF_UNIX };
    strncpy(caddr.sun_path, ctl_path, sizeof(caddr.sun_path)-1);
    bind(gw.ctl_fd, (struct sockaddr *)&caddr, sizeof(caddr));
    listen(gw.ctl_fd, 1);
    
    struct epoll_event ev_c = { .events = EPOLLIN, .data = {.fd = gw.ctl_fd} };
    epoll_ctl(gw.epfd, EPOLL_CTL_ADD, gw.ctl_fd, &ev_c);

    run_gateway(&gw);
    return 0;
}
