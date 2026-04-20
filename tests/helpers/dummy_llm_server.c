// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sunchao Dong

/* tests/helpers/dummy_llm_server.c
 *
 * A dummy streaming LLM server with native TCP_REPAIR migration.
 * No CRIU, no gateway proxy — the application owns its own checkpoint.
 *
 * Normal mode:  ./dummy_llm_server 8080
 * Restore mode: sudo ./dummy_llm_server --restore
 *
 * SIGUSR1 triggers CCMC export: TCP state → /tmp/dummy_llm.state, then exit.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>
#include "../../include/ccmc.h"

#ifndef TCP_REPAIR
#define TCP_REPAIR           19
#define TCP_REPAIR_QUEUE     20
#define TCP_QUEUE_SEQ        21
#define TCP_NO_QUEUE         0
#define TCP_SEND_QUEUE       1
#define TCP_RECV_QUEUE       2
#endif

#ifndef TCP_REPAIR_WINDOW
#define TCP_REPAIR_WINDOW    29
#endif

int global_client_fd = -1;
int global_token_index = 0;

const char* fake_tokens[] = {
    "The ", "quick ", "brown ", "fox ", "jumps ",
    "over ", "the ", "lazy ", "dog. ",
    "Wait, ", "let ", "me ", "think... "
};
#define NUM_TOKENS 13

/* ================================================================
 * CCMC EXPORT — triggered by SIGUSR1
 * Extracts the bare minimum to resurrect this TCP connection elsewhere.
 * ================================================================ */
void handle_migrate(int sig)
{
    (void)sig;

    if (global_client_fd < 0) {
        printf("[CCMC] No active client to migrate. Exiting.\n");
        exit(0);
    }

    struct ccmc_state state = {};
    state.token_index = global_token_index;

    /* 1. Enter TCP_REPAIR mode — freezes the socket, no FIN/RST sent */
    int opt = 1;
    if (setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        perror("[CCMC] setsockopt TCP_REPAIR ON failed");
        exit(1);
    }

    /* 2. Capture endpoints */
    socklen_t len = sizeof(state.local_addr);
    getsockname(global_client_fd, (struct sockaddr *)&state.local_addr, &len);
    len = sizeof(state.remote_addr);
    getpeername(global_client_fd, (struct sockaddr *)&state.remote_addr, &len);

    /* 3. Capture send sequence */
    int queue = TCP_SEND_QUEUE;
    setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    socklen_t optlen = sizeof(state.send_seq);
    getsockopt(global_client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.send_seq, &optlen);

    /* 4. Capture receive sequence */
    queue = TCP_RECV_QUEUE;
    setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    optlen = sizeof(state.recv_seq);
    getsockopt(global_client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.recv_seq, &optlen);

    /* 5. Deselect queue before reading window (important!) */
    queue = TCP_NO_QUEUE;
    setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));

    /* 6. Capture window parameters — WITHOUT THIS, RESTORE DEADLOCKS */
    optlen = sizeof(state.repair_window);
    if (getsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_WINDOW, &state.repair_window, &optlen) < 0) {
        perror("[CCMC] getsockopt TCP_REPAIR_WINDOW failed");
    }

    /* 7. Capture MSS */
    optlen = sizeof(state.mss);
    if (getsockopt(global_client_fd, IPPROTO_TCP, TCP_MAXSEG, &state.mss, &optlen) < 0) {
        perror("[CCMC] getsockopt TCP_MAXSEG failed");
    }

    /* 8. Write checkpoint to disk */
    FILE *f = fopen("/tmp/dummy_llm.state", "wb");
    if (f) {
        fwrite(&state, sizeof(state), 1, f);
        fclose(f);
    }

    printf("[CCMC Export] send_seq=%u recv_seq=%u mss=%d "
           "snd_wnd=%u rcv_wnd=%u max_window=%u token=%d\n",
           state.send_seq, state.recv_seq, state.mss,
           state.repair_window.snd_wnd, state.repair_window.rcv_wnd,
           state.repair_window.max_window, state.token_index);
    printf("[CCMC Export] State file: /tmp/dummy_llm.state (%zu bytes). Terminating source.\n",
           sizeof(state));

    /* Socket stays in REPAIR mode — kernel destroys it silently, no RST */
    close(global_client_fd);
    exit(0);
}

/* ================================================================
 * TOKEN LOOP — simulates LLM streaming
 * ================================================================ */
void run_token_loop()
{
    int flag = 1;
    setsockopt(global_client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    printf("[Dummy LLM] Streaming tokens starting from index %d...\n", global_token_index);

    while (1) {
        const char* token = fake_tokens[global_token_index % NUM_TOKENS];
        ssize_t bytes_sent = write(global_client_fd, token, strlen(token));

        if (bytes_sent <= 0) {
            printf("[Dummy LLM] Client disconnected (errno=%d).\n", errno);
            break;
        }

        global_token_index++;
        usleep(200000);
    }
    close(global_client_fd);
    global_client_fd = -1;
}

/* ================================================================
 * CCMC IMPORT — restore a frozen TCP connection from checkpoint
 * ================================================================ */
int restore_from_checkpoint(void)
{
    FILE *f = fopen("/tmp/dummy_llm.state", "rb");
    if (!f) {
        perror("[CCMC Import] Failed to open /tmp/dummy_llm.state");
        return 1;
    }

    struct ccmc_state state = {};
    if (fread(&state, sizeof(state), 1, f) != 1) {
        fprintf(stderr, "[CCMC Import] Failed to read state file\n");
        fclose(f);
        return 1;
    }
    fclose(f);

    printf("[CCMC Import] Restoring: send_seq=%u recv_seq=%u mss=%d "
           "snd_wnd=%u rcv_wnd=%u token=%d\n",
           state.send_seq, state.recv_seq, state.mss,
           state.repair_window.snd_wnd, state.repair_window.rcv_wnd,
           state.token_index);

    /* 1. Create socket */
    global_client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (global_client_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(global_client_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Allow bind to an IP not (yet) owned by this machine — essential for cross-host restore.
     * The VIP will be added via `ip addr add` + gratuitous ARP after restore. */
    setsockopt(global_client_fd, SOL_IP, IP_FREEBIND, &opt, sizeof(opt));

    /* 2. Enter REPAIR mode BEFORE bind/connect */
    if (setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        perror("[CCMC Import] TCP_REPAIR ON failed (need root/CAP_NET_ADMIN)");
        return 1;
    }

    /* 3. Bind to original local address:port */
    if (bind(global_client_fd, (struct sockaddr *)&state.local_addr, sizeof(state.local_addr)) < 0) {
        perror("[CCMC Import] bind failed");
        return 1;
    }

    /* 4. Set send sequence BEFORE connect */
    int queue = TCP_SEND_QUEUE;
    setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    setsockopt(global_client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.send_seq, sizeof(state.send_seq));

    /* 5. Set receive sequence */
    queue = TCP_RECV_QUEUE;
    setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    setsockopt(global_client_fd, SOL_TCP, TCP_QUEUE_SEQ, &state.recv_seq, sizeof(state.recv_seq));

    /* 6. Deselect queue */
    queue = TCP_NO_QUEUE;
    setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));

    /* 7. Repair connect — no SYN sent, kernel jumps straight to ESTABLISHED */
    if (connect(global_client_fd, (struct sockaddr *)&state.remote_addr, sizeof(state.remote_addr)) < 0) {
        perror("[CCMC Import] repair-connect failed");
        return 1;
    }

    /* 8. Restore window parameters — THIS IS THE KEY TO UNBLOCKING DATA FLOW */
    if (setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR_WINDOW,
                   &state.repair_window, sizeof(state.repair_window)) < 0) {
        perror("[CCMC Import] TCP_REPAIR_WINDOW failed");
        /* non-fatal, try to continue */
    }

    /* 9. Restore MSS */
    if (state.mss > 0) {
        setsockopt(global_client_fd, IPPROTO_TCP, TCP_MAXSEG,
                   &state.mss, sizeof(state.mss));
    }

    /* 10. Exit REPAIR mode — socket is now live! */
    opt = 0;
    if (setsockopt(global_client_fd, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) < 0) {
        perror("[CCMC Import] TCP_REPAIR OFF failed");
        return 1;
    }

    printf("[CCMC Import] Socket restored and LIVE. Resuming token stream.\n");

    /* 11. Resume application state */
    global_token_index = state.token_index;
    run_token_loop();
    return 0;
}

/* ================================================================
 * MAIN
 * ================================================================ */
int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, handle_migrate);

    if (argc > 1 && strcmp(argv[1], "--restore") == 0) {
        return restore_from_checkpoint();
    }

    /* Normal server mode */
    int port = argc > 1 ? atoi(argv[1]) : 8080;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("[Dummy LLM] Listening on port %d. SIGUSR1 triggers CCMC export.\n", port);

    while (1) {
        global_client_fd = accept(server_fd, NULL, NULL);
        if (global_client_fd < 0) {
            perror("accept");
            continue;
        }
        global_token_index = 0;
        printf("[Dummy LLM] Client connected.\n");
        run_token_loop();
    }
    return 0;
}
