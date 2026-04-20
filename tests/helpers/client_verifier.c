// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sunchao Dong

/* tests/helpers/client_verifier.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 8080;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    inet_pton(AF_INET, host, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    printf("Connected to %s:%d\n", host, port);

    uint64_t expected_seq = 0;
    double last_recv = now_sec();
    double max_gap   = 0;
    uint64_t total   = 0;

    char buf[4096];
    int buf_off = 0;

    while (1) {
        int n = read(fd, buf + buf_off, sizeof(buf) - buf_off - 1);
        if (n <= 0) {
            printf("DISCONNECTED at seq %lu (max_gap=%.3fs)\n", expected_seq, max_gap);
            return 1;
        }
        buf_off += n;
        buf[buf_off] = '\0';

        char *line;
        char *strtok_ctx = buf;
        while ((line = strtok(strtok_ctx, "\n")) != NULL) {
            strtok_ctx = NULL; // subsequent calls need NULL
            
            double now = now_sec();
            double gap = now - last_recv;
            if (gap > max_gap) max_gap = gap;
            last_recv = now;

            uint64_t seq;
            // The gateway translates "TOKEN_X\n" to "data: TOKEN_X\n\n"
            if (sscanf(line, "data: TOKEN_%lu", &seq) == 1 || sscanf(line, "TOKEN_%lu", &seq) == 1) {
                if (seq != expected_seq) {
                    printf("SEQ MISMATCH: expected %lu, got %lu (max_gap=%.3fs)\n", expected_seq, seq, max_gap);
                    return 2;
                }
                expected_seq++;
                total++;

                if (total % 10 == 0) {
                    printf("OK: seq=%lu max_gap=%.3fs\n", seq, max_gap);
                }
            } else if (strncmp(line, "data:", 5) == 0) {
                 // Might be incomplete frame, handle appropriately if needed. 
            }
        }
        buf_off = 0; // Simple reset assuming full lines, might lose fragments if framing split, but good for demo.
    }
}
