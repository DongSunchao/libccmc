// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sunchao Dong

/* tests/helpers/tcp_echo_server.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 9000;

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sfd, 1);

    printf("tcp_echo_server Listening on port %d\n", port);
    int cfd = accept(sfd, NULL, NULL);
    printf("Client connected\n");

    uint64_t seq = 0;
    while (1) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf), "TOKEN_%lu\n", seq++);
        if (write(cfd, buf, n) < 0)
            break;
        usleep(100000);  /* 100ms interval, 10 tokens/sec */
    }

    printf("Connection closed at seq %lu\n", seq);
    close(cfd);
    close(sfd);
    return 0;
}
