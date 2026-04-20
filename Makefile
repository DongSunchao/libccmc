# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sunchao Dong
#
# libccmc — Connection-Centric Micro-Checkpoint
#
# Targets:
#   all          — build shared + static library
#   libccmc.so   — shared library (build/libccmc.so)
#   libccmc.a    — static library (build/libccmc.a)
#   examples     — build example programs
#   tests        — build test helpers
#   ebpf         — build eBPF XDP + TC programs
#   clean        — remove all build artifacts

CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -g -I./include
LDFLAGS :=

BUILD   := build
SRC     := src/ccmc.c

.PHONY: all libccmc.so libccmc.a examples tests ebpf clean

all: libccmc.so libccmc.a

$(BUILD):
	mkdir -p $(BUILD)

# ── Shared library ──────────────────────────────────────────────────
libccmc.so: $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC $(SRC) -o $(BUILD)/libccmc.so
	@echo "  → $(BUILD)/libccmc.so"

# ── Static library ──────────────────────────────────────────────────
libccmc.a: $(BUILD)
	$(CC) $(CFLAGS) -c $(SRC) -o $(BUILD)/ccmc.o
	ar rcs $(BUILD)/libccmc.a $(BUILD)/ccmc.o
	@echo "  → $(BUILD)/libccmc.a"

# ── Examples ────────────────────────────────────────────────────────
examples: libccmc.so
	$(CC) $(CFLAGS) examples/sse_server.c -o $(BUILD)/sse_server
	$(CC) $(CFLAGS) examples/gateway.c    -o $(BUILD)/gateway
	@echo "  → $(BUILD)/sse_server  $(BUILD)/gateway"

# ── Test helpers ────────────────────────────────────────────────────
tests: libccmc.so
	$(CC) $(CFLAGS) tests/helpers/tcp_echo_server.c  -o $(BUILD)/tcp_echo_server
	$(CC) $(CFLAGS) tests/helpers/client_verifier.c  -o $(BUILD)/client_verifier
	$(CC) $(CFLAGS) -I./include tests/helpers/dummy_llm_server.c -o $(BUILD)/dummy_llm_server
	@echo "  → test helpers in $(BUILD)/"

# ── eBPF programs ───────────────────────────────────────────────────
ebpf:
	$(MAKE) -C ebpf

# ── Clean ───────────────────────────────────────────────────────────
clean:
	rm -rf $(BUILD)
	$(MAKE) -C ebpf clean 2>/dev/null || true
