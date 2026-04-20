// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Sunchao Dong

/* ebpf/include/zeno_common.h */
#ifndef __ZENO_COMMON_H__
#define __ZENO_COMMON_H__

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* ---- Migration States ---- */
enum zeno_state {
    ZENO_INACTIVE = 0,   /* Pass-through, XDP_PASS / TC_ACT_OK */
    ZENO_ARMED    = 1,   /* Rewrite Window=0 on egress, but no ingress intercept */
    ZENO_FROZEN   = 2,   /* Full intercept: XDP constructs replies */
    ZENO_RELEASED = 3,   /* Migration done, resume pass-through */
};

/* ---- 4-tuple flow key ---- */
/* Use packed + aligned(4) for consistent memory layout */
struct flow_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
} __attribute__((packed, aligned(4)));

/* ---- Per-session state ---- */
/* Aligned to 8 bytes to avoid 32-bit eBPF / 64-bit userspace padding mismatch. */
struct session_state {
    __u32 state;           /* enum zeno_state */

    /* TCP sequence tracking (parsed by agent from CRIU images) */
    __u32 snd_nxt;         /* Local next sequence to send */
    __u32 rcv_nxt;         /* Expected remote sequence (ack_seq to reply) */

    __u32 _pad0;           /* Explicit padding for __u8[6] layout */

    /* MAC addresses for XDP reply packet construction */
    __u8  local_mac[6];
    __u8  remote_mac[6];

    __u32 _pad1;           /* Align to 8 bytes */

    /* Stats */
    __u64 pkts_intercepted;
    __u64 keepalive_replied;
    __u64 freeze_ts_ns;
} __attribute__((aligned(8)));

/* ---- Deep Buffer for incoming payloads during freeze ---- */
#define DEEP_BUF_MAX_PKTS  4096
#define DEEP_BUF_PKT_SIZE  1600

struct buf_entry {
    __u32 len;
    __u8  data[DEEP_BUF_PKT_SIZE];
} __attribute__((aligned(4)));

/* ---- Compile-time size assertions ---- */
#ifndef __cplusplus
_Static_assert(sizeof(struct flow_key) == 12, "flow_key must be 12 bytes");
_Static_assert(sizeof(struct session_state) == 56, "session_state padding mismatch");
_Static_assert(offsetof(struct session_state, snd_nxt) == 4, "snd_nxt offset!=4");
_Static_assert(offsetof(struct session_state, rcv_nxt) == 8, "rcv_nxt offset!=8");
_Static_assert(offsetof(struct session_state, pkts_intercepted) == 32, "pkts_intercepted offset!=32");
_Static_assert(sizeof(struct buf_entry) == 1604, "buf_entry must be 1604 bytes");
#endif

#endif /* __ZENO_COMMON_H__ */
