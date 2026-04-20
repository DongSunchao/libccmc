// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Sunchao Dong

/* ebpf/include/zeno_proto.h */
#ifndef __ZENO_PROTO_H__
#define __ZENO_PROTO_H__

#ifndef __VMLINUX_H__
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#endif

/* ---- Safe Packet Parsers ---- */
static __always_inline struct ethhdr *
parse_eth(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return NULL;
    return eth;
}

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#include <bpf/bpf_endian.h>

static __always_inline struct iphdr *
parse_ip(struct ethhdr *eth, void *data_end)
{
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return NULL;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return NULL;
    if (ip->protocol != IPPROTO_TCP) return NULL;
    return ip;
}

static __always_inline struct tcphdr *
parse_tcp(struct iphdr *ip, void *data_end)
{
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return NULL;
    return tcp;
}

/* ---- TCP Payload Length ---- */
static __always_inline __u32
tcp_payload_len(struct iphdr *ip, struct tcphdr *tcp)
{
    __u32 ip_total = bpf_ntohs(ip->tot_len);
    __u32 ip_hdr   = ip->ihl * 4;
    __u32 tcp_hdr  = tcp->doff * 4;
    return ip_total - ip_hdr - tcp_hdr;
}

/* ---- Keepalive Probe Detection ---- */
static __always_inline int
is_keepalive_probe(struct tcphdr *tcp, __u32 payload_len, struct session_state *ss)
{
    __u32 seg_seq = bpf_ntohl(tcp->seq);
    if (payload_len <= 1 && seg_seq == ss->rcv_nxt - 1)
        return 1;
    return 0;
}

#endif /* __ZENO_PROTO_H__ */
