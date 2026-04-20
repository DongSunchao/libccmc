// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Sunchao Dong

/* ebpf/tc_egress.bpf.c
 * TC egress hook: rewrite window to 0 for target session
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "zeno_common.h"
#include "zeno_proto.h"

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct flow_key);
    __type(value, struct session_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} zeno_sessions SEC(".maps");

SEC("tc")
int tc_zeno_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;

    /* egress: src is us, dst is remote */
    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    struct session_state *ss = bpf_map_lookup_elem(&zeno_sessions, &key);
    if (!ss) return TC_ACT_OK;
    if (ss->state < ZENO_ARMED) return TC_ACT_OK;

    /* Rewrite Window to 0 */
    __u16 old_win = tcp->window;
    if (old_win == 0) return TC_ACT_OK;

    __u16 new_win = 0;

    /* Track our outgoing sequence before invalidating packet pointers */
    __u32 ip_total_len = bpf_ntohs(ip->tot_len);
    __u32 ip_hdr_len = ip->ihl * 4;
    __u32 tcp_hdr_len = tcp->doff * 4;
    if (ip_total_len >= ip_hdr_len + tcp_hdr_len) {
        ss->snd_nxt = bpf_ntohl(tcp->seq) + (ip_total_len - ip_hdr_len - tcp_hdr_len);
    }

    int tcp_offset = ETH_HLEN + ip_hdr_len;

    /* Incremental csum repair */
    bpf_l4_csum_replace(skb,
        tcp_offset + offsetof(struct tcphdr, check),
        old_win, new_win, sizeof(__u16));

    bpf_skb_store_bytes(skb,
        tcp_offset + offsetof(struct tcphdr, window),
        &new_win, sizeof(__u16), 0);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
