// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2026 Sunchao Dong

/* ebpf/xdp_zerowin.bpf.c
 * XDP Program: Ingress intercept for zero-window caching and reply
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "zeno_common.h"
#include "zeno_proto.h"
#include "zeno_checksum.h"

/* ---- Maps ---- */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct flow_key);
    __type(value, struct session_state);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} zeno_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, DEEP_BUF_MAX_PKTS);
    __type(value, struct buf_entry);
} zeno_deep_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct buf_entry);
} zeno_scratch SEC(".maps");

/* Unrolled IP checksum to satisfy the verifier */
static __always_inline __sum16 calc_ip_csum(struct iphdr *ip) {
    __u16 *p = (__u16 *)ip;
    __u32 sum = 0;

    sum += p[0];   /* version + ihl + tos */
    sum += p[1];   /* tot_len */
    sum += p[2];   /* id */
    sum += p[3];   /* frag_off */
    sum += p[4];   /* ttl + protocol */
    /* p[5] = checksum, treated as 0 */
    sum += p[6];   /* saddr low */
    sum += p[7];   /* saddr high */
    sum += p[8];   /* daddr low */
    sum += p[9];   /* daddr high */

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (__sum16)~sum;
}

/* Unrolled TCP checksum including pseudo header */
static __always_inline __sum16 calc_tcp_csum_fixed(struct iphdr *ip, struct tcphdr *tcp) {
    __u32 sum = 0;

    /* Pseudo Header */
    sum += (__u16)(ip->saddr & 0xFFFF);
    sum += (__u16)(ip->saddr >> 16);
    sum += (__u16)(ip->daddr & 0xFFFF);
    sum += (__u16)(ip->daddr >> 16);
    sum += bpf_htons((__u16)IPPROTO_TCP);
    sum += bpf_htons(20); /* fixed 20 bytes len */

    /* TCP header */
    __u16 *p = (__u16 *)tcp;
    sum += p[0];   /* source port */
    sum += p[1];   /* dest port */
    sum += p[2];   /* seq high */
    sum += p[3];   /* seq low */
    sum += p[4];   /* ack_seq high */
    sum += p[5];   /* ack_seq low */
    sum += p[6];   /* doff + reserved + flags */
    sum += p[7];   /* window (= 0) */
    sum += p[9];   /* urgent pointer */

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (__sum16)~sum;
}

/* In-place construct an ACK reply packet */
static __always_inline int craft_ack_reply(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, struct session_state *ss) {
    void *data_end = (void *)(long)ctx->data_end;

    /* Swap MAC */
    __u8 tmp_mac_0 = eth->h_dest[0];
    __u8 tmp_mac_1 = eth->h_dest[1];
    __u8 tmp_mac_2 = eth->h_dest[2];
    __u8 tmp_mac_3 = eth->h_dest[3];
    __u8 tmp_mac_4 = eth->h_dest[4];
    __u8 tmp_mac_5 = eth->h_dest[5];
    
    eth->h_dest[0] = eth->h_source[0];
    eth->h_dest[1] = eth->h_source[1];
    eth->h_dest[2] = eth->h_source[2];
    eth->h_dest[3] = eth->h_source[3];
    eth->h_dest[4] = eth->h_source[4];
    eth->h_dest[5] = eth->h_source[5];
    
    eth->h_source[0] = tmp_mac_0;
    eth->h_source[1] = tmp_mac_1;
    eth->h_source[2] = tmp_mac_2;
    eth->h_source[3] = tmp_mac_3;
    eth->h_source[4] = tmp_mac_4;
    eth->h_source[5] = tmp_mac_5;

    /* Swap IP */
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    /* Defensive: If IP options present, move TCP header forward to maintain 40B clean ACK */
    if (ip->ihl > 5) {
        __u8 *src = (__u8 *)tcp;
        __u8 *dst = (__u8 *)ip + sizeof(struct iphdr);
        if ((void *)(dst + sizeof(struct tcphdr)) > data_end) return XDP_PASS;
        
        #pragma unroll
        for (int i = 0; i < 20; i++) {
            dst[i] = src[i];
        }
        tcp = (struct tcphdr *)dst;
        ip->ihl = 5;
    }

    /* Setup IP header */
    ip->tot_len = bpf_htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id      = 0;
    ip->ttl     = 64;
    ip->frag_off = 0;
    ip->check = 0;
    ip->check = calc_ip_csum(ip);

    /* Swap TCP Ports */
    __be16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest   = tmp_port;

    /* Setup TCP sequence */
    tcp->seq     = bpf_htonl(ss->snd_nxt);
    tcp->ack_seq = bpf_htonl(ss->rcv_nxt);

    /* Set flags: ACK only, doff=5 (20 bytes bytes, no options) */
    tcp->doff = 5;
    *(((__u8 *)tcp) + 13) = 0x10;  /* ACK flag */
    tcp->window  = 0;
    tcp->urg_ptr = 0;

    /* recalculate based on the addresses before invalidating pointers */
    tcp->check = 0;
    tcp->check = calc_tcp_csum_fixed(ip, tcp);

    /* Trim the packet payload and any leftover options */
    int trim = (void *)(long)ctx->data_end - ((void *)tcp + sizeof(struct tcphdr));
    if (trim > 0) {
        bpf_xdp_adjust_tail(ctx, -trim);
    }
    
    return XDP_TX;
}

SEC("xdp")
int xdp_zeno_main(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = parse_eth(data, data_end);
    if (!eth) return XDP_PASS;
    struct iphdr *ip = parse_ip(eth, data_end);
    if (!ip) return XDP_PASS;
    struct tcphdr *tcp = parse_tcp(ip, data_end);
    if (!tcp) return XDP_PASS;

    /* Build flow key for ingress */
    struct flow_key key = {
        .saddr = ip->daddr,   /* Our IP */
        .daddr = ip->saddr,   /* Remote IP */
        .sport = tcp->dest,   /* Our port */
        .dport = tcp->source, /* Remote port */
    };

    struct session_state *ss = bpf_map_lookup_elem(&zeno_sessions, &key);
    if (!ss) return XDP_PASS;

    if (ss->state == ZENO_INACTIVE || ss->state == ZENO_RELEASED)
        return XDP_PASS;

    if (ss->state == ZENO_ARMED) {
        return XDP_PASS;
    }

    __u32 payload_len = tcp_payload_len(ip, tcp);

    /* Redline #3: Move state updates before side effects (map push or pointer invalidations) */
    ss->rcv_nxt += payload_len;
    ss->pkts_intercepted++;

    /* Cache payload to deep buffer */
    if (payload_len > 0) {
        __u32 zero = 0;
        struct buf_entry *entry = bpf_map_lookup_elem(&zeno_scratch, &zero);
        if (entry) {
            entry->len = payload_len;
            void *payload_start = (void *)tcp + (tcp->doff * 4);
            if (payload_start > data_end) return XDP_PASS;
            
            /* Runtime Bug Fix: Direct packet copy with bounded index and strict explicit data_end check inside loop */
            __u32 copy_len = payload_len & (DEEP_BUF_PKT_SIZE - 1);
            for (int i = 0; i < DEEP_BUF_PKT_SIZE; i++) {
                if (i >= copy_len) break;
                if ((void *)((__u8 *)payload_start + i + 1) > data_end) break;
                entry->data[i] = ((__u8 *)payload_start)[i];
            }
            bpf_map_push_elem(&zeno_deep_buf, entry, 0);
        }
    }

    return craft_ack_reply(ctx, eth, ip, tcp, ss);
}

char _license[] SEC("license") = "GPL";
