// SPDX-License-Identifier: GPL-2.0-only
#ifndef __SYN_CAPTURE_H
#define __SYN_CAPTURE_H

// clang-format off
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// clang-format on

#define MAX_TCP_OPTIONS_RAW 40

// VLAN EtherTypes (pre-swapped for LE host).
#define ETH_P_8021Q_BE   0x0081u
#define ETH_P_8021AD_BE  0xa888u

#define IPV4_FRAG_DF    0x4000
#define IPV4_FRAG_MF    0x2000
#define IPV4_FRAG_OFFS  0x1fff
#define IPV4_FRAG_EVIL  0x8000

// p0f v3 quirk bits — must match Go constants in pkg/tcp/ebpf_linux.go.
#define QUIRK_DF        (1u << 0)
#define QUIRK_ID_POS    (1u << 1)
#define QUIRK_ID_NEG    (1u << 2)
#define QUIRK_ECN       (1u << 3)
#define QUIRK_ZERO_PLUS (1u << 4)
#define QUIRK_FLOW      (1u << 5)
#define QUIRK_SEQ_NEG   (1u << 6)
#define QUIRK_ACK_POS   (1u << 7)
#define QUIRK_UPTR_POS  (1u << 8)
#define QUIRK_URGF_POS  (1u << 9)
#define QUIRK_PUSHF_POS (1u << 10)

#define RINGBUF_SIZE (1 * 1024 * 1024)

#define STAT_SYN_PROCESSED      0
#define STAT_SYN_RINGBUF_DROPS  1
#define STAT_SYN_FILTERED       2
#define STAT_MAX                3

// Must match synEvent in pkg/tcp/ebpf_linux.go
struct syn_event {
    __u8  src_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u8  ip_version;
    __u8  ip_ttl;
    __u8  ip_options_len;
    __u8  _pad0;
    __u16 tcp_window_size;
    __u16 tcp_quirks;
    __u8  tcp_options_len;
    __u8  tcp_has_payload;
    __u8  tcp_options_raw[MAX_TCP_OPTIONS_RAW];
    __u64 syn_ts_ns;
} __attribute__((packed));

struct vlan_hdr {
    __be16 tci;
    __be16 encapsulated_proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} SYN_EVENTS SEC(".maps");

// Go reads these for metrics.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} EBPF_STATS SEC(".maps");

// Non-zero = only capture SYNs to this port. Patched at load time.
volatile const __u16 target_port = 0;

static __always_inline void stats_inc(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&EBPF_STATS, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline void map_ipv4_to_ipv6(__u32 ipv4_addr, __u8 *out) {
    __builtin_memset(out, 0, 10);
    out[10] = 0xff;
    out[11] = 0xff;
    __builtin_memcpy(out + 12, &ipv4_addr, 4);
}

static __always_inline int peel_vlan_tags(
    void *data, void *data_end, __u16 *eth_type, __u32 *offset
) {
    if (*eth_type == ETH_P_8021Q_BE || *eth_type == ETH_P_8021AD_BE) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)((char *)data + *offset);
        if ((void *)(vlan + 1) > data_end) return -1;
        *offset += sizeof(struct vlan_hdr);
        *eth_type = vlan->encapsulated_proto;
    }
    if (*eth_type == ETH_P_8021Q_BE || *eth_type == ETH_P_8021AD_BE) {
        struct vlan_hdr *vlan = (struct vlan_hdr *)((char *)data + *offset);
        if ((void *)(vlan + 1) > data_end) return -1;
        *offset += sizeof(struct vlan_hdr);
        *eth_type = vlan->encapsulated_proto;
    }
    return 0;
}

static __always_inline __u16 compute_quirks(
    __u8 ip_version, __u8 ip_df, __u16 ip_id, __u8 ip_evil,
    __u32 ipv6_flow, __u8 tcp_doff_rsvd, __u8 tcp_flags,
    __u32 tcp_seq, __u32 tcp_ack, __u16 tcp_urg
) {
    __u16 q = 0;
    if (ip_version == 4) {
        if (ip_df)                q |= QUIRK_DF;
        if (ip_df && ip_id != 0)  q |= QUIRK_ID_POS;
        if (!ip_df && ip_id == 0) q |= QUIRK_ID_NEG;
        if (ip_evil)              q |= QUIRK_ZERO_PLUS;
    }
    if (ip_version == 6 && ipv6_flow != 0) q |= QUIRK_FLOW;
    __u8 ns = tcp_doff_rsvd & 0x01;
    __u8 rsvd = (tcp_doff_rsvd >> 1) & 0x07;
    if ((tcp_flags & 0xc0) || ns) q |= QUIRK_ECN;  // CWR|ECE
    if (rsvd)          q |= QUIRK_ZERO_PLUS;
    if (tcp_seq == 0)  q |= QUIRK_SEQ_NEG;
    if (tcp_ack != 0)  q |= QUIRK_ACK_POS;
    if (tcp_urg != 0 && !(tcp_flags & 0x20)) q |= QUIRK_UPTR_POS;
    if (tcp_flags & 0x20) q |= QUIRK_URGF_POS;
    if (tcp_flags & 0x08) q |= QUIRK_PUSHF_POS;
    return q;
}

static __always_inline void copy_tcp_options(
    struct tcphdr *tcp, void *data_end, __u8 *out, __u8 *out_len
) {
    __u8 *ptr = (__u8 *)tcp + sizeof(struct tcphdr);
    __u32 olen = tcp->doff * 4 - sizeof(struct tcphdr);
    if (olen > MAX_TCP_OPTIONS_RAW) olen = MAX_TCP_OPTIONS_RAW;
    __u8 *end = ptr + olen;
    if (end > (__u8 *)data_end) {
        olen = (__u8 *)data_end - ptr;
        if (olen > MAX_TCP_OPTIONS_RAW) olen = MAX_TCP_OPTIONS_RAW;
    }
    if (ptr >= (__u8 *)data_end) { *out_len = 0; return; }
    *out_len = (__u8)olen;
    for (__u32 i = 0; i < MAX_TCP_OPTIONS_RAW; i++) {
        if (i >= olen || ptr + i >= (__u8 *)data_end) break;
        out[i] = ptr[i];
    }
}

// Shared parse-and-submit for direct-access programs (XDP + TC).
// Returns unconditionally — both XDP_PASS and TC_ACT_OK are "pass the packet".
static __always_inline void parse_and_submit(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return;

    __u16 eth_type = eth->h_proto;
    __u32 l3_off = sizeof(struct ethhdr);
    if (peel_vlan_tags(data, data_end, &eth_type, &l3_off) < 0) return;

    struct tcphdr *tcp = NULL;
    __u8 ipv = 0, ttl = 0, ipolen = 0, ip_df = 0, ip_evil = 0;
    __u16 ip_id = 0;
    __u32 flow6 = 0;
    __u8 src[16] = {0};

    if (eth_type == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)((char *)data + l3_off);
        if ((void *)(ip + 1) > data_end) return;
        __u32 ihl = ip->ihl * 4;
        if (ihl < 20 || (void *)((char *)ip + ihl) > data_end) return;
        if (ip->protocol != IPPROTO_TCP) return;
        __u16 fo = bpf_ntohs(ip->frag_off);
        if (fo & (IPV4_FRAG_MF | IPV4_FRAG_OFFS)) return;
        tcp = (void *)((char *)ip + ihl);
        if ((void *)(tcp + 1) > data_end) return;
        ipv = 4; ttl = ip->ttl;
        ip_df = (fo & IPV4_FRAG_DF) ? 1 : 0;
        ipolen = (__u8)(ihl - 20);
        ip_id = bpf_ntohs(ip->id);
        ip_evil = (fo & IPV4_FRAG_EVIL) ? 1 : 0;
        map_ipv4_to_ipv6(ip->saddr, src);
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)((char *)data + l3_off);
        if ((void *)(ip6 + 1) > data_end) return;
        if (ip6->nexthdr != IPPROTO_TCP) return;
        tcp = (struct tcphdr *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return;
        ipv = 6; ttl = ip6->hop_limit;
        flow6 = ((__u32)(ip6->flow_lbl[0] & 0x0F) << 16) |
                ((__u32)ip6->flow_lbl[1] << 8) | (__u32)ip6->flow_lbl[2];
        __builtin_memcpy(src, &ip6->saddr, 16);
    } else {
        return;
    }

    if (!tcp->syn || tcp->ack) return;

    __u16 tp = target_port;
    if (tp && bpf_ntohs(tcp->dest) != tp) { stats_inc(STAT_SYN_FILTERED); return; }
    if (tcp->doff * 4 < sizeof(struct tcphdr)) return;

    struct syn_event *ev = bpf_ringbuf_reserve(&SYN_EVENTS, sizeof(*ev), 0);
    if (!ev) { stats_inc(STAT_SYN_RINGBUF_DROPS); return; }
    __builtin_memset(ev, 0, sizeof(*ev));

    __builtin_memcpy(ev->src_addr, src, 16);
    ev->src_port = bpf_ntohs(tcp->source);
    ev->dst_port = bpf_ntohs(tcp->dest);
    ev->ip_version = ipv;
    ev->ip_ttl = ttl;
    ev->ip_options_len = ipolen;
    ev->tcp_window_size = bpf_ntohs(tcp->window);
    ev->tcp_quirks = compute_quirks(ipv, ip_df, ip_id, ip_evil, flow6,
        ((__u8 *)tcp)[12], ((__u8 *)tcp)[13],
        bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq), bpf_ntohs(tcp->urg_ptr));
    ev->tcp_has_payload = ((void *)((__u8 *)tcp + tcp->doff * 4 + 1) <= data_end) ? 1 : 0;
    copy_tcp_options(tcp, data_end, ev->tcp_options_raw, &ev->tcp_options_len);
    ev->syn_ts_ns = bpf_ktime_get_ns();
    stats_inc(STAT_SYN_PROCESSED);
    bpf_ringbuf_submit(ev, 0);
}

#endif // __SYN_CAPTURE_H
