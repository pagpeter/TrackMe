// SPDX-License-Identifier: GPL-2.0-only
//
// eBPF programs for passive TCP SYN fingerprinting.
// Two entry points for different attachment methods:
//   SEC("classifier") syn_capture        — TC ingress (direct packet access)
//   SEC("socket")     syn_capture_socket — AF_PACKET (bpf_skb_load_bytes)
//
// clang -O2 -g -target bpf -c syn_capture.c -o syn_capture.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_TCP_OPTIONS_RAW 40

#define IPV4_FRAG_DF    0x4000
#define IPV4_FRAG_MF    0x2000
#define IPV4_FRAG_OFFS  0x1fff
#define IPV4_FRAG_EVIL  0x8000

#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ECE    0x40
#define TCP_FLAG_CWR    0x80

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
#define ETH_HLEN     14

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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} SYN_EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} TARGET_PORT SEC(".maps");

static __always_inline void map_ipv4_to_ipv6(__u32 ipv4_addr, __u8 *out) {
    __builtin_memset(out, 0, 10);
    out[10] = 0xff;
    out[11] = 0xff;
    __builtin_memcpy(out + 12, &ipv4_addr, 4);
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
    if (ip_version == 6 && ipv6_flow != 0)
        q |= QUIRK_FLOW;
    __u8 ns = tcp_doff_rsvd & 0x01;
    __u8 rsvd = (tcp_doff_rsvd >> 1) & 0x07;
    if ((tcp_flags & (TCP_FLAG_CWR | TCP_FLAG_ECE)) || ns) q |= QUIRK_ECN;
    if (rsvd)          q |= QUIRK_ZERO_PLUS;
    if (tcp_seq == 0)  q |= QUIRK_SEQ_NEG;
    if (tcp_ack != 0)  q |= QUIRK_ACK_POS;
    if (tcp_urg != 0 && !(tcp_flags & TCP_FLAG_URG)) q |= QUIRK_UPTR_POS;
    if (tcp_flags & TCP_FLAG_URG) q |= QUIRK_URGF_POS;
    if (tcp_flags & TCP_FLAG_PSH) q |= QUIRK_PUSHF_POS;
    return q;
}

// TC classifier — direct packet access

static __always_inline void tc_copy_options(
    struct tcphdr *tcp, void *data_end,
    __u8 *out, __u8 *out_len
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

SEC("classifier")
int syn_capture(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    struct tcphdr *tcp = NULL;
    __u8 ipv = 0, ttl = 0, ipolen = 0, ip_df = 0, ip_evil = 0;
    __u16 ip_id = 0;
    __u32 flow6 = 0;
    __u8 src[16] = {0};

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
        __u32 ihl = ip->ihl * 4;
        if (ihl < 20 || (void *)((char *)ip + ihl) > data_end) return TC_ACT_OK;
        if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;
        __u16 fo = bpf_ntohs(ip->frag_off);
        if (fo & (IPV4_FRAG_MF | IPV4_FRAG_OFFS)) return TC_ACT_OK;
        tcp = (void *)((char *)ip + ihl);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        ipv = 4; ttl = ip->ttl;
        ip_df = (fo & IPV4_FRAG_DF) ? 1 : 0;
        ipolen = (__u8)(ihl - 20);
        ip_id = bpf_ntohs(ip->id);
        ip_evil = (fo & IPV4_FRAG_EVIL) ? 1 : 0;
        map_ipv4_to_ipv6(ip->saddr, src);
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return TC_ACT_OK;
        if (ip6->nexthdr != IPPROTO_TCP) return TC_ACT_OK;
        tcp = (struct tcphdr *)(ip6 + 1);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        ipv = 6; ttl = ip6->hop_limit;
        flow6 = ((__u32)(ip6->flow_lbl[0] & 0x0F) << 16) |
                ((__u32)ip6->flow_lbl[1] << 8) | (__u32)ip6->flow_lbl[2];
        __builtin_memcpy(src, &ip6->saddr, 16);
    } else {
        return TC_ACT_OK;
    }

    if (!tcp->syn || tcp->ack) return TC_ACT_OK;

    __u32 zero = 0;
    __u16 *target = bpf_map_lookup_elem(&TARGET_PORT, &zero);
    if (target && *target && bpf_ntohs(tcp->dest) != *target) return TC_ACT_OK;
    if (tcp->doff * 4 < sizeof(struct tcphdr)) return TC_ACT_OK;

    struct syn_event *ev = bpf_ringbuf_reserve(&SYN_EVENTS, sizeof(*ev), 0);
    if (!ev) return TC_ACT_OK;
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
    tc_copy_options(tcp, data_end, ev->tcp_options_raw, &ev->tcp_options_len);
    ev->syn_ts_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(ev, 0);
    return TC_ACT_OK;
}

// Socket filter — bpf_skb_load_bytes (can't use data/data_end)

SEC("socket")
int syn_capture_socket(struct __sk_buff *skb) {
    // Read ethertype
    __u16 eth_proto;
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2) < 0) return 0;

    __u8 ipv = 0, ttl = 0, ipolen = 0, ip_df = 0, ip_evil = 0;
    __u16 ip_id = 0;
    __u32 flow6 = 0, tcp_off = 0;
    __u8 src[16] = {0};

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr ip;
        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) < 0) return 0;
        if (ip.protocol != IPPROTO_TCP) return 0;
        __u32 ihl = ip.ihl * 4;
        if (ihl < 20) return 0;
        __u16 fo = bpf_ntohs(ip.frag_off);
        if (fo & (IPV4_FRAG_MF | IPV4_FRAG_OFFS)) return 0;
        tcp_off = ETH_HLEN + ihl;
        ipv = 4; ttl = ip.ttl;
        ip_df = (fo & IPV4_FRAG_DF) ? 1 : 0;
        ipolen = (__u8)(ihl - 20);
        ip_id = bpf_ntohs(ip.id);
        ip_evil = (fo & IPV4_FRAG_EVIL) ? 1 : 0;
        map_ipv4_to_ipv6(ip.saddr, src);
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr ip6;
        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6)) < 0) return 0;
        if (ip6.nexthdr != IPPROTO_TCP) return 0;
        tcp_off = ETH_HLEN + 40;
        ipv = 6; ttl = ip6.hop_limit;
        flow6 = ((__u32)(ip6.flow_lbl[0] & 0x0F) << 16) |
                ((__u32)ip6.flow_lbl[1] << 8) | (__u32)ip6.flow_lbl[2];
        __builtin_memcpy(src, &ip6.saddr, 16);
    } else {
        return 0;
    }

    struct tcphdr tcp;
    if (bpf_skb_load_bytes(skb, tcp_off, &tcp, sizeof(tcp)) < 0) return 0;

    if (!tcp.syn || tcp.ack) return 0;

    __u32 zero = 0;
    __u16 *target = bpf_map_lookup_elem(&TARGET_PORT, &zero);
    if (target && *target && bpf_ntohs(tcp.dest) != *target) return 0;

    __u32 tcp_hdr_len = tcp.doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) return 0;

    struct syn_event *ev = bpf_ringbuf_reserve(&SYN_EVENTS, sizeof(*ev), 0);
    if (!ev) return 0;
    __builtin_memset(ev, 0, sizeof(*ev));

    __builtin_memcpy(ev->src_addr, src, 16);
    ev->src_port = bpf_ntohs(tcp.source);
    ev->dst_port = bpf_ntohs(tcp.dest);
    ev->ip_version = ipv;
    ev->ip_ttl = ttl;
    ev->ip_options_len = ipolen;
    ev->tcp_window_size = bpf_ntohs(tcp.window);

    __u8 doff_rsvd, flags_byte;
    bpf_skb_load_bytes(skb, tcp_off + 12, &doff_rsvd, 1);
    bpf_skb_load_bytes(skb, tcp_off + 13, &flags_byte, 1);

    ev->tcp_quirks = compute_quirks(ipv, ip_df, ip_id, ip_evil, flow6,
        doff_rsvd, flags_byte,
        bpf_ntohl(tcp.seq), bpf_ntohl(tcp.ack_seq), bpf_ntohs(tcp.urg_ptr));

    ev->tcp_has_payload = (skb->len > tcp_off + tcp_hdr_len) ? 1 : 0;

    // Copy TCP options via bpf_skb_load_bytes
    __u32 opts_off = tcp_off + sizeof(struct tcphdr);
    __u32 opts_len = tcp_hdr_len - sizeof(struct tcphdr);
    if (opts_len > MAX_TCP_OPTIONS_RAW) opts_len = MAX_TCP_OPTIONS_RAW;

    // Descending constant-size loads (verifier needs constant size arg)
    // Try exact size first, then descend. Most SYN packets have ~20 bytes
    // of options so the exact match usually hits on the first try.
    if (opts_len >= 4) {
#define TRY_OPTS(N) \
    if (ev->tcp_options_len == 0 && opts_len >= (N)) { \
        if (bpf_skb_load_bytes(skb, opts_off, ev->tcp_options_raw, (N)) == 0) \
            ev->tcp_options_len = (N); \
    }
        TRY_OPTS(40)
        TRY_OPTS(36)
        TRY_OPTS(32)
        TRY_OPTS(28)
        TRY_OPTS(24)
        TRY_OPTS(20)
        TRY_OPTS(16)
        TRY_OPTS(12)
        TRY_OPTS(8)
        TRY_OPTS(4)
#undef TRY_OPTS
    }

    ev->syn_ts_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
