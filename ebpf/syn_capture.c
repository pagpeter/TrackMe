// SPDX-License-Identifier: GPL-2.0-only
// TCP SYN capture: XDP + TC (direct access) and AF_PACKET (load_bytes).

#include "syn_capture.h"

SEC("xdp")
int syn_capture_xdp(struct xdp_md *ctx) {
    parse_and_submit((void *)(long)ctx->data, (void *)(long)ctx->data_end);
    return XDP_PASS;
}

SEC("classifier")
int syn_capture(struct __sk_buff *skb) {
    parse_and_submit((void *)(long)skb->data, (void *)(long)skb->data_end);
    return TC_ACT_OK;
}

// Socket filter — uses bpf_skb_load_bytes (no direct packet access).
// Kept as a fallback for environments where XDP isn't available.
SEC("socket")
int syn_capture_socket(struct __sk_buff *skb) {
    __u16 eth_proto;
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2) < 0) return 0;

    // VLAN peeling via load_bytes (can't use peel_vlan_tags here).
    __u32 l3_off = ETH_HLEN;
    if (eth_proto == ETH_P_8021Q_BE || eth_proto == ETH_P_8021AD_BE) {
        if (bpf_skb_load_bytes(skb, l3_off + 2, &eth_proto, 2) < 0) return 0;
        l3_off += 4;
    }
    if (eth_proto == ETH_P_8021Q_BE || eth_proto == ETH_P_8021AD_BE) {
        if (bpf_skb_load_bytes(skb, l3_off + 2, &eth_proto, 2) < 0) return 0;
        l3_off += 4;
    }

    __u8 ipv = 0, ttl = 0, ipolen = 0, ip_df = 0, ip_evil = 0;
    __u16 ip_id = 0;
    __u32 flow6 = 0, tcp_off = 0;
    __u8 src[16] = {0};

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr ip;
        if (bpf_skb_load_bytes(skb, l3_off, &ip, sizeof(ip)) < 0) return 0;
        if (ip.protocol != IPPROTO_TCP) return 0;
        __u32 ihl = ip.ihl * 4;
        if (ihl < 20) return 0;
        __u16 fo = bpf_ntohs(ip.frag_off);
        if (fo & (IPV4_FRAG_MF | IPV4_FRAG_OFFS)) return 0;
        tcp_off = l3_off + ihl;
        ipv = 4; ttl = ip.ttl;
        ip_df = (fo & IPV4_FRAG_DF) ? 1 : 0;
        ipolen = (__u8)(ihl - 20);
        ip_id = bpf_ntohs(ip.id);
        ip_evil = (fo & IPV4_FRAG_EVIL) ? 1 : 0;
        map_ipv4_to_ipv6(ip.saddr, src);
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr ip6;
        if (bpf_skb_load_bytes(skb, l3_off, &ip6, sizeof(ip6)) < 0) return 0;
        if (ip6.nexthdr != IPPROTO_TCP) return 0;
        tcp_off = l3_off + 40;
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

    __u16 tp = target_port;
    if (tp && bpf_ntohs(tcp.dest) != tp) { stats_inc(STAT_SYN_FILTERED); return 0; }

    __u32 tcp_hdr_len = tcp.doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr)) return 0;

    struct syn_event *ev = bpf_ringbuf_reserve(&SYN_EVENTS, sizeof(*ev), 0);
    if (!ev) { stats_inc(STAT_SYN_RINGBUF_DROPS); return 0; }
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

    __u32 opts_off = tcp_off + sizeof(struct tcphdr);
    __u32 opts_len = tcp_hdr_len - sizeof(struct tcphdr);
    if (opts_len > MAX_TCP_OPTIONS_RAW) opts_len = MAX_TCP_OPTIONS_RAW;
    if (opts_len >= 4) {
#define TRY(N) \
    if (ev->tcp_options_len == 0 && opts_len >= (N)) { \
        if (bpf_skb_load_bytes(skb, opts_off, ev->tcp_options_raw, (N)) == 0) \
            ev->tcp_options_len = (N); \
    }
        TRY(40) TRY(36) TRY(32) TRY(28) TRY(24) TRY(20) TRY(16) TRY(12) TRY(8) TRY(4)
#undef TRY
    }

    ev->syn_ts_ns = bpf_ktime_get_ns();
    stats_inc(STAT_SYN_PROCESSED);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
