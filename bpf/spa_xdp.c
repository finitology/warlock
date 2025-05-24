// SPDX-License-Identifier: AGPL-3.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define SIG_LEN 32        // Length of HMAC-SHA256 signature
#define UDP_PORT 7000     // SPA port
#define ETH_P_IP 0x0800


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct spa_event_t {
    __u32 src_ip;
    __u16 src_port;
    __u8  signature[SIG_LEN];
};

// Ring buffer to send events to user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

SEC("xdp")
int xdp_spa_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udp->dest) != UDP_PORT)
        return XDP_PASS;

    // Pointer to UDP payload
    unsigned char *payload = (unsigned char *)(udp + 1);
    if (payload + SIG_LEN > (unsigned char *)data_end)
        return XDP_PASS;

    struct spa_event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    event->src_ip = ip->saddr;
    event->src_port = bpf_ntohs(udp->source);
    __builtin_memcpy(event->signature, payload, SIG_LEN);

    bpf_ringbuf_submit(event, 0);
    return XDP_PASS;
}
