// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if ((void *)((struct iphdr *)(eth + 1) + 1) > data_end)
        return XDP_PASS;

    __u32 queue = ctx->rx_queue_index;
    if (!bpf_map_lookup_elem(&xsks_map, &queue))
        return XDP_PASS;

    return bpf_redirect_map(&xsks_map, queue, 0);
}

char _license[] SEC("license") = "GPL";