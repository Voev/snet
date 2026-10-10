#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    __u32 index = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, index, 0);
}

/*SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    bpf_printk("xdp: queue=%d\n", index);

    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        bpf_printk("xdp: redirecting\n");
        return bpf_redirect_map(&xsks_map, index, 0);
    }
    bpf_printk("xdp: no xsk, pass\n");
    return XDP_PASS;
}*/

char _license[] SEC("license") = "GPL";