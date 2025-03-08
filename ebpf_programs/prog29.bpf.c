// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 32);
} xdp_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 data_start = ctx->data;
    __u32 data_end = ctx->data_end;
    if(data_end > data_start) {
        __u32 key = 0;
        __u32* value = bpf_map_lookup_elem(&xdp_map, &key);
        *value = *value + 1;
    }
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";