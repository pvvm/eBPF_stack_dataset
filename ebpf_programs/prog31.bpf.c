// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 32);
} xdp_map SEC(".maps");

struct value {
    __u32 testing;
    __u32 testing2;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct value);
	__uint(max_entries, 32);
} map_value SEC(".maps");

void updating_map(__u32 key) {
    __u32* value = bpf_map_lookup_elem(&xdp_map, &key);
    *value = *value + 1;
    struct value *value2 = bpf_map_lookup_elem(&map_value, &key);
    value2->testing = *value;
    value2->testing2 = value2->testing * (*value);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 data_start = ctx->data;
    __u32 data_end = ctx->data_end;
    if(data_end > data_start) {
        __u32 key = 0;
        updating_map(key);
    }
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";