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

__u32 helping_func(__u32 valiable) {
    if(valiable * 2 > 500)
        return valiable;
    else
        return 0;
}

__u32 second_func(__u32 number) {
    return number * 10;
}

void updating_map(__u32 *value, struct value *value2) {
    *value = *value + 1;
    value2->testing = *value;
    value2->testing2 = value2->testing * (*value);
    if(*value > 5) {
        *value = helping_func(*value);
    } else {
        value2->testing = second_func(*value);
    }
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 data_start = ctx->data;
    __u32 data_end = ctx->data_end;
    if(data_end > data_start) {
        __u32 key = 0;
        __u32* value = bpf_map_lookup_elem(&xdp_map, &key);
        struct value *value2 = bpf_map_lookup_elem(&map_value, &key);
        updating_map(value, value2);
    }
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";