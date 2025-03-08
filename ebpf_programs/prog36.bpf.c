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


__u32 multiply_ten(__u32 number) {
    return number * 10;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u64 value = 1;
    __u8 value1 = 2;
    __u16 value2 = 3;
    __u8 value3 = 4;
    __u32 value4 = 5;

    __u64 total = value + value1 + value2 + value3 + value4;
    total = multiply_ten(total);

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";