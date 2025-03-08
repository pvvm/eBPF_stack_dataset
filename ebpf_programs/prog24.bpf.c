// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct testing {
    __u32 amem;
    __u64 example;
};

struct str_testando {
    __u8 hello;
    __u64 trying_out;
};

__u32 function1(__u32 value) {
    __u8 xandao = 2;
    value = value + 1;
    return xandao;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 value = 1;
    function1(value);

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";