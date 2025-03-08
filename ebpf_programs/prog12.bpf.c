// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 this = 1;
    __u8 value = 0;
    __u64 variable = 1;
    __u8 variable2 = variable + 5;
    __u16 trying12 = 1;
    this += -1;

    if(variable > value) {
        return XDP_PASS;
    } else if(this && variable2) {
        this *= 12;
    }

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";