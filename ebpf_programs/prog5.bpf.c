// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 variable = 100;
    variable += 51;
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";