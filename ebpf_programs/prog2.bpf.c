// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u8 variable = 5;
    variable += 4;
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";