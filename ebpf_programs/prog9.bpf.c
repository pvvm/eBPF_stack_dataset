// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u8 variable1 = 1;
    __u16 variable2;
    __u32 a = 20;
    if(a > variable1) {
        variable2 = 5 + variable1;
        __u32 b = a;
        b *= 123;
        if(b > 1000) {
            __u8 c = 1;
        }
    }
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";