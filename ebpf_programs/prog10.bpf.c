// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 this = 1;
    __u8 value = 0;
    this += -1;
    if(this > value) {
        value = 5 + this;
        __u32 testing = 123;
        testing *= 123;
        if(this > 1000) {
            testing = 1;
        }
    }
    __u8 a = 20;
    a += this;
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";