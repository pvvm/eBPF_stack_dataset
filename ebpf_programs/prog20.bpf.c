// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__u8 helper() {
    __u8 var = 123;
    if(var != 100) {
        __u32 value2 = 3;
        value2 *= 2;
        var = value2 - value2 + 1;
    }
    return var;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 this = 1;
    __u8 value = 0;
    __u64 val2 = value + 1;
    this += -1;
    if(this > value) {
        value = 5 + this;
        __u32 testing = 123;
        testing *= 123;
        if(this > 1000) {
            testing = 1;
        }
        helper();
    }
    __u8 a = 20;
    a += this;
    a += val2;

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";