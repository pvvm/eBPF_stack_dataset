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

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 this = 1;
    __u8 value = 0;
    __u8 you_are_cool = 1 + 5;
    __u16 trying12 = 1;
    this += -1;

    if(you_are_cool > value) {
        struct str_testando str_inst_2;
        str_inst_2.hello = this;
        str_inst_2.trying_out = trying12 * 1000;
        return XDP_PASS;
    } else if((this && 1) || trying12) {
        this *= 12;
        struct testing struct_instance;
        struct_instance.amem = value;
        struct_instance.example = struct_instance.amem * this;
    }

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";