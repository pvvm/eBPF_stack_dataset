// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct testing {
    __u8 a;
    __u8 b;
    __u8 c;
    __u16 d;
    __u64 e;
};

struct str_testando {
    __u8 hello;
    __u64 trying_out;
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 this = 1;
    __u8 value = 0;
    __u64 variable = 1;
    __u8 variable2 = variable + 5;
    __u16 trying12 = 1;
    this += -1;

    if(variable > value) {
        struct str_testando str_inst_2;
        str_inst_2.hello = this;
        str_inst_2.trying_out = variable2 * 1000;
        return XDP_PASS;
    } else if(this && variable2) {
        this *= 12;
        struct testing struct_instance;
        struct_instance.a = value;
    }

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";