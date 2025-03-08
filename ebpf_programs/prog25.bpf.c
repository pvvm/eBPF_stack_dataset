// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__u32 function4(__u16 trying) {
    if(trying < 10) {
        return trying;
    }
    return 0;
}

__u32 helping(__u32 value) {
    value = value + 1;
    __u8 afago = 1;
    __u32 argument;
    if(afago)
        argument = afago;
    else
        argument = value;
    function4(argument);
    return value;
}

__u32 function2(__u32 value) {
    value = value + 1;
    __u16 roedor = 5;
    value = roedor + 1;
    helping(value);
    function4(roedor);
    return value;
}

__u32 function1(__u32 value) {
    __u8 xandao = 2;
    value = value + 1;
    function2(value);
    return xandao;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 value = 1;
    function1(value);

    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";