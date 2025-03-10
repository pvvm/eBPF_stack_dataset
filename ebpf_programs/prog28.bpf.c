// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__u8 check_helper(__u32 value, __u16 auxiliar) {
    if(value > auxiliar)
        return 1;
    else
        return 0;
}

__u32 helping_hand(__u32 value, __u16 auxiliar) {
    value = value + auxiliar;
    __u8 returned = check_helper(value, auxiliar);
    if(returned)
        return value - auxiliar;
    else
        return value;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 value = 1;
    value = helping_hand(value, 25);

    __u32 data_start = ctx->data;
    __u32 data_end = ctx->data_end;
    if(data_end > data_start && value) {
        check_helper(value, value - 1);
    }
    return XDP_DROP; // Drop all packets
}

char LICENSE[] SEC("license") = "GPL";